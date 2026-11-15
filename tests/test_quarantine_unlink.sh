#!/usr/bin/env bash
#
# tests/test_quarantine_unlink.sh - behavioral test for
# unlink_original_pinned() in userspace/avd/avd.c, the step where
# quarantine_file() removes the original by name (#231).
#
# The function is extracted from avd.c and built into a small
# harness. The harness wraps fstatat() so it can swap a parent
# directory for a symlink exactly between the identity check and the
# unlink - the race CodeQL flagged as cpp/toctou-race-condition. It
# also runs the old lstat()+unlink(path) sequence through the same swap
# to show the test reproduces the race at all (that version must delete
# the decoy).
#
# Pure userspace, no root, no module, no VM:
#   tests/test_quarantine_unlink.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVD="$REPO_ROOT/userspace/avd/avd.c"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_qunlink.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

awk '/^static int unlink_original_pinned\(/ {in_body=1} in_body{print} in_body && /^}/{exit}' \
    "$AVD" > "$BUILD_DIR/func.inc"
if ! grep -q unlinkat "$BUILD_DIR/func.inc"; then
    echo "FAIL: could not extract unlink_original_pinned() from $AVD"
    exit 1
fi

cat > "$BUILD_DIR/harness.c" <<'EOF'
/* Built and run by tests/test_quarantine_unlink.sh only. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char root[PATH_MAX / 2];
static int swap_armed;

static void p(char *buf, const char *rel) {
  snprintf(buf, PATH_MAX, "%s/%s", root, rel);
}

/* Moves <root>/<dir> aside to <dir>_moved and puts a symlink to
 * <root>/decoy in its place. */
static void swap_parent(const char *dir) {
  char from[PATH_MAX], to[PATH_MAX], decoy[PATH_MAX];
  char moved[64];

  snprintf(moved, sizeof(moved), "%s_moved", dir);
  p(from, dir);
  p(to, moved);
  p(decoy, "decoy");
  if (rename(from, to) != 0 || symlink(decoy, from) != 0) {
    perror("swap_parent");
    exit(2);
  }
}

static const char *swap_dir;

static int test_fstatat(int dirfd, const char *name, struct stat *st,
                        int flags) {
  int rc = fstatat(dirfd, name, st, flags);

  if (swap_armed) {
    swap_armed = 0;
    swap_parent(swap_dir);
  }
  return rc;
}

#define fstatat test_fstatat
#include "func.inc"
#undef fstatat

static void make_file(const char *rel, const char *content) {
  char path[PATH_MAX];
  int fd;

  p(path, rel);
  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0 || write(fd, content, strlen(content)) < 0) {
    perror(path);
    exit(2);
  }
  close(fd);
}

static void make_dir(const char *rel) {
  char path[PATH_MAX];

  p(path, rel);
  if (mkdir(path, 0755) != 0) {
    perror(path);
    exit(2);
  }
}

static int exists(const char *rel) {
  char path[PATH_MAX];
  struct stat st;

  p(path, rel);
  return lstat(path, &st) == 0;
}

/* Opens and fstat()s <rel> the way handle_scan_request() pins the
 * scanned file. */
static int pin(const char *rel, struct stat *st) {
  char path[PATH_MAX];
  int fd;

  p(path, rel);
  fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0 || fstat(fd, st) != 0) {
    perror(path);
    exit(2);
  }
  return fd;
}

static int failures;

static void check(int ok, const char *what) {
  printf("  %s: %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok)
    failures++;
}

/* The pre-fix sequence from quarantine_file(), with the swap landing
 * where it would in a lost race: after lstat(), before unlink(). */
static int legacy_unlink(const char *path, const struct stat *want) {
  struct stat now;

  if (lstat(path, &now) != 0 || now.st_dev != want->st_dev ||
      now.st_ino != want->st_ino)
    return 1;
  if (swap_armed) {
    swap_armed = 0;
    swap_parent(swap_dir);
  }
  return unlink(path) == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
  char path[PATH_MAX];
  struct stat st;
  int fd, rc;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <scratch dir>\n", argv[0]);
    return 2;
  }
  snprintf(root, sizeof(root), "%s", argv[1]);
  make_dir("decoy");
  make_file("decoy/evil", "decoy - must survive\n");

  /* 1. Nothing moves: the original is removed. */
  make_dir("plain");
  make_file("plain/evil", "original\n");
  fd = pin("plain/evil", &st);
  p(path, "plain/evil");
  rc = unlink_original_pinned(path, &st);
  check(rc == 0 && !exists("plain/evil"), "unchanged path: original removed");
  close(fd);

  /* 2. The name was replaced by another file before the call:
   * refused, the replacement survives. */
  make_dir("repl");
  make_file("repl/evil", "original\n");
  fd = pin("repl/evil", &st);
  make_file("repl/other", "replacement\n");
  {
    char from[PATH_MAX];

    p(from, "repl/other");
    p(path, "repl/evil");
    if (rename(from, path) != 0) {
      perror("rename");
      return 2;
    }
  }
  rc = unlink_original_pinned(path, &st);
  check(rc == 1 && exists("repl/evil"), "replaced file: refused, replacement kept");
  close(fd);

  /* 3. Parent swapped for a symlink before the call: refused. */
  make_dir("pre");
  make_file("pre/evil", "original\n");
  fd = pin("pre/evil", &st);
  swap_parent("pre");
  p(path, "pre/evil");
  rc = unlink_original_pinned(path, &st);
  check(rc == 1 && exists("decoy/evil") && exists("pre_moved/evil"),
        "parent swapped before the check: refused, decoy kept");
  close(fd);

  /* 4. The race itself: parent swapped between the identity check and
   * the unlink. The pinned dirfd still names the real directory, so
   * the original goes and the decoy stays. */
  make_dir("race");
  make_file("race/evil", "original\n");
  fd = pin("race/evil", &st);
  p(path, "race/evil");
  swap_dir = "race";
  swap_armed = 1;
  rc = unlink_original_pinned(path, &st);
  check(rc == 0 && exists("decoy/evil") && !exists("race_moved/evil"),
        "parent swapped between check and unlink: original removed, decoy kept");
  close(fd);

  /* 5. Control: the same swap against the old lstat()+unlink(path)
   * sequence deletes the decoy. If this ever stops happening, case 4
   * is no longer testing the race. */
  make_dir("legacy");
  make_file("legacy/evil", "original\n");
  fd = pin("legacy/evil", &st);
  p(path, "legacy/evil");
  swap_dir = "legacy";
  swap_armed = 1;
  rc = legacy_unlink(path, &st);
  check(rc == 0 && !exists("decoy/evil") && exists("legacy_moved/evil"),
        "control: old lstat()+unlink() removes the decoy under the same swap");
  close(fd);

  /* 6. Bad names are rejected rather than handed to unlinkat(). */
  check(unlink_original_pinned("/", &st) == -1 && errno == EINVAL,
        "path with an empty final component is rejected");

  printf("%s\n", failures ? "FAIL" : "PASS");
  return failures ? 1 : 0;
}
EOF

if ! ${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -I"$BUILD_DIR" \
        -o "$BUILD_DIR/harness" "$BUILD_DIR/harness.c"; then
    echo "test_quarantine_unlink.sh: FAIL - harness did not build"
    exit 1
fi
mkdir "$BUILD_DIR/scratch"
"$BUILD_DIR/harness" "$BUILD_DIR/scratch"
rc=$?
echo "test_quarantine_unlink.sh: $([ $rc = 0 ] && echo PASS || echo FAIL)"
exit $rc
