#!/usr/bin/env bash
#
# test_execveat_bypass.sh - execveat() coverage test (post-fix
# regression, not really an "evasion" in the adversarial sense the
# other scripts in this dir test - included here because until the
# execveat kprobe was added, calling execveat() instead of execve()
# was a complete, trivial bypass of every exec-based check: no
# hash/signature match, no daemon scan, no av_behavior_record_exec()
# call at all).
#
# Technique: glibc has no execveat() wrapper, so this calls the raw
# syscall directly via syscall(SYS_execveat, ...). Covers six cases
# that mirror bugs already found and fixed elsewhere in this codebase
# for other syscalls (execve's relative-path fix, openat's dfd-ignored
# fix):
#
#   1. AT_FDCWD + absolute path       - the plain case
#   2. AT_FDCWD + relative path       - cwd resolution
#   3. real dfd + relative path       - dfd resolution (openat's bug, for exec)
#   4. memfd_create() + AT_EMPTY_PATH - fileless exec (fexecve()-style):
#      pathname is empty and dfd names the target directly, no
#      filesystem path to resolve at all. Previously a documented gap
#      (open_exec_target() had nothing to open); handler_pre_execveat()
#      now special-cases AT_EMPTY_PATH and resolves the target via
#      dfd's own struct path directly - see main.c's comments on the
#      empty-string sentinel in resolve_absolute_path()/
#      open_exec_target().
#   5. real dfd + non-empty relative path + AT_EMPTY_PATH set anyway -
#      per execveat(2), AT_EMPTY_PATH only changes anything when the
#      pathname is actually empty; a non-empty pathname resolves
#      exactly as it would without the flag, and that resolution
#      succeeds. Regression case for a bug this hook briefly had:
#      treating "AT_EMPTY_PATH is set" as "trust the flag, skip
#      scanning" would have made the flag a free bypass for an
#      otherwise-ordinary dfd-relative exec. Must be detected exactly
#      like Test 3.
#   6. real dfd + empty pathname, AT_EMPTY_PATH NOT set - the one
#      combination that's genuinely invalid: generic path resolution
#      rejects a zero-length pathname unless LOOKUP_EMPTY is set, so
#      this execveat() fails with ENOENT before executing anything.
#      Must NOT be detected/killed - there is nothing to scan.
#
# All six are real pass/fail assertions now.
#
# NEEDS THE LIVE KERNEL MODULE - run this in your VM, not standalone.
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "This script needs root to check dmesg meaningfully after the test."
	echo "Re-run with sudo."
	exit 1
fi

if [ ! -d /sys/module/av ]; then
	echo "av.ko doesn't appear to be loaded - insmod it first:"
	echo "  sudo insmod av/av.ko"
	exit 1
fi

# mktemp -d gives an unpredictable name with mode 0700 already, so a
# local attacker can't pre-create it or a symlink at this path ahead
# of us the way a fixed /tmp/execveat_test name would allow.
TESTDIR="$(mktemp -d /tmp/execveat_test.XXXXXXXX)"
trap 'rm -rf "$TESTDIR"' EXIT

PASS=0
FAIL=0

echo "=== execveat() coverage test ==="
echo

# ---- build the raw-syscall runner ----

cat >"$TESTDIR/execveat_runner.c" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>

/* Usage: execveat_runner <dfd-path-or-"AT_FDCWD"-or-"memfd"> <pathname> <flags> */
int main(int argc, char *argv[])
{
    int dfd;
    const char *path = argv[2];
    int flags = atoi(argv[3]);
    char *av_[2] = { NULL, NULL };
    char *const ev_[1] = { NULL };

    if (!strcmp(argv[1], "AT_FDCWD")) {
        dfd = AT_FDCWD;
    } else if (!strcmp(argv[1], "memfd")) {
        /* Fileless exec: copy the EICAR file into an anonymous memfd,
         * exec it via dfd=memfd_fd, pathname="", AT_EMPTY_PATH. */
        FILE *src = fopen(path, "rb");
        char buf[256];
        size_t n;

        if (!src) { perror("fopen"); return 1; }
        dfd = syscall(SYS_memfd_create, "execveat_test", 0);
        if (dfd < 0) { perror("memfd_create"); return 1; }
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
            write(dfd, buf, n);
        fclose(src);
        path = "";
        flags |= 0x1000; /* AT_EMPTY_PATH */
    } else {
        dfd = open(argv[1], O_RDONLY | O_DIRECTORY);
        if (dfd < 0) { perror("open dfd"); return 1; }
    }

    av_[0] = (char *)path;
    syscall(SYS_execveat, dfd, path, av_, ev_, flags);
    /* Only reached if execveat itself failed. Save errno immediately -
     * perror()/stdio can clobber it as a side effect before we get to
     * use it, even on their own success paths - then exit with that
     * saved value (not just a fixed 1) so callers that need to
     * distinguish WHY it failed (e.g. confirming ENOENT rather than
     * some other error, or the helper never reaching the syscall at
     * all) can check $? for the specific errno value instead of just
     * "nonzero". */
    {
        int saved_errno = errno;
        perror("execveat");
        return saved_errno;
    }
}
EOF
gcc -o "$TESTDIR/execveat_runner" "$TESTDIR/execveat_runner.c"

# ---- shared EICAR fixture ----

# Single quotes are intentional: this string has literal $ characters
# that must NOT be shell-expanded (with set -u active, an unquoted/
# double-quoted $EICAR here is an unbound-variable error, not just a
# wrong-content bug) - same reasoning as tests/test_detection.sh's
# identical EICAR fixture.
# shellcheck disable=SC2016
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >"$TESTDIR/eicar.com"
chmod +x "$TESTDIR/eicar.com"

# av_kill()'s log format is structured key=value (see main.c's
# v1.0.0-merge comment): "event=detected action=kill type=...
# path="...". Match on that instead of the old free-form
# 'DETECTED "..."' sentence format, which this check predates and no
# longer appears anywhere in the module.
check_detected() {
	local expect_path="$1"
	if dmesg | tail -20 | grep -q "event=detected.*action=kill.*path=\"$expect_path\""; then
		return 0
	fi
	return 1
}

# ---- Test 1: AT_FDCWD + absolute path ----

echo "-- Test 1: AT_FDCWD + absolute path --"
dmesg -C
"$TESTDIR/execveat_runner" AT_FDCWD "$TESTDIR/eicar.com" 0 || true
sleep 1
if check_detected "$TESTDIR/eicar.com"; then
	echo "PASS: detected via AT_FDCWD + absolute path"
	PASS=$((PASS + 1))
else
	echo "FAIL: no detection - check the execveat kprobe symbol/register"
	echo "      mapping first (sudo cat /proc/kallsyms | grep sys_execveat)"
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 2: AT_FDCWD + relative path ----

echo "-- Test 2: AT_FDCWD + relative path --"
dmesg -C
(cd "$TESTDIR" && "$TESTDIR/execveat_runner" AT_FDCWD eicar.com 0) || true
sleep 1
if check_detected "$TESTDIR/eicar.com"; then
	echo "PASS: relative path resolved against cwd correctly"
	PASS=$((PASS + 1))
else
	echo "FAIL: relative path not resolved (or resolved to the wrong string) -"
	echo "      check that aw->pwd is actually being set from resolve_dfd_path()"
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 3: real dfd + relative path ----

echo "-- Test 3: real dfd + relative path --"
mkdir -p "$TESTDIR/subdir"
cp "$TESTDIR/eicar.com" "$TESTDIR/subdir/eicar.com"
dmesg -C
"$TESTDIR/execveat_runner" "$TESTDIR/subdir" eicar.com 0 || true
sleep 1
if check_detected "$TESTDIR/subdir/eicar.com"; then
	echo "PASS: dfd-relative path resolved correctly"
	PASS=$((PASS + 1))
else
	echo "FAIL: dfd was ignored/mishandled - this is openat's dfd-ignored bug's"
	echo "      exact counterpart for exec; check resolve_dfd_path()'s return"
	echo "      value path in handler_pre_execveat(), not the hashing logic"
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 4: memfd + AT_EMPTY_PATH (fileless exec) ----

echo "-- Test 4: memfd + AT_EMPTY_PATH (fileless exec) --"
dmesg -C
"$TESTDIR/execveat_runner" memfd "$TESTDIR/eicar.com" 0 || true
sleep 1
# An anonymous memfd has no real dentry in any mounted filesystem, so
# d_path() reports it the same way the kernel always names memfds:
# "/memfd:<name> (deleted)" (the name given to memfd_create(), plus
# the same "(deleted)" suffix d_path() appends for any unlinked-but-
# still-open file). That is not a bug or a loose match - it is the
# correct, expected representation of a fileless exec target.
if dmesg | tail -10 | grep -q 'event=detected.*action=kill.*path="/memfd:execveat_test'; then
	echo "PASS: fileless exec (memfd + AT_EMPTY_PATH) detected and killed"
	PASS=$((PASS + 1))
else
	echo "FAIL: memfd + AT_EMPTY_PATH exec was not detected - check the"
	echo "      AT_EMPTY_PATH branch in handler_pre_execveat() and the"
	echo "      empty-string sentinel handling in resolve_absolute_path()/"
	echo "      open_exec_target() in main.c"
	dmesg | tail -10
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 5: real dfd + non-empty relative path + AT_EMPTY_PATH set anyway ----

# 0x1000 = AT_EMPTY_PATH. Setting it here does NOT make the pathname
# argument optional/ignored - execveat(2) only special-cases an empty
# pathname. With a non-empty pathname the flag is inert and resolution
# proceeds exactly like Test 3 (relative to dfd), so this must still
# be detected. A hook that trusts the flag alone and skips scanning
# whenever it's set would silently miss this.
echo "-- Test 5: real dfd + relative path + AT_EMPTY_PATH set anyway --"
dmesg -C
"$TESTDIR/execveat_runner" "$TESTDIR/subdir" eicar.com 4096 || true
sleep 1
if check_detected "$TESTDIR/subdir/eicar.com"; then
	echo "PASS: AT_EMPTY_PATH + non-empty path still resolved/detected normally"
	PASS=$((PASS + 1))
else
	echo "FAIL: AT_EMPTY_PATH + non-empty path was NOT detected - handler_pre_execveat()"
	echo "      is treating the flag as authoritative and skipping the scan instead of"
	echo "      only special-casing an actually-empty pathname"
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 6: real dfd + empty pathname, AT_EMPTY_PATH NOT set ----

# Without AT_EMPTY_PATH, an empty pathname is invalid (ENOENT) - the
# syscall fails before executing anything, so no kill event should
# ever appear for it. Absence of a kill event alone doesn't prove
# that, though - the helper could have died before ever reaching the
# syscall, or (if handler_pre_execveat() regressed some other way) the
# syscall could have unexpectedly succeeded without being detected.
# execveat_runner exits with errno itself on failure (see the C source
# above), so assert the specific failure this case requires: ENOENT
# (value 2 on Linux - see errno-base.h), not just "something nonzero".
echo "-- Test 6: real dfd + empty path, AT_EMPTY_PATH NOT set --"
dmesg -C
rc=0
"$TESTDIR/execveat_runner" "$TESTDIR/subdir" "" 0 || rc=$?
sleep 1
ENOENT=2
if [ "$rc" -ne "$ENOENT" ]; then
	echo "FAIL: execveat_runner exited $rc, expected ENOENT ($ENOENT) - either it never"
	echo "      reached the syscall, or the syscall didn't fail the way this case requires"
	FAIL=$((FAIL + 1))
elif dmesg | tail -10 | grep -q 'event=detected.*action=kill'; then
	echo "FAIL: a kill event fired for a syscall that should have failed with ENOENT -"
	echo "      handler_pre_execveat() scanned dfd despite empty_path being false"
	dmesg | tail -10
	FAIL=$((FAIL + 1))
else
	echo "PASS: execveat() failed with ENOENT as expected, and no kill event fired"
	PASS=$((PASS + 1))
fi
echo

# ---- summary ----
# (cleanup of $TESTDIR happens via the EXIT trap set above)

echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
