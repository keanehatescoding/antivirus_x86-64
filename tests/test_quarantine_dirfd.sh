#!/usr/bin/env bash
#
# tests/test_quarantine_dirfd.sh - static checks that quarantine_file()
# and its helpers create the quarantine entry through the pinned
# quarantine dirfd from open_quarantine_dir(), not by full path (#231;
# mirrors keanehatescoding/antivirus_arm64's #64 item 1 checks). The
# behavior itself - files quarantined, sidecars written, originals
# removed - is covered end to end by tests/test_perform_scan.sh, and
# the original's removal by tests/test_quarantine_unlink.sh.
#
# Pure source-level greps, no root, no module, no VM:
#   tests/test_quarantine_dirfd.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVD="$REPO_ROOT/userspace/avd/avd.c"

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

# Scoped to the one function each assertion is about, so a matching
# token elsewhere in avd.c cannot mask a regression at the real site.
extract_c_func() { # $1 = file, $2 = function name (defined at column 0)
    awk -v fn="$2" '$0 ~ "^static .* " fn "\\(" {in_body=1} in_body{print} in_body && /^}/{exit}' "$1"
}

expect() { # $1 = body, $2 = fixed string, $3 = description
    if grep -qF -- "$2" <<< "$1"; then pass "$3"; else fail "$3"; fi
}

QFILE="$(extract_c_func "$AVD" quarantine_file)"
QOPEN="$(extract_c_func "$AVD" open_quarantine_dir)"
QCOPY="$(extract_c_func "$AVD" copy_fd_to_at)"
QMETA="$(extract_c_func "$AVD" write_quarantine_meta)"

expect "$QOPEN" 'dir_hierarchy_trusted("quarantine dir"' \
    "open_quarantine_dir() validates the whole chain"
expect "$QOPEN" 'O_DIRECTORY | O_NOFOLLOW' \
    "open_quarantine_dir() opens the final component without following it"
expect "$QFILE" 'qdirfd = open_quarantine_dir();' \
    "quarantine_file() pins the quarantine dir"
expect "$QFILE" 'linkat(fd, "", qdirfd, name, AT_EMPTY_PATH)' \
    "linkat() goes through the pinned dirfd"
expect "$QFILE" 'copy_fd_to_at(fd, qdirfd, name)' \
    "copy fallback receives the pinned dirfd"
expect "$QFILE" 'write_quarantine_meta(qdirfd, name,' \
    "sidecar is written through the pinned dirfd"
expect "$QFILE" 'fchmodat(qdirfd, name, 0000, 0)' \
    "lockdown chmod goes through the pinned dirfd"
expect "$QFILE" 'unlinkat(qdirfd, name, 0)' \
    "chmod-failure cleanup goes through the pinned dirfd"
expect "$QCOPY" 'openat(dirfd, name,' \
    "copy_fd_to_at() creates the copy relative to the dirfd"
expect "$QMETA" 'openat(qdirfd, meta_name,' \
    "write_quarantine_meta() creates the sidecar relative to the dirfd"

if grep -qE '(linkat|openat|fchmodat|unlinkat)\([^;]*AT_FDCWD' <<< "$QFILE$QCOPY$QMETA"; then
    fail "quarantine creation still resolves a path via AT_FDCWD"
else
    pass "no AT_FDCWD path resolution in quarantine creation"
fi
# Comment lines are skipped: they still name the plain calls in prose.
if grep -vE '^[[:space:]]*(/?\*)' <<< "$QFILE$QCOPY$QMETA" |
        grep -qE '(^|[^a-z_])(chmod|unlink|open)\('; then
    fail "quarantine creation still calls a path-based chmod/unlink/open"
else
    pass "no path-based chmod/unlink/open in quarantine creation"
fi
# open_quarantine_dir()'s own open() of quarantine_dir is the one
# deliberate path-based call, and it is outside the bodies checked above.

echo
echo "test_quarantine_dirfd.sh: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
