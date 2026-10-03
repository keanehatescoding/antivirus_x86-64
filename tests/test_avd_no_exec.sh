#!/usr/bin/env bash
#
# tests/test_avd_no_exec.sh - regression guard for #176's re-entrancy
# argument: avd answers FAN_OPEN_EXEC_PERM events for every exec on the
# machine, so if avd itself ever exec'd a program, that exec would be
# held waiting on avd. The watchdog (AVD_FANOTIFY_TIMEOUT_MS) bounds the
# damage, but the design relies on it never happening.
#
# Checks, against the built binary rather than the source alone (a
# macro or a new helper file could hide a call from a grep):
#   1. avd's own dynamic imports contain no exec/fork/spawn/system/
#      popen-family symbol.
#   2. Neither does any shared library avd links, except the allowlist
#      below - each entry says why the import is unreachable from avd.
#   3. The avd sources contain no such call (catches a static helper
#      before it is ever built).
#
# No root, no module, no daemon:
#   tests/test_avd_no_exec.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVD_DIR="$REPO_ROOT/userspace/avd"
AVD="$AVD_DIR/avd"

SYMS='execl|execle|execlp|execv|execve|execvp|execvpe|fexecve|execveat|fork|vfork|_Fork|clone3?|system|popen|posix_spawnp?|wordexp'

# Libraries allowed to import exec-family symbols, with the reason the
# import cannot be reached from avd. Keyed on the soname prefix.
#
#   libmagic: fork/posix_spawnp are only used by uncompressbuf() to run
#   external decompressors, which happens only with MAGIC_COMPRESS set.
#   libmagic is linked solely through libyara's "magic" module, which
#   calls magic_open() without MAGIC_COMPRESS - and no shipped rule
#   imports "magic" at all.
ALLOW_LIBS='^libmagic\.so'

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

if ! command -v nm >/dev/null 2>&1; then
    echo "SKIP: nm (binutils) not installed"
    exit 0
fi

if ! make -C "$AVD_DIR" >/dev/null 2>&1; then
    echo "FAIL: could not build avd"
    exit 1
fi

imports() {
    nm -D --undefined-only "$1" 2>/dev/null | awk '{print $NF}' |
        sed 's/@.*//' | grep -Ex "$SYMS" | sort -u | tr '\n' ' '
}

echo "=== avd's own imports ==="
found="$(imports "$AVD")"
if [ -z "$found" ]; then
    pass "avd imports no exec/fork/spawn-family symbol"
else
    fail "avd imports: $found"
fi

echo "=== linked libraries ==="
while read -r lib; do
    [ -n "$lib" ] || continue
    name="$(basename "$lib")"
    found="$(imports "$lib")"
    if [ -z "$found" ]; then
        continue
    elif echo "$name" | grep -Eq "$ALLOW_LIBS"; then
        pass "$name imports $found- allowlisted (see the comment above ALLOW_LIBS)"
    else
        fail "$name imports $found- reachable from avd? Audit, then allowlist with a reason"
    fi
done < <(ldd "$AVD" | awk '/=>/ && $3 ~ /^\// {print $3}')
pass "linked libraries audited"

echo "=== rules ==="
# The libmagic allowlist above holds only while no rule pulls in YARA's
# magic module - importing it is what links libmagic's code into scans.
magic="$(grep -lE '^[[:space:]]*import[[:space:]]+"magic"' "$REPO_ROOT"/rules/*.yar 2>/dev/null || true)"
if [ -z "$magic" ]; then
    pass "no shipped rule imports \"magic\""
else
    fail "rule(s) import \"magic\" (re-audit libmagic's fork/posix_spawnp): $magic"
fi

echo "=== sources ==="
# Call sites only: the name must start at a word boundary and be
# followed by an opening parenthesis; lines that start as comments are
# then dropped crudely. Not grep -w: that also demands a non-word
# character after the match, which ends in "(", so it would miss
# execve(path, ...) and system(cmd) and only catch fork().
hits="$(grep -nE "(^|[^[:alnum:]_])($SYMS)[[:space:]]*\(" "$AVD_DIR"/*.c "$AVD_DIR"/*.h |
        grep -vE '^[^:]+:[0-9]+:[[:space:]]*(\*|/\*|//)' || true)"
if [ -z "$hits" ]; then
    pass "no exec/fork/spawn-family call in userspace/avd sources"
else
    fail "exec-family call(s) in avd sources:"
    while IFS= read -r h; do echo "        $h"; done <<< "$hits"
fi

echo
echo "==================================="
echo "avd no-exec guard: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
