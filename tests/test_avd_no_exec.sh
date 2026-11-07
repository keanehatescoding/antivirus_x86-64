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
#      before it is ever built), and no exec/fork/clone syscall number
#      (catches syscall(SYS_execveat, ...), which imports only syscall).
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

# Source files allowed to call plain fork(), and nothing else exec-family
# (#103). The privilege-separation spawner forks scan workers and never execs
# them: a forked child that does not exec raises no FAN_OPEN_EXEC_PERM event,
# so the re-entrancy argument above does not apply to it, and the design needs
# the children to inherit the compiled rules copy-on-write, which an exec
# would throw away (docs/privilege-separation.md, "The spawner"). Every
# exec/spawn/system/popen/vfork/clone call stays banned in these files too.
# Keyed on the file's basename. Since the spawner is linked into avd
# (Stage 1e), avd itself imports fork, so its own import check below allows
# fork and nothing else (SYMS_NO_FORK); this source scan is what keeps the
# fork() call confined to the spawner.
FORK_ALLOW_SRC='^privsep_spawner\.h$'
SYMS_NO_FORK='execl|execle|execlp|execv|execve|execvp|execvpe|fexecve|execveat|vfork|_Fork|clone3?|system|popen|posix_spawnp?|wordexp'

# The spawner's seccomp filter has to NAME the clone syscall to allow exactly
# fork()'s flags and nothing else (#103, privsep_lockdown.h); it is an
# allowance in a filter, not a call. Only the plain clone number is exempt, and
# only in that file: execve/execveat/fork/vfork/clone3 numbers stay banned
# there, and clone stays banned everywhere else. Same scope as the fork
# allowance above, and the source scan only.
CLONE_NR_ALLOW_SRC='^privsep_lockdown\.h$'

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

# imports BINARY [PATTERN] - the dynamic imports of BINARY matching PATTERN
# (default: $SYMS, the full exec/fork/spawn family).
imports() {
    nm -D --undefined-only "$1" 2>/dev/null | awk '{print $NF}' |
        sed 's/@.*//' | grep -Ex "${2:-$SYMS}" | sort -u | tr '\n' ' '
}

echo "=== avd's own imports ==="
# fork is allowed (the privsep spawner, see FORK_ALLOW_SRC); every other
# exec/spawn-family symbol is not.
found="$(imports "$AVD" "$SYMS_NO_FORK")"
if [ -z "$found" ]; then
    pass "avd imports no exec/spawn-family symbol (fork only, for the privsep spawner)"
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
# Any use of the name as an identifier, not only a call: "#define SPAWN
# fork" followed by SPAWN() never spells "fork(", and neither does a
# function pointer, and avd's import check above already allows fork, so
# this scan is what confines it to the spawner. Comments and string
# literals are stripped first (crudely, one line at a time: a // or /* */
# comment, an unclosed /* to end of line, "..."), then lines that start
# as comment continuations are dropped.
strip_comments() {
    sed -E 's#//.*$##; s#/\*([^*]|\*+[^*/])*\*+/##g; s#/\*.*$##; s#"([^"\\]|\\.)*"#""#g' "$1"
}
hits=""
for f in "$AVD_DIR"/*.c "$AVD_DIR"/*.h; do
    syms="$SYMS"
    if basename "$f" | grep -Eq "$FORK_ALLOW_SRC"; then
        syms="$SYMS_NO_FORK"
    fi
    found="$(strip_comments "$f" | grep -nE "(^|[^[:alnum:]_])($syms)([^[:alnum:]_]|$)" |
             grep -vE '^[0-9]+:[[:space:]]*(\*|/\*|//)' | sed "s#^#$f:#" || true)"
    [ -n "$found" ] && hits+="$found"$'\n'
done
hits="${hits%$'\n'}"
if [ -z "$hits" ]; then
    pass "no exec/fork/spawn-family call in userspace/avd sources"
else
    fail "exec-family call(s) in avd sources:"
    while IFS= read -r h; do echo "        $h"; done <<< "$hits"
fi

# Raw syscall(SYS_execveat, ...) bypasses both checks above: the import
# is just "syscall", and the call site does not name an exec function.
# Flag the syscall numbers themselves - any use, not only as a direct
# syscall() argument, so a call split across lines or a number passed
# through a variable is caught too.
NRS='(SYS|__NR)_(execve|execveat|fork|vfork|clone|clone3)'
NRS_NO_CLONE='(SYS|__NR)_(execve|execveat|fork|vfork|clone3)'
hits=""
for f in "$AVD_DIR"/*.c "$AVD_DIR"/*.h; do
    nrs="$NRS"
    if basename "$f" | grep -Eq "$CLONE_NR_ALLOW_SRC"; then
        nrs="$NRS_NO_CLONE"
    fi
    found="$(grep -nHE "(^|[^[:alnum:]_])$nrs([^[:alnum:]_]|$)" "$f" |
             grep -vE '^[^:]+:[0-9]+:[[:space:]]*(\*|/\*|//)' || true)"
    [ -n "$found" ] && hits+="$found"$'\n'
done
hits="${hits%$'\n'}"
if [ -z "$hits" ]; then
    pass "no exec/fork/clone syscall number in userspace/avd sources"
else
    fail "raw exec/fork/clone syscall(s) in avd sources:"
    while IFS= read -r h; do echo "        $h"; done <<< "$hits"
fi

echo
echo "==================================="
echo "avd no-exec guard: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
