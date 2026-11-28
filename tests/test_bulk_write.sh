#!/usr/bin/env bash
#
# tests/test_bulk_write.sh - #256: distinguish bulk file creation from
# in-place modification in the rapid-write heuristic.
#
#   - extracting a few hundred files must NOT be killed
#   - overwriting existing files in place must still be killed
#   - a creation-heavy burst must log (event=bulk-create), not kill
#
# All fixtures are built BEFORE loading av.ko: generating hundreds of
# files with the module loaded would itself trip the heuristic and kill
# this test script.
#
# Usage: sudo tests/test_bulk_write.sh
#
set -u

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root (insmod/rmmod). Re-run with sudo."
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091 # sourced at runtime; lint it on its own
. "$REPO_ROOT/tests/avd_guard.sh"
avd_guard || exit 1

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $*"; }
section() { echo; echo "== $* =="; }
# The kernel ring buffer is bounded and wraps. `dmesg | wc -l` can be a
# LARGER number than the current number of lines after it fills up, so
# `tail -n +$MARK` silently returns nothing and a hook that DID fire
# looks like a SKIP (observed on the Ubuntu 26.04 VM: a bulk-create line
# was present in dmesg while the canary reported no events). This test
# already owns the module and the daemon for its run, so clear the
# buffer at each mark instead of trusting a line count.
dmesg_mark() { dmesg -c >/dev/null 2>&1; echo 1; }
dmesg_since() { dmesg; }
# If the buffer cannot be cleared, every assertion below could match an
# old line from a previous run. Refuse to run instead of reporting a
# misleading PASS or SKIP.
if ! dmesg -c >/dev/null 2>&1; then
    echo "FAIL: cannot clear the kernel log buffer (root required)" >&2
    exit 1
fi

WORK="$(mktemp -d /tmp/av_bulk_write.XXXXXX)" || exit 1
AVD_PID=""
cleanup() {
    [ -n "$AVD_PID" ] && kill "$AVD_PID" 2>/dev/null || true
    wait "$AVD_PID" 2>/dev/null || true
    rmmod av 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

section "build"
MAKE_ARGS=()
if grep -q "clang version" /proc/version 2>/dev/null; then
    MAKE_ARGS=(CC=clang LLVM=1)
fi
make -C "$REPO_ROOT/av" "${MAKE_ARGS[@]}" >/dev/null || {
    fail "module build"; exit 1;
}
make -C "$REPO_ROOT/userspace/avd" >/dev/null || {
    fail "avd build"; exit 1;
}
pass "module and avd built"

section "fixtures (before loading the module)"
SRC="$WORK/src"
OVERWRITE="$WORK/overwrite"
mkdir -p "$SRC" "$OVERWRITE"
for i in $(seq 1 240); do printf 'file %s\n' "$i" > "$SRC/file_$i.txt"; done
for i in $(seq 1 120); do printf 'old\n' > "$OVERWRITE/f$i"; done
tar -czf "$WORK/archive.tgz" -C "$SRC" . || { fail "tar archive"; exit 1; }
cat > "$WORK/writer.c" <<'CEOF'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
/* Stay alive across the whole 2s window without exec'ing anything:
 * shell sleep/read timeouts perturb the probe budget in this test. */
int main(int argc, char **argv) {
  int i, create = (argc > 2 && atoi(argv[2]) == 1);
  if (argc < 2) return 2;
  for (i = 0; i < 120; i++) {
    char p[4096];
    int fd;
    snprintf(p, sizeof(p), "%s/%s%d", argv[1], create ? "n" : "f", i);
    fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { (void)!write(fd, "x", 1); close(fd); }
    usleep(10000);
  }
  return 0;
}
CEOF
gcc -O2 -o "$WORK/writer" "$WORK/writer.c" || { fail "writer build"; exit 1; }
pass "240-file archive, 120 overwrite fixtures and writer harness"

section "load module and start avd"
insmod "$REPO_ROOT/av/av.ko" || { fail "insmod"; exit 1; }
mkdir -p "$WORK/rules" "$WORK/quarantine"
cp "$REPO_ROOT"/rules/*.yar "$WORK/rules"/
cp "$REPO_ROOT/tests/fixtures/test.yar" "$WORK/rules/"
(
    cd "$REPO_ROOT" || exit 1
    exec "$REPO_ROOT/userspace/avd/avd" "$WORK/rules" \
        corpus/fuzzy_hashes.txt "$WORK/quarantine" corpus/tlsh_hashes.txt \
        "$WORK/control.sock" >"$WORK/avd.log" 2>&1
) &
AVD_PID=$!
for _ in $(seq 1 20); do
    [ -S "$WORK/control.sock" ] && break
    sleep 0.5
done
if [ -S "$WORK/control.sock" ]; then
    pass "avd started"
else
    fail "avd did not start"
    cat "$WORK/avd.log"
    exit 1
fi

# The security_file_open kretprobe does not fire on some newer kernels
# (seen on 7.3.x - see docs/evasion-findings.md). Without it none of the
# behavioral assertions below can pass, so skip rather than fail the
# whole suite on an unsupported stack.
section "canary: does the write hook fire on this kernel?"
mkdir -p "$WORK/canary"
MARK="$(dmesg_mark)"
"$WORK/writer" "$WORK/canary" 1 >/dev/null 2>&1
if ! dmesg_since "$MARK" | grep -q 'event=bulk-create'; then
    echo "  SKIP: no security_file_open behavior events on $(uname -r); see docs/evasion-findings.md"
    echo "bulk-write tests: skipped (hook not active)"
    exit 0
fi
pass "write hook is active"

section "1: tar extraction creates files and must not be killed"
mkdir -p "$WORK/dst"
MARK="$(dmesg_mark)"
tar -xzf "$WORK/archive.tgz" -C "$WORK/dst" >/dev/null 2>&1
rc=$?
if [ "$rc" -eq 0 ]; then
    pass "tar xzf of 240 files survived"
else
    fail "tar xzf exited $rc (killed by the behavior engine?)"
fi
if dmesg_since "$MARK" | grep -q 'reason="rapid file modification'; then
    fail "extraction triggered the rapid-write kill"
else
    pass "no rapid-write kill for extraction"
fi
if [ "$(find "$WORK/dst" -type f | wc -l)" -ge 240 ]; then
    pass "all files were extracted"
else
    fail "extraction was incomplete"
fi

section "2: in-place overwrites are still killed"
MARK="$(dmesg_mark)"
"$WORK/writer" "$OVERWRITE" 0 >/dev/null 2>&1 &
writer=$!
wait "$writer" 2>/dev/null
rc=$?
if [ "$rc" -eq 137 ]; then
    pass "in-place overwrite writer was SIGKILLed"
else
    fail "in-place overwrite writer exited $rc, expected 137"
fi
if dmesg_since "$MARK" | grep -q 'reason="rapid file modification'; then
    pass "rapid-write kill reason present for in-place writes"
else
    fail "no rapid-write kill logged for in-place writes"
fi

section "3: creation-heavy burst logs, does not kill"
mkdir -p "$WORK/create"
MARK="$(dmesg_mark)"
"$WORK/writer" "$WORK/create" 1 >/dev/null 2>&1
rc=$?
if [ "$rc" -eq 0 ]; then
    pass "creation-heavy writer survived"
else
    fail "creation-heavy writer exited $rc"
fi
if dmesg_since "$MARK" | grep -q 'event=bulk-create'; then
    pass "bulk-create was logged"
else
    fail "no event=bulk-create log line"
fi

echo
echo "bulk-write tests: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
