#!/usr/bin/env bash
#
# tests/test_sigtable.sh - exercises the avctl <-> /proc/kernel_av_signatures
# protocol: add/list/del, plus malformed-input rejection.
#
# Run this INSIDE YOUR VM, with the av module already built.
# Does NOT insmod/rmmod for you - run it against a module you've already
# loaded, so you can inspect state between test runs if something fails.
#
# Usage:
#   sudo insmod av/av.ko          # if not already loaded
#   cd userspace/avctl && make
#   ../../tests/test_sigtable.sh
#
set -u

AVCTL="$(cd "$(dirname "${BASH_SOURCE[0]}")/../userspace/avctl" && pwd)/avctl"
PROC_PATH="/proc/kernel_av_signatures"

PASS=0
FAIL=0

# A syntactically valid but harmless test hash - all zeros, 64 hex chars.
TEST_SHA256_VALID="0000000000000000000000000000000000000000000000000000000000000000"
TEST_NAME="test-signature-do-not-flag"

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

section() { echo; echo "== $1 =="; }

require_module_loaded() {
    if [ ! -e "$PROC_PATH" ]; then
        echo "ERROR: $PROC_PATH does not exist - is the av module loaded?"
        echo "  sudo insmod av/av.ko"
        exit 1
    fi
    if [ ! -x "$AVCTL" ]; then
        echo "ERROR: avctl not built at $AVCTL"
        echo "  cd userspace/avctl && make"
        exit 1
    fi
}

require_module_loaded

section "add a valid signature"
if "$AVCTL" add sha256 "$TEST_SHA256_VALID" "$TEST_NAME" >/tmp/avctl_out 2>&1; then
    pass "add returned success"
else
    fail "add returned non-zero: $(cat /tmp/avctl_out)"
fi

section "list shows the added signature"
if "$AVCTL" list | grep -q "$TEST_SHA256_VALID"; then
    pass "signature appears in list"
else
    fail "signature missing from list"
fi

section "del removes it"
if "$AVCTL" del sha256 "$TEST_SHA256_VALID" >/tmp/avctl_out 2>&1; then
    pass "del returned success"
else
    fail "del returned non-zero: $(cat /tmp/avctl_out)"
fi

section "list no longer shows it"
if "$AVCTL" list | grep -q "$TEST_SHA256_VALID"; then
    fail "signature still present after del"
else
    pass "signature correctly absent after del"
fi

section "del of a nonexistent signature errors cleanly"
if "$AVCTL" del sha256 "$TEST_SHA256_VALID" >/tmp/avctl_out 2>&1; then
    fail "del of already-removed signature unexpectedly succeeded"
else
    pass "del of nonexistent signature correctly failed"
fi

section "add rejects a malformed (too-short) hash"
if echo "add sha256 deadbeef $TEST_NAME" > "$PROC_PATH" 2>/tmp/avctl_out; then
    fail "malformed hash was accepted (should have been rejected)"
else
    pass "malformed hash correctly rejected"
fi

section "add rejects an unknown algorithm"
if echo "add notarealalgo $TEST_SHA256_VALID $TEST_NAME" > "$PROC_PATH" 2>/tmp/avctl_out; then
    fail "unknown algorithm was accepted (should have been rejected)"
else
    pass "unknown algorithm correctly rejected"
fi

section "EICAR seed signature is present after module load"
if "$AVCTL" list | grep -qi "EICAR"; then
    pass "seeded EICAR signature found"
else
    fail "seeded EICAR signature NOT found - check av_init() seeding"
fi

section "proc entry restricts reads to owner/group (0640, #143)"
if [ "$(stat -c %a "$PROC_PATH")" = "640" ]; then
    pass "mode is 0640"
else
    fail "mode is $(stat -c %a "$PROC_PATH"), expected 640"
fi

echo
echo "==================================="
echo "sigtable tests: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
