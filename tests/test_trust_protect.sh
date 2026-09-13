#!/usr/bin/env bash
#
# tests/test_trust_protect.sh - exercises the avctl <-> /proc/kernel_av_trusted
# and /proc/kernel_av_protected protocols: add/list/del, plus
# malformed-input rejection.
#
# Closes the TRUST/PROTECT half of issue #104: trust_proc_write() /
# protected_proc_write() (av/behavior.c) previously had no end-to-end
# functional coverage confirming trust/protect actually gate behavior as
# intended - test_sigtable.sh only covers /proc/kernel_av_signatures.
#
# Run this INSIDE YOUR VM, with the av module already built.
# Does NOT insmod/rmmod for you - run it against a module you've already
# loaded, so you can inspect state between test runs if something fails.
#
# Usage:
#   sudo insmod av/av.ko          # if not already loaded
#   cd userspace/avctl && make
#   ../../tests/test_trust_protect.sh
#
set -uo pipefail

AVCTL="$(cd "$(dirname "${BASH_SOURCE[0]}")/../userspace/avctl" && pwd)/avctl"
TRUST_PROC_PATH="/proc/kernel_av_trusted"
PROTECTED_PROC_PATH="/proc/kernel_av_protected"

PASS=0
FAIL=0

# Private capture file for avctl output - run_all.sh runs this suite as
# root, so a fixed /tmp path could follow an attacker-created symlink
# and truncate an attacker-chosen target.
TMP_OUT="$(mktemp)" || exit 1
trap 'rm -f "$TMP_OUT"' EXIT

# A syntactically valid but harmless test hash - all zeros, 64 hex chars.
TEST_SHA256_VALID="0000000000000000000000000000000000000000000000000000000000000000"
TEST_NAME="test-trust-do-not-flag"
# Absolute but (almost certainly) nonexistent - protect_add() only checks
# absoluteness/length, never existence, so no fixture file is needed.
TEST_PROTECT_PATH="/tmp/av-test-protected-do-not-flag"

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

section() { echo; echo "== $1 =="; }

require_module_loaded() {
    if [ ! -e "$TRUST_PROC_PATH" ] || [ ! -e "$PROTECTED_PROC_PATH" ]; then
        echo "ERROR: $TRUST_PROC_PATH or $PROTECTED_PROC_PATH does not exist - is the av module loaded?"
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

section "trust add a valid hash"
if "$AVCTL" trust add "$TEST_SHA256_VALID" "$TEST_NAME" >"$TMP_OUT" 2>&1; then
    pass "trust add returned success"
else
    fail "trust add returned non-zero: $(cat "$TMP_OUT")"
fi

# List assertions capture to a file and grep that, never `list | grep`:
# a failed list piped into grep would make an absence check false-pass,
# and grep -q can SIGPIPE avctl on a large list.
section "trust list shows the added hash"
if "$AVCTL" trust list >"$TMP_OUT" 2>&1 && grep -q "$TEST_SHA256_VALID" "$TMP_OUT"; then
    pass "hash present in trust list"
else
    fail "hash missing from trust list (or list failed)"
fi

section "trust del removes it"
if "$AVCTL" trust del "$TEST_SHA256_VALID" >"$TMP_OUT" 2>&1; then
    pass "trust del returned success"
else
    fail "trust del returned non-zero: $(cat "$TMP_OUT")"
fi

section "trust list no longer shows it"
if "$AVCTL" trust list >"$TMP_OUT" 2>&1 && ! grep -q "$TEST_SHA256_VALID" "$TMP_OUT"; then
    pass "hash gone from trust list"
else
    fail "hash still present in trust list after del (or list failed)"
fi

section "trust del of a nonexistent hash errors cleanly"
if "$AVCTL" trust del "$TEST_SHA256_VALID" >"$TMP_OUT" 2>&1; then
    fail "trust del of a nonexistent hash unexpectedly succeeded"
else
    pass "trust del of a nonexistent hash failed as expected"
fi

section "trust add rejects a malformed (too-short) hash"
if echo "add deadbeef $TEST_NAME" > "$TRUST_PROC_PATH" 2>"$TMP_OUT"; then
    fail "short-hash trust add unexpectedly succeeded"
else
    pass "short-hash trust add rejected"
fi

section "trust rejects an unknown verb"
if echo "frobnicate $TEST_SHA256_VALID $TEST_NAME" > "$TRUST_PROC_PATH" 2>"$TMP_OUT"; then
    fail "unknown-verb trust write unexpectedly succeeded"
else
    pass "unknown-verb trust write rejected"
fi

section "protect add an absolute path"
if "$AVCTL" protect add "$TEST_PROTECT_PATH" >"$TMP_OUT" 2>&1; then
    pass "protect add returned success"
else
    fail "protect add returned non-zero: $(cat "$TMP_OUT")"
fi

section "protect list shows the added path"
if "$AVCTL" protect list >"$TMP_OUT" 2>&1 && grep -q "$TEST_PROTECT_PATH" "$TMP_OUT"; then
    pass "path present in protected list"
else
    fail "path missing from protected list (or list failed)"
fi

section "protect del removes it"
if "$AVCTL" protect del "$TEST_PROTECT_PATH" >"$TMP_OUT" 2>&1; then
    pass "protect del returned success"
else
    fail "protect del returned non-zero: $(cat "$TMP_OUT")"
fi

section "protect list no longer shows it"
if "$AVCTL" protect list >"$TMP_OUT" 2>&1 && ! grep -q "$TEST_PROTECT_PATH" "$TMP_OUT"; then
    pass "path gone from protected list"
else
    fail "path still present in protected list after del (or list failed)"
fi

section "protect del of a nonexistent path errors cleanly"
if "$AVCTL" protect del "$TEST_PROTECT_PATH" >"$TMP_OUT" 2>&1; then
    fail "protect del of a nonexistent path unexpectedly succeeded"
else
    pass "protect del of a nonexistent path failed as expected"
fi

section "protect add rejects a relative path"
if "$AVCTL" protect add "relative/path" >"$TMP_OUT" 2>&1; then
    fail "relative-path protect add unexpectedly succeeded"
else
    pass "relative-path protect add rejected"
fi

section "protect rejects an unknown verb"
if echo "frobnicate $TEST_PROTECT_PATH" > "$PROTECTED_PROC_PATH" 2>"$TMP_OUT"; then
    fail "unknown-verb protect write unexpectedly succeeded"
else
    pass "unknown-verb protect write rejected"
fi

echo
echo "==================================="
echo "trust/protect tests: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
