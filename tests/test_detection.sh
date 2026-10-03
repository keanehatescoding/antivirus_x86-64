#!/usr/bin/env bash
#
# tests/test_detection.sh - end-to-end integration test: builds the module,
# loads it, runs a known-clean command and the EICAR test file, checks
# dmesg for the expected outcome, then unloads.
#
# RUN THIS ONLY IN YOUR VM, ideally from a fresh snapshot. It loads a
# kernel module - if there's a regression this script won't catch, the
# usual kernel-module risks apply (see top-level README).
#
# Usage: sudo tests/test_detection.sh
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
AV_DIR="$REPO_ROOT/av"
# Private mktemp -d, not a fixed /tmp/av_test_eicar.com path: this script
# runs as root and writes the EICAR file plus build/insmod/rmmod logs,
# so a predictable world-writable-directory path lets a local attacker
# pre-plant a symlink (e.g. to /etc/...) that the root redirect/write
# would then follow. mktemp -d's random suffix plus its 0700 mode close
# both the guessable-name and the anyone-can-write angles at once -
# same pattern as tests/test_netlink.sh and tests/benchmark.sh.
TEST_TMP_DIR="$(mktemp -d -- /tmp/av_test_detection.XXXXXX)" || exit 1
EICAR_PATH="$TEST_TMP_DIR/eicar.com"
BUILD_LOG="$TEST_TMP_DIR/build.log"
INSMOD_LOG="$TEST_TMP_DIR/insmod.log"
RMMOD_LOG="$TEST_TMP_DIR/rmmod.log"
EICAR_HASH="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
section() { echo; echo "== $1 =="; }

# dmesg can lag the event being checked for (detection is async via the
# workqueue), so retry a few times before treating a missing line as a
# real failure - same pattern as tests/test_netlink.sh's clean round-trip
# retry loop. $1 = grep -E pattern, $2 = attempts (default 5).
wait_for_dmesg() {
    local pattern="$1" attempts="${2:-5}"
    for _ in $(seq 1 "$attempts"); do
        if dmesg | grep -qiE "$pattern"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# A module MUST be built with the same compiler family as the running
# kernel (see the top-level README's toolchain section) - e.g. CachyOS
# ships kernels built with Clang. We can't rely on inherited CC/LLVM
# environment variables here: this script is meant to run under sudo
# (for insmod/rmmod), and sudo resets the environment by default,
# stripping any CC=clang LLVM=1 the user had exported. Detecting the
# running kernel's actual build toolchain directly is robust regardless
# of how this script gets invoked or what the caller's shell had set.
MAKE_ARGS=()
if grep -q "clang version" /proc/version 2>/dev/null; then
    echo "Detected a Clang-built running kernel ($(uname -r)) - building with CC=clang LLVM=1"
    MAKE_ARGS=(CC=clang LLVM=1)
fi

cleanup() {
    section "cleanup"
    rmmod av 2>/dev/null && echo "  module unloaded" || echo "  module already unloaded"
    rm -rf "$TEST_TMP_DIR"
}
trap cleanup EXIT

section "build"
if make -C "$AV_DIR" "${MAKE_ARGS[@]}" clean >"$BUILD_LOG" 2>&1 && \
   make -C "$AV_DIR" "${MAKE_ARGS[@]}" >>"$BUILD_LOG" 2>&1; then
    pass "module built"
else
    fail "build failed - see $BUILD_LOG"
    cat "$BUILD_LOG"
    exit 1
fi

section "load"
if insmod "$AV_DIR/av.ko" 2>"$INSMOD_LOG"; then
    pass "module loaded"
else
    fail "insmod failed: $(cat "$INSMOD_LOG")"
    exit 1
fi
sleep 1

section "clean-file sanity check (should NOT be killed, should log as clean)"
dmesg -C  # clear dmesg so we only see events from this point on
# No avd here, so /bin/ls logs through the fail-open clean line - a
# pr_info_ratelimited() call site (kernel default: 10 lines per 5s
# window) shared with every other exec on the host. Background exec
# activity can use a whole window up before this exec lands in it, so
# each attempt re-runs the exec and waits longer than one window,
# letting the next attempt start in a fresh one.
#
# The module logs the canonical d_path() of the file actually executed,
# so on usr-merged distros (/bin -> usr/bin) /bin/ls shows up as
# /usr/bin/ls - match on the resolved path, not the one typed here.
CLEAN_BIN="$(readlink -f /bin/ls)"
CLEAN_OK=0
for _ in 1 2 3 4; do
    /bin/ls >/dev/null
    if wait_for_dmesg "event=clean.*path=\"$CLEAN_BIN\"" 6; then
        CLEAN_OK=1
        break
    fi
done
if [ "$CLEAN_OK" -eq 1 ]; then
    pass "clean file logged as clean"
else
    fail "expected clean-file log line not found in dmesg"
fi
if dmesg | grep -q "event=detected.*path=\"$CLEAN_BIN\""; then
    fail "clean file was incorrectly flagged as a detection"
else
    pass "clean file was not flagged"
fi

section "EICAR detection"
# Single quotes are intentional: this string has literal $ characters
# that must NOT be shell-expanded.
# shellcheck disable=SC2016
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$EICAR_PATH"
chmod +x "$EICAR_PATH"

ACTUAL_HASH="$(sha256sum "$EICAR_PATH" | awk '{print $1}')"
if [ "$ACTUAL_HASH" = "$EICAR_HASH" ]; then
    pass "EICAR file hash matches expected value"
else
    fail "EICAR file hash mismatch: got $ACTUAL_HASH, expected $EICAR_HASH"
fi

dmesg -C
"$EICAR_PATH" >/dev/null 2>&1
# Detection is async (workqueue) and dmesg can lag the event - retry
# rather than treating a single delayed poll as a real failure.
if wait_for_dmesg 'event=detected.*action=kill.*reason="signature:EICAR-Test-File"' 5; then
    pass "EICAR execution was detected and killed"
else
    fail "expected DETECTED/killing log line not found in dmesg"
    dmesg | tail -10
fi

section "unload"
if rmmod av 2>"$RMMOD_LOG"; then
    pass "module unloaded cleanly"
else
    fail "rmmod failed: $(cat "$RMMOD_LOG")"
fi

echo
echo "==================================="
echo "detection tests: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
