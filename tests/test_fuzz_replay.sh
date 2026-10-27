#!/usr/bin/env bash
#
# tests/test_fuzz_replay.sh - replays the checked-in libFuzzer corpora
# (tests/fuzz/corpus/) through the fuzz targets once each, under
# ASan+UBSan. This is the fast regression half of the fuzzing work in #105:
# every seed and every minimized crasher the fuzzers ever found is run
# against the current parsers, in seconds, with no fuzzing involved.
#
# The targets cover avd's externally reachable parsers: control-socket
# line reading and dispatch (control_parse.h, avd.c) and the fanotify
# mountinfo / signature parsers (fan_parse.h). See tests/fuzz/Makefile for
# how to fuzz for real.
#
# Pure userspace, no root or kernel module. Needs clang with the libFuzzer
# and sanitizer runtimes plus avd's own build dependencies; without them
# the test SKIPs (exit 0) so it cannot break a machine that lacks the
# toolchain. CI sets AV_FUZZ_REQUIRED=1 so a missing toolchain there is a
# failure rather than a silent skip.
#
#   tests/test_fuzz_replay.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$REPO_ROOT/tests/fuzz"
CLANG="${CLANG:-clang}"
PKG_CONFIG="${PKG_CONFIG:-pkg-config}"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_fuzz_replay.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
# False positive: cleanup() IS invoked, via `trap` on the next line.
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

skip() {
    if [ "${AV_FUZZ_REQUIRED:-0}" = "1" ]; then
        echo "FAIL: $1 (AV_FUZZ_REQUIRED=1, so this is not a skip)"
        exit 1
    fi
    echo "SKIP: $1"
    exit 0
}

command -v "$CLANG" >/dev/null 2>&1 || skip "$CLANG not found"

# Probe that this clang can actually link libFuzzer + the sanitizers; the
# compiler alone is not enough (Debian/Ubuntu ship the runtime separately,
# as libclang-rt-dev).
echo 'int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n)
{ (void)d; (void)n; return 0; }' > "$BUILD_DIR/probe.c"
"$CLANG" -fsanitize=fuzzer,address,undefined "$BUILD_DIR/probe.c" \
    -o "$BUILD_DIR/probe" >/dev/null 2>&1 \
    || skip "$CLANG cannot link libFuzzer/ASan/UBSan (install libclang-rt-dev)"

"$PKG_CONFIG" --exists libnl-genl-3.0 yara 2>/dev/null \
    || skip "libnl-genl-3.0 and yara dev packages not found (needed to build the avd.c dispatcher target)"

echo "building fuzz targets:"
if ! make -C "$FUZZ_DIR" CLANG="$CLANG" all > "$BUILD_DIR/build.log" 2>&1; then
    echo "FAIL: could not build the fuzz targets:"
    cat "$BUILD_DIR/build.log"
    exit 1
fi

PASS=0
FAIL=0
for target in fuzz_fan_parse fuzz_control_parse fuzz_control_line; do
    seeds="$(find "$FUZZ_DIR/corpus/$target" -type f 2>/dev/null | wc -l)"
    if [ "$seeds" -eq 0 ]; then
        echo "  FAIL: $target has no seed corpus"
        FAIL=$((FAIL + 1))
        continue
    fi
    if "$FUZZ_DIR/$target" -runs=0 "$FUZZ_DIR/corpus/$target" \
            > "$BUILD_DIR/$target.log" 2>&1; then
        echo "  PASS: $target ($seeds inputs)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $target"
        grep -E "contract violated|ERROR: |runtime error|SUMMARY" \
            "$BUILD_DIR/$target.log" | head -5 | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi
done

# Remove only the binaries built above; work/ and crash-* from an earlier
# `make run` are fuzzing results and must survive a replay.
make -C "$FUZZ_DIR" clean-bin >/dev/null 2>&1

echo
echo "fuzz replay: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
