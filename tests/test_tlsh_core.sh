#!/usr/bin/env bash
#
# tests/test_tlsh_core.sh - known-answer tests for the hand-ported TLSH
# implementation in userspace/avd/tlsh_core.c/tlsh_shim.c. Unlike
# sha256.c (published FIPS 180-4 vectors exist), TLSH has no public
# known-answer test suite - the expected digests below were generated
# with the real system oracle (`tlsh -old -f <file>`, the tlsh-tools
# package's `tlsh` CLI, libtlsh.so.4 4.12.0 - the "-old" flag is what
# gets its no-"T1"-prefix output, matching this port's format; the
# plain default now version-prefixes) against these exact fixed inputs,
# cross-checked against this port's own output before being hardcoded
# here. A hand-ported algorithm with no automated check against
# independently-generated vectors is exactly the kind of
# silent-corruption risk this test exists to catch (see tlsh_core.c's
# own top comment: "any transcription error here would silently
# produce plausible-looking but wrong hashes for every input, not a
# crash") - re-running the oracle isn't required for this test to be
# useful, only to have generated it once.
#
# Pure userspace, no kernel module or root needed - safe to run
# standalone, same as test_sha256.sh:
#   tests/test_tlsh_core.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVD_DIR="$REPO_ROOT/userspace/avd"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_tlsh.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

# kat_a/kat_b/kat_c: three fixed, reproducible text files (kat_b is
# kat_a plus one appended line - a "near-duplicate" scenario, same
# spirit as the README's ptrace_test/ptrace_test_variant manual TLSH
# test; kat_c is unrelated content). All three exceed MIN_DATA_LENGTH
# (50 bytes) with enough byte diversity to produce a valid digest.
cat > "$BUILD_DIR/kat_a.txt" <<'EOF'
The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs. How vexingly quick daft zebras jump! The five boxing wizards jump quickly. Sphinx of black quartz, judge my vow.
The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs. How vexingly quick daft zebras jump! The five boxing wizards jump quickly. Sphinx of black quartz, judge my vow.
The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs. How vexingly quick daft zebras jump! The five boxing wizards jump quickly. Sphinx of black quartz, judge my vow.
EOF

cp "$BUILD_DIR/kat_a.txt" "$BUILD_DIR/kat_b.txt"
echo "EXTRA-PADDING-APPENDED-FOR-VARIANT-TEST" >> "$BUILD_DIR/kat_b.txt"

cat > "$BUILD_DIR/kat_c.txt" <<'EOF'
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum.
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum.
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum.
EOF

# kat_short.txt: deliberately under MIN_DATA_LENGTH (50 bytes) -
# av_tlsh_hash_fd() must return -2 ("no verdict", not an error), never
# a fabricated digest.
printf 'too short for tlsh' > "$BUILD_DIR/kat_short.txt"

cat > "$BUILD_DIR/kat.c" <<'EOF'
/* TLSH known-answer tests - built and run by tests/test_tlsh_core.sh
 * only, not part of the shipped avd binary. Expected digests generated
 * against the real system libtlsh oracle (`tlsh -old -f`), not
 * hand-derived - see this file's shell wrapper for the full story. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "tlsh_shim.h"

static int PASS, FAIL;

static void check_hash(const char *label, const char *path, int expect_ret,
                        const char *expected_hash) {
    int fd = open(path, O_RDONLY);
    char hash[256];
    int ret;

    if (fd < 0) {
        printf("  FAIL: %s: could not open %s\n", label, path);
        FAIL++;
        return;
    }
    ret = av_tlsh_hash_fd(fd, hash, sizeof(hash), (size_t)-1);
    close(fd);

    if (ret != expect_ret) {
        printf("  FAIL: %s: av_tlsh_hash_fd() returned %d, expected %d\n",
               label, ret, expect_ret);
        FAIL++;
        return;
    }
    if (expect_ret != 0) {
        printf("  PASS: %s\n", label);
        PASS++;
        return;
    }
    if (strcmp(hash, expected_hash) == 0) {
        printf("  PASS: %s\n", label);
        PASS++;
    } else {
        printf("  FAIL: %s: got %s, expected %s\n", label, hash, expected_hash);
        FAIL++;
    }
}

static void check_diff(const char *label, const char *hash_a,
                        const char *hash_b, int expected_diff) {
    int diff = av_tlsh_diff(hash_a, hash_b);

    if (diff == expected_diff) {
        printf("  PASS: %s\n", label);
        PASS++;
    } else {
        printf("  FAIL: %s: got diff=%d, expected %d\n", label, diff,
               expected_diff);
        FAIL++;
    }
}

int main(void) {
    static const char hash_a[] =
        "6DF023C4F665119516E9040C435E7572D1EC8A045313F63050745183205C1734CF06B5";
    static const char hash_b[] =
        "BFF0FEC5F66915961AEA080D439E75B2D2FC9A48A313FB3150789193205C2734CF47FA";
    static const char hash_c[] =
        "8901AB3C834D5B647E9330FEF269696FE95872200A35DB5EA9E6C59F48012048536726";

    check_hash("kat_a.txt digest", "kat_a.txt", 0, hash_a);
    check_hash("kat_b.txt digest (kat_a + appended line)", "kat_b.txt", 0,
               hash_b);
    check_hash("kat_c.txt digest (unrelated content)", "kat_c.txt", 0, hash_c);
    check_hash("kat_short.txt (< MIN_DATA_LENGTH) yields no digest",
               "kat_short.txt", -2, NULL);

    /* av_tlsh_hash_maxlen() is the contract av_tlsh_hash_fd()'s callers
     * (avd.c's AV_TLSH_HASH_BUFSZ check) size their buffers against -
     * regressing this silently would widen every buffer-overflow-
     * defense-in-depth check in avd.c into a false sense of safety. */
    if (av_tlsh_hash_maxlen() == 70) {
        printf("  PASS: av_tlsh_hash_maxlen() == 70\n");
        PASS++;
    } else {
        printf("  FAIL: av_tlsh_hash_maxlen() == %zu, expected 70\n",
               av_tlsh_hash_maxlen());
        FAIL++;
    }

    check_diff("av_tlsh_diff(a, a) == 0 (identical digests)", hash_a, hash_a, 0);
    check_diff("av_tlsh_diff(a, b) matches the real-libtlsh oracle", hash_a,
               hash_b, 102);
    check_diff("av_tlsh_diff(a, c) matches the real-libtlsh oracle", hash_a,
               hash_c, 371);

    /* Malformed input (wrong length / non-hex) must be rejected, not
     * silently parsed into a garbage digest that then compares
     * "successfully" against real corpus entries. */
    if (av_tlsh_diff("not-a-valid-tlsh-digest", hash_a) == -1) {
        printf("  PASS: av_tlsh_diff() rejects a malformed digest\n");
        PASS++;
    } else {
        printf("  FAIL: av_tlsh_diff() accepted a malformed digest\n");
        FAIL++;
    }

    printf("\n===================================\n");
    printf("tlsh_core known-answer tests: %d passed, %d failed\n", PASS, FAIL);
    printf("===================================\n");
    return FAIL ? 1 : 0;
}
EOF

if ! cc -Wall -Wextra -O2 -I "$AVD_DIR" \
        "$BUILD_DIR/kat.c" "$AVD_DIR/tlsh_core.c" "$AVD_DIR/tlsh_shim.c" \
        -o "$BUILD_DIR/kat" 2>"$BUILD_DIR/build.log"; then
    echo "FAIL: could not build the tlsh_core known-answer test - see build log:"
    cat "$BUILD_DIR/build.log"
    exit 1
fi

(cd "$BUILD_DIR" && ./kat)
exit $?
