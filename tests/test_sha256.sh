#!/usr/bin/env bash
#
# tests/test_sha256.sh - known-answer tests (FIPS 180-4 test vectors)
# for the self-contained SHA-256 implementation in
# userspace/avd/sha256.c - used to hash on-demand scans (see
# docs/avd-socket-protocol.md and this project's minimal-dependency
# stance on not linking libcrypto for one hash). A hand-rolled hash
# with no automated check against published vectors is exactly the
# kind of silent-corruption risk this test exists to catch: a wrong
# digest here would corrupt the SHA256= quarantine metadata field and
# every VERDICTS/SCAN response involving an on-demand scan, with
# nothing else in this codebase positioned to notice.
#
# Pure userspace, no kernel module or root needed - unlike most of
# tests/, safe to run standalone:
#   tests/test_sha256.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVD_DIR="$REPO_ROOT/userspace/avd"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_sha256.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
# False positive: cleanup() IS invoked, via `trap` on the very next
# line - the linter loses track of that reference across the C
# heredoc further down (verified by bisecting this file: truncating it
# right after the trap line below makes the warning disappear).
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

cat > "$BUILD_DIR/kat.c" <<'EOF'
/* FIPS 180-4 known-answer vectors for sha256.c - built and run by
 * tests/test_sha256.sh only, not part of the shipped avd binary.
 * Expected digests cross-checked against Python's hashlib, not
 * hand-copied from any single source. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "sha256.h"

static int PASS, FAIL;

static void check_buf(const char *label, const unsigned char *data, size_t len,
                       const char *expected) {
    struct sha256_ctx ctx;
    unsigned char digest[SHA256_DIGEST_SIZE];
    char hex[65];
    int i;

    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
    for (i = 0; i < SHA256_DIGEST_SIZE; i++)
        sprintf(hex + i * 2, "%02x", digest[i]);
    hex[64] = '\0';

    if (strcmp(hex, expected) == 0) {
        printf("  PASS: %s\n", label);
        PASS++;
    } else {
        printf("  FAIL: %s: got %s, expected %s\n", label, hex, expected);
        FAIL++;
    }
}

static void check_fd(const char *label, int fd, const char *expected) {
    char hex[65];

    if (sha256_fd(fd, hex) != 0) {
        printf("  FAIL: %s: sha256_fd() itself failed\n", label);
        FAIL++;
        return;
    }
    if (strcmp(hex, expected) == 0) {
        printf("  PASS: %s\n", label);
        PASS++;
    } else {
        printf("  FAIL: %s: got %s, expected %s\n", label, hex, expected);
        FAIL++;
    }
}

int main(void) {
    static const unsigned char two_block[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    check_buf("empty string", (const unsigned char *)"", 0,
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_buf("\"abc\"", (const unsigned char *)"abc", 3,
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_buf("two-block (56 bytes, crosses the 55/56-byte padding boundary)",
              two_block, sizeof(two_block) - 1,
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* sha256_fd() is what avd actually calls (see perform_scan() in
     * avd.c) - exercise the fd-based path too, not just the buffer
     * API the three checks above use directly. */
    {
        int fd = open("kat_abc.txt", O_RDONLY);
        if (fd >= 0) {
            check_fd("sha256_fd() on a real file (\"abc\")", fd,
                     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
            close(fd);
        } else {
            printf("  FAIL: could not open kat_abc.txt for the sha256_fd() check\n");
            FAIL++;
        }
    }

    printf("\n===================================\n");
    printf("sha256 known-answer tests: %d passed, %d failed\n", PASS, FAIL);
    printf("===================================\n");
    return FAIL ? 1 : 0;
}
EOF

printf 'abc' > "$BUILD_DIR/kat_abc.txt"

if ! cc -Wall -Wextra -O2 -I "$AVD_DIR" \
        "$BUILD_DIR/kat.c" "$AVD_DIR/sha256.c" -o "$BUILD_DIR/kat" 2>"$BUILD_DIR/build.log"; then
    echo "FAIL: could not build the sha256 known-answer test - see build log:"
    cat "$BUILD_DIR/build.log"
    exit 1
fi

(cd "$BUILD_DIR" && ./kat)
exit $?
