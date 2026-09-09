/*
 * sha256.h - minimal self-contained SHA-256 (FIPS 180-4). Used only to
 * fill in a hash for on-demand scans (avctl scan / GUI-triggered),
 * which - unlike kernel-initiated scans - have no netlink-precomputed
 * SHA-256 to reuse (see AV_A_SHA256 in av/netlink_proto.h). Deliberately
 * not linking libcrypto for this one hash - matches the project's
 * stated minimal-dependency stance (see the top-level README).
 */

#ifndef AVD_SHA256_H
#define AVD_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32

/* Cap on how much sha256_fd() will hash. The fuzzy/TLSH pass already stops
 * at MAX_FUZZY_TLSH_FILE_SIZE (avd.c) - same 256MB value as the kernel
 * side's MAX_HASH_FILE_SIZE - while this streamed the whole file with no
 * bound, so one very large file tied up a scan worker for the full read.
 * Oversize input returns -1 and callers proceed without a hash (their
 * existing fail-open stance), exactly like any other hashing I/O error. */
#define SHA256_FD_MAX_BYTES (256 * 1024 * 1024)

struct sha256_ctx {
  uint32_t state[8];
  uint64_t bitlen;
  unsigned char buffer[64];
  size_t buflen;
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const unsigned char *data, size_t len);
void sha256_final(struct sha256_ctx *ctx, unsigned char digest[SHA256_DIGEST_SIZE]);

/*
 * Hashes the file referenced by `fd` and writes the lowercase hex
 * digest (64 chars + NUL) into hex_out, which must be at least 65
 * bytes. Hashes through a dup()'d handle seeked to the start - same
 * convention as check_fuzzy_corpus()/check_tlsh_corpus() in avd.c - so
 * this never disturbs `fd`'s own read offset. Returns 0 on success, -1
 * on any I/O error.
 */
int sha256_fd(int fd, char hex_out[65]);

#endif /* AVD_SHA256_H */
