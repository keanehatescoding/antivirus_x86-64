/*
 * sha256.c - minimal self-contained SHA-256 (FIPS 180-4). See sha256.h
 * for why this exists instead of linking libcrypto. Implemented
 * directly against the published FIPS 180-4 spec - no external
 * reference implementation copied.
 */

#include "sha256.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_transform(struct sha256_ctx *ctx, const unsigned char block[64]) {
  uint32_t w[64];
  uint32_t a, b, c, d, e, f, g, h;
  int i;

  for (i = 0; i < 16; i++)
    w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
           ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];

  for (i = 16; i < 64; i++) {
    uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; i++) {
    uint32_t s1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t temp1 = h + s1 + ch + k[i] + w[i];
    uint32_t s0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void sha256_init(struct sha256_ctx *ctx) {
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->bitlen = 0;
  ctx->buflen = 0;
}

void sha256_update(struct sha256_ctx *ctx, const unsigned char *data, size_t len) {
  size_t i = 0;

  while (i < len) {
    size_t take = 64 - ctx->buflen;
    if (take > len - i)
      take = len - i;
    memcpy(ctx->buffer + ctx->buflen, data + i, take);
    ctx->buflen += take;
    i += take;
    ctx->bitlen += (uint64_t)take * 8;

    if (ctx->buflen == 64) {
      sha256_transform(ctx, ctx->buffer);
      ctx->buflen = 0;
    }
  }
}

void sha256_final(struct sha256_ctx *ctx, unsigned char digest[SHA256_DIGEST_SIZE]) {
  uint64_t bitlen = ctx->bitlen; /* save before the padding bytes below
                                  * feed back through sha256_update()
                                  * and inflate ctx->bitlen further */
  unsigned char pad = 0x80;
  unsigned char zero = 0x00;
  int i;

  sha256_update(ctx, &pad, 1);
  while (ctx->buflen != 56)
    sha256_update(ctx, &zero, 1);

  {
    unsigned char lenbytes[8];

    for (i = 0; i < 8; i++)
      lenbytes[i] = (unsigned char)(bitlen >> (56 - 8 * i));
    /* Bypass sha256_update() for the length field - it would fold
     * this 8-byte write into ctx->bitlen too, double-counting the
     * message length. ctx->buflen is guaranteed exactly 56 here (the
     * padding loop above's exit condition), so this appends directly
     * into the last 8 bytes of the final block and transforms it. */
    memcpy(ctx->buffer + 56, lenbytes, 8);
    sha256_transform(ctx, ctx->buffer);
  }

  for (i = 0; i < 8; i++) {
    digest[i * 4] = (unsigned char)(ctx->state[i] >> 24);
    digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
    digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
    digest[i * 4 + 3] = (unsigned char)(ctx->state[i]);
  }
}

int sha256_fd(int fd, char hex_out[65]) {
  static const char hexchars[] = "0123456789abcdef";
  struct sha256_ctx ctx;
  unsigned char buf[65536];
  unsigned char digest[SHA256_DIGEST_SIZE];
  int dup_fd;
  FILE *fp;
  size_t n;
  uint64_t total = 0;
  int i;

  /* Reject-only early gate: avoids reading 256MB just to fail, mirroring
   * fuzzy_tlsh_size_ok()'s role for the fuzzy/TLSH pass in avd.c. Fails
   * open (returns -1, caller proceeds without a hash) on fstat() failure
   * too - a stat error alone must not disable hashing for normal files,
   * same stance as that gate. The bounded loop below remains the real
   * guard against a file that grows past the cap between here and the
   * read. */
  {
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        (uint64_t)st.st_size > (uint64_t)SHA256_FD_MAX_BYTES) {
      fprintf(stderr,
              "sha256: skipping hash - file is %lld bytes, over the %d cap\n",
              (long long)st.st_size, SHA256_FD_MAX_BYTES);
      return -1;
    }
  }

  dup_fd = dup(fd);
  if (dup_fd < 0)
    return -1;

  fp = fdopen(dup_fd, "rb");
  if (!fp) {
    close(dup_fd);
    return -1;
  }

  if (fseek(fp, 0, SEEK_SET) != 0) {
    fclose(fp);
    return -1;
  }

  sha256_init(&ctx);
  /* Bounded like check_fuzzy_corpus()'s read-to-EOF-or-cap loop: a file
   * that grows concurrently past the fstat gate above still stops here
   * instead of hashing unboundedly on a worker thread. Oversize is -1,
   * same as any I/O error - perform_scan() already fails open to
   * hash="" on exactly this return. */
  while (total <= (uint64_t)SHA256_FD_MAX_BYTES &&
         (n = fread(buf, 1, sizeof(buf), fp)) > 0) {
    total += (uint64_t)n;
    if (total > (uint64_t)SHA256_FD_MAX_BYTES) {
      fprintf(stderr, "sha256: file grew past the %d cap during hashing\n",
              SHA256_FD_MAX_BYTES);
      fclose(fp);
      return -1;
    }
    sha256_update(&ctx, buf, n);
  }

  if (ferror(fp)) {
    fclose(fp);
    return -1;
  }
  fclose(fp); /* also closes dup_fd */

  sha256_final(&ctx, digest);

  for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
    hex_out[i * 2] = hexchars[digest[i] >> 4];
    hex_out[i * 2 + 1] = hexchars[digest[i] & 0xf];
  }
  hex_out[64] = '\0';

  return 0;
}
