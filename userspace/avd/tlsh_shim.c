/* SPDX-License-Identifier: MIT */
/*
 * tlsh_shim.c - the plain-C, in-tree implementation of TLSH fuzzy
 * hashing. This used to be tlsh_shim.cpp, a thin C++ bridge to the
 * system's libtlsh (whose only public API is a C++ class, see git
 * history / the old comments this replaced). That dependency is gone:
 * the actual algorithm now lives in tlsh_core.c/tlsh_core.h, a
 * from-scratch pure-C port of upstream trendmicro/tlsh's default
 * BUCKETS_128/CHECKSUM_1B configuration, validated byte-for-byte
 * against the system's real libtlsh.so.4 before this replaced it (see
 * tlsh_core.h's top comment for exactly which config this is and
 * isn't). This file is now just the same kind of tiny public-contract
 * wrapper it always was - streaming a file descriptor through
 * update()/final(), and translating results into this project's
 * 0/-1/-2/-3 return-code convention - it just no longer needs a
 * separate translation unit or compiler to do it.
 *
 * NOT ported: BUCKETS_256 (256-bucket digests), CHECKSUM_3B (3-byte
 * checksums), and the "T1"-prefixed version-tagged digest format
 * (upstream's own default in library >=5.0.0, but NOT what the
 * system's installed 4.12.0 produces - confirmed empirically, see
 * tlsh_core.h). If this project's oracle libtlsh package is ever
 * upgraded to one that changes its default output format, this file's
 * hardcoded TLSH_DIGEST_HEXLEN-sized, unprefixed, uppercase-hex
 * contract would need re-validating against it.
 */
#include "tlsh_shim.h"
#include "tlsh_core.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

size_t av_tlsh_hash_maxlen(void) {
  return TLSH_DIGEST_HEXLEN;
}

int av_tlsh_hash_fd(int fd, char *out, size_t outlen, size_t max_len) {
  tlsh_ctx ctx;
  tlsh_digest digest;
  unsigned char buf[65536];
  size_t total = 0;
  ssize_t n;
  int any_data = 0;

  if (lseek(fd, 0, SEEK_SET) < 0)
    return -1;

  tlsh_init(&ctx);

  while (total < max_len) {
    size_t want = sizeof(buf);

    /* Never ask read() for more than the remaining budget - avoids
     * reading (and hashing) even one byte past max_len when the
     * remainder is smaller than the buffer. */
    if (max_len - total < want)
      want = max_len - total;

    n = read(fd, buf, want);
    if (n == 0)
      break;
    if (n < 0) {
      /* avd installs signal handlers - a signal landing mid-read can
       * return -1/EINTR with nothing actually wrong, and the syscall
       * just needs retrying, not treating as a real I/O error. */
      if (errno == EINTR)
        continue;
      /* tlsh_update() may have calloc'd ctx.a_bucket already - free it
       * rather than leaking on this error path. */
      tlsh_free(&ctx);
      return -1;
    }
    tlsh_update(&ctx, buf, (unsigned int)n);
    total += (size_t)n;
    any_data = 1;
  }
  if (!any_data) {
    /* ctx.a_bucket is still NULL here (tlsh_update() was never
     * called), so tlsh_free() is a no-op, but call it anyway rather
     * than special-casing the empty-file path - one less thing to get
     * out of sync if tlsh_ctx's fields ever change. */
    tlsh_free(&ctx);
    return -2;
  }

  /* -2 covers every way tlsh_final() can decide the input didn't
   * produce a valid hash (too short, degenerate quartiles, too few
   * non-empty buckets - see tlsh_core.c) - same "no verdict from this
   * algorithm, not an error" treatment the old libtlsh-backed shim
   * gave its MIN_DATA_LENGTH cutoff. */
  if (tlsh_final(&ctx, &digest) != 0)
    return -2;

  /* Reject rather than silently truncate if the hash somehow doesn't
   * fit - this can't actually happen now (the digest length is a
   * compile-time constant, TLSH_DIGEST_HEXLEN, not a runtime library
   * property this project doesn't control), but av_tlsh_hash_maxlen()
   * is a *contract*, not just today's observed value - checking it
   * here is defense in depth against outlen ever being sized wrong by
   * a future caller. */
  if (TLSH_DIGEST_HEXLEN >= outlen)
    return -3;

  tlsh_to_hex(&digest, out);
  return 0;
}

int av_tlsh_diff(const char *hash_a, const char *hash_b) {
  tlsh_digest a, b;

  if (tlsh_from_hex(hash_a, &a) != 0)
    return -1;
  if (tlsh_from_hex(hash_b, &b) != 0)
    return -1;

  return tlsh_total_diff(&a, &b);
}
