/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * sigtable.h - kernel-side signature store: a mutex-protected hashtable
 * of known-bad hashes, plus a /proc interface to manage it from
 * userspace without recompiling/reloading the module.
 */

#ifndef AV_SIGTABLE_H
#define AV_SIGTABLE_H

#include <linux/types.h>

#define AV_SIG_NAME_LEN 64
#define AV_HASH_HEX_MAXLEN 64 /* longest supported: sha256 */

enum av_algo {
  AV_ALGO_MD5 = 0,
  AV_ALGO_SHA1,
  AV_ALGO_SHA256,
  AV_ALGO_COUNT,
};

/* All three digests of one file, computed together in a single read
 * pass (see hash_file_multi() in main.c). */

struct av_digest {
  /* cppcheck-suppress unusedStructMember */
  char md5[33];
  /* cppcheck-suppress unusedStructMember */
  char sha1[41];
  /* cppcheck-suppress unusedStructMember */
  char sha256[65];
};

int av_sigtable_init(void);
void av_sigtable_exit(void);

/* Creates/removes /proc/kernel_av_signatures. Call after
 * av_sigtable_init() / before av_sigtable_exit(). */
int av_sigtable_proc_init(void);
void av_sigtable_proc_exit(void);

int av_sigtable_add(enum av_algo algo, const char *hex, const char *name);
int av_sigtable_del(enum av_algo algo, const char *hex);

/* Checks all three digests in `d` against the table. On a hit, copies
 * the signature name into name_out and returns 1; returns 0 on no
 * match. Safe to call from process context (takes a mutex). */
int av_sigtable_match(const struct av_digest *d, char *name_out,
                      size_t name_out_len);

size_t av_sigtable_count(void);

/* Number of entries currently stored for one specific algo. Lets a
 * caller (main.c's hash_file_multi()) skip computing a digest that no
 * signature could ever match. Informational only, no lock - same
 * stance as av_sigtable_count(). */
size_t av_sigtable_algo_count(enum av_algo algo);

#endif /* AV_SIGTABLE_H */
