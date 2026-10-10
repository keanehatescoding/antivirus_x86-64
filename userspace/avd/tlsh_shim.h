/* SPDX-License-Identifier: MIT */
/*
 * tlsh_shim.h - plain-C interface to this project's own TLSH fuzzy-
 * hashing implementation (tlsh_shim.c + tlsh_core.c/tlsh_core.h). This
 * used to bridge to the system's libtlsh, whose only public API was a
 * C++ class with no extern "C" surface at all - that C++ dependency
 * (and the g++ translation unit it required) is gone: TLSH is now
 * vendored, pure C, no external library. This header's public contract
 * (the three functions below, their signatures and return codes) is
 * unchanged by that swap - avd.c does not need to change how it calls
 * these.
 *
 * This is a genuinely different integration shape than ssdeep's
 * (fuzzy.h/libfuzzy is a plain-C system library avd.c links directly,
 * no wrapper needed) - not a design inconsistency, just two different
 * histories: ssdeep's upstream ships a C API, TLSH's upstream doesn't,
 * and this project chose to vendor TLSH rather than keep carrying a
 * C++-only system dependency for it.
 */
#ifndef AV_TLSH_SHIM_H
#define AV_TLSH_SHIM_H

#include <stddef.h>

/* Returns the exact length (in hex chars, NOT including the NUL
 * terminator) that av_tlsh_hash_fd() will write on success -
 * TLSH_DIGEST_HEXLEN, a compile-time constant now that the algorithm
 * is vendored rather than linked from a system library whose exact
 * bucket/checksum configuration this project didn't control (that was
 * the old shim's reason for a deliberately oversized 200-byte
 * constant instead of an exact one - see git history). Still a
 * function rather than a raw macro so callers don't need to include
 * tlsh_core.h just to size a buffer. Callers should size their buffer
 * to at least this + 1. */
size_t av_tlsh_hash_maxlen(void);

/* Hashes the already-open file `fd`, seeking to its start first (same
 * as fuzzy_hash_file()'s own internal seek-to-start behavior, which
 * check_fuzzy_corpus() in avd.c already relies on). Unlike
 * fuzzy_hash_file(), this does NOT restore the position afterward -
 * it reads straight through to EOF (or `max_len` bytes, whichever
 * comes first) and leaves `fd` there. Callers should pass a dup()'d
 * fd, same convention as check_fuzzy_corpus(), and not rely on the
 * original fd's position afterward - remember dup()'d fds share the
 * same underlying offset, so this also leaves the fd it was dup()'d
 * from sitting wherever the read stopped. Writes the hex-encoded hash
 * into `out` (NUL-terminated).
 *
 * `max_len`: stops reading once this many bytes have been consumed,
 * hashing that prefix rather than the whole file - even if the file
 * keeps growing underneath this call (e.g. a concurrent writer), the
 * read loop can never exceed `max_len` regardless of how much more
 * data shows up. Pass SIZE_MAX for "no cap, hash the whole file" (the
 * unbounded behavior this function used to always have).
 *
 * Returns 0 on success, -1 on a read/I/O error, -2 if the file didn't
 * contain enough data for TLSH to produce a valid hash (MIN_DATA_LENGTH
 * in tlsh_core.c - 50 bytes in this port's/the system's previous
 * libtlsh's non-conservative default; short files, like short ssdeep
 * inputs, just don't fuzzy-hash meaningfully at all, this isn't a bug
 * to work around - callers should treat -2 as "no verdict from this
 * algorithm", not as an error condition worth logging), -3 if the hash
 * didn't fit in `outlen` bytes (should not happen if the caller sized
 * its buffer via av_tlsh_hash_maxlen(), but rejected outright rather
 * than silently truncated either way - a truncated hash would still
 * parse as a well-formed-looking but WRONG hash downstream, a worse
 * failure mode than an honest error here). */
int av_tlsh_hash_fd(int fd, char *out, size_t outlen, size_t max_len);

/* Compares two hex-encoded TLSH hashes and returns this project's own
 * totalDiff()-equivalent distance (tlsh_total_diff() in tlsh_core.c,
 * ported from and validated against upstream/libtlsh's totalDiff(&other,
 * true)): 0 = identical, larger = more different. This is the OPPOSITE
 * convention from ssdeep's fuzzy_compare() (0-100 similarity, higher =
 * more similar) - callers must not mix up "score >= threshold means
 * match" (ssdeep) with "diff <= threshold means match" (TLSH). Returns
 * -1 if either hash string fails to parse. */
int av_tlsh_diff(const char *hash_a, const char *hash_b);

#endif /* AV_TLSH_SHIM_H */
