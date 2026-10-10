/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Derived from TLSH (https://github.com/trendmicro/tlsh), which upstream
 * offers under Apache-2.0 OR BSD-3-Clause; used here under BSD-3-Clause.
 *
 * Copyright (c) 2013, Trend Micro Incorporated
 * All rights reserved.
 * Copyright (c) 2026 keanehatescoding (C port)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * tlsh_core.h - from-scratch, pure-C port of upstream trendmicro/tlsh's
 * TLSH fuzzy-hashing algorithm (the actual math: Pearson-hash bucket
 * mapping, quartile-based digest packing, hex codec, totalDiff()), in
 * exactly the "default"/compact configuration upstream ships when no
 * CMake option overrides it: BUCKETS_128 (128 effective buckets),
 * CHECKSUM_1B (1-byte checksum), no "T1" version-prefix. That default
 * config is a compile-time choice in upstream (BUCKETS_256/CHECKSUM_3B
 * are picked by #define before including tlsh.h) - this port only
 * implements the one configuration this project's oracle (the system's
 * `tlsh` package, libtlsh.so.4 4.12.0) actually produces, confirmed
 * empirically: t.getHash() with no args returns a 70-hex-char, no-
 * prefix, UPPERCASE string (see tlsh_util.cpp's HexLookup - upstream's
 * own hex codec emits A-F, not a-f). BUCKETS_256 and the T1-prefixed
 * "showvers=1" variants (upstream's own default in >=5.0.0, per the
 * old shim's version-skew comment) are deliberately NOT implemented -
 * see tlsh_shim.c's header comment.
 *
 * This header is the internal digest representation + the algorithm
 * entry points; tlsh_shim.c is the thin public-contract wrapper over
 * it (av_tlsh_hash_maxlen/av_tlsh_hash_fd/av_tlsh_diff), same
 * bridge-not-scanning-logic split the old C++ shim had.
 */
#ifndef AV_TLSH_CORE_H
#define AV_TLSH_CORE_H

/* CODE_SIZE for BUCKETS_128: 128 buckets, 2 bits (quartile 0-3) each,
 * packed 4-per-byte = 32 bytes. This is EFF_BUCKETS/4 in upstream's
 * naming, hardcoded here rather than left as a #define knob because
 * this port only ever targets the one (128-bucket) configuration. */
#define TLSH_CODE_SIZE 32

/* 1 checksum byte + 1 Lvalue byte + 1 Q-ratio byte + 32 body bytes =
 * 35 raw bytes = 70 hex chars. No "+1" here - this is the digest
 * length, not a buffer size; callers NUL-terminate separately. */
#define TLSH_DIGEST_HEXLEN 70

/* Internal digest representation. Deliberately NOT the on-the-wire hex
 * byte layout: upstream reverses tmp_code and nibble-swaps
 * checksum/Lvalue/Q before hex-encoding (see tlsh_to_hex()'s comment
 * for why that reversal must be replicated bit-for-bit to get matching
 * strings) - keeping this struct in the more natural/internal order
 * means totalDiff() (which operates on this struct directly, same as
 * upstream's TlshImpl::totalDiff working on the pre-serialization
 * lsh_bin) never has to think about that swap at all. */
typedef struct {
    unsigned char checksum;              /* TLSH_CHECKSUM_LEN=1 */
    unsigned char Lvalue;                /* length bucket, see l_capturing() */
    unsigned char Q1ratio;               /* 0-15 */
    unsigned char Q2ratio;               /* 0-15 */
    unsigned char tmp_code[TLSH_CODE_SIZE];
} tlsh_digest;

/* Streaming hash state - mirrors upstream TlshImpl's update()-then-
 * final() shape, which tlsh_shim.c's fd-reading loop depends on. */
typedef struct {
    unsigned int *a_bucket;      /* lazily calloc'd, 256 counters (see
                                   * tlsh_core.c: Pearson hash output is a
                                   * full byte 0-255, even though only
                                   * buckets 0-127 feed the digest) */
    unsigned char slide_window[5];   /* SLIDING_WND_SIZE=5 */
    unsigned int data_len;
    unsigned char checksum;
    /* Sticky, not just "a_bucket is NULL": a calloc() failure in one
     * tlsh_update() call must permanently invalidate this ctx, even if
     * a LATER call's calloc happens to succeed (transient OOM clearing
     * up) - otherwise that later call would silently start a fresh
     * bucket array and hash only the chunks fed in after the failure,
     * and tlsh_final() would hand back a normal-looking digest for
     * what's actually incomplete input. Checked before a_bucket's own
     * NULL-ness in both tlsh_update() and tlsh_final(). */
    int alloc_failed;
} tlsh_ctx;

void tlsh_init(tlsh_ctx *ctx);
void tlsh_update(tlsh_ctx *ctx, const unsigned char *data, unsigned int len);

/* Finalizes the digest. Returns 0 on success (out filled), -1 if the
 * data was too short/insufficiently diverse for a valid hash (mirrors
 * upstream TlshImpl::final()'s several silent-invalidation paths -
 * short input, degenerate quartiles, too many empty buckets - all
 * folded into one "invalid" outcome here, same as upstream's own empty-
 * string signal that the old C++ shim relied on). Frees ctx's internal
 * bucket array either way; ctx must not be updated again afterward. */
int tlsh_final(tlsh_ctx *ctx, tlsh_digest *out);

/* Releases ctx's internal state without finalizing - for early-exit
 * error paths (e.g. a read() failure mid-stream) that never call
 * tlsh_final(). Safe to call on a zero-initialized or already-freed ctx. */
void tlsh_free(tlsh_ctx *ctx);

/* Encodes to uppercase hex (matches upstream's own HexLookup table -
 * this is not a stylistic choice, it's what makes digests byte-for-
 * byte comparable against hashes produced by real libtlsh or stored in
 * corpus files generated by it). buf must hold at least
 * TLSH_DIGEST_HEXLEN+1 bytes; NUL-terminates. */
void tlsh_to_hex(const tlsh_digest *d, char *buf);

/* Parses exactly TLSH_DIGEST_HEXLEN hex chars (case-insensitive, no
 * "T1" prefix accepted - see this file's top comment) into *out.
 * Returns 0 on success, -1 if str isn't a well-formed digest of the
 * expected length. */
int tlsh_from_hex(const char *str, tlsh_digest *out);

/* Upstream's totalDiff(&other, true) - the "true" means Lvalue
 * (length) is included in the distance, which is upstream's own
 * default and what the old C++ shim always passed. This project has no
 * use case (unlike upstream's own -force/-conservative CLI options)
 * for excluding length from the comparison, so len_diff is not exposed
 * as a parameter here - always compute the length-inclusive form the
 * rest of this codebase (and any stored corpus hashes) expects. */
int tlsh_total_diff(const tlsh_digest *a, const tlsh_digest *b);

#endif /* AV_TLSH_CORE_H */
