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
 * tlsh_core.c - pure-C port of the TLSH algorithm itself (BUCKETS_128 /
 * CHECKSUM_1B / no version prefix - see tlsh_core.h). Ported line-by-
 * line from upstream trendmicro/tlsh's src/tlsh_impl.cpp and
 * src/tlsh_util.cpp, not reconstructed from the paper/memory - the
 * exact constants below (the Pearson salts, the length-capture
 * breakpoints, the diff-scoring multipliers) are load-bearing for hash
 * compatibility, and were checked against upstream source rather than
 * guessed. Validated byte-for-byte against the system's real
 * libtlsh.so.4 (4.12.0) across a range of file sizes/contents before
 * this replaced the C++ shim - see the task's validation notes.
 *
 * Two upstream update() code paths (the generic SLIDING_WND_SIZE loop
 * vs. the 5x-unrolled "fast_update5" upstream actually calls for our
 * exact config) are mathematically identical - verified term-by-term
 * against tlsh_impl.cpp's raw_fast_update5(). This port implements only
 * the generic loop: same output, simpler to read and audit, and this
 * isn't upstream's SIMD-tuned hot path so there's no perf reason to
 * carry the unrolled version too.
 */
#include "tlsh_core.h"

#include <stdlib.h>
#include <string.h>

#define BUCKET_COUNT 256   /* Pearson hash output range - see below */
#define EFF_BUCKETS  128   /* buckets actually used in the digest (BUCKETS_128) */
#define SLIDING_WND_SIZE 5
#define MIN_DATA_LENGTH 50   /* non-conservative default (fc_cons_option=0),
                               * matches libtlsh 4.12.0's #define - the old
                               * shim's version-skew comment notes 3.4.4 used
                               * 256 here, but this project only builds
                               * against/validates the current (4.12.0)
                               * behavior, same as before. */

/* Pearson's sample random permutation table, copied verbatim from
 * upstream tlsh_impl.cpp's v_table[256] - this is what makes bucket
 * assignment and the checksum reproducible byte-for-byte against real
 * TLSH; any transcription error here would silently produce
 * plausible-looking but wrong hashes for every input, not a crash. */
static const unsigned char v_table[256] = {
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
    14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
    110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
    25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
    97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
    174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
    132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
    119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
    138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
    125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
    118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
    27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
    233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
    140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209
};

/* fast_b_mapping(ms,i,j,k) == b_mapping(salt,i,j,k) where
 * ms == v_table[salt] - upstream precomputes that first lookup into a
 * literal constant at each call site (see tlsh_impl.cpp's update(),
 * e.g. "fast_b_mapping(49, ...)" annotated "b_mapping(2, ...)" since
 * v_table[2]=49) rather than doing it at runtime. This port keeps the
 * same precomputed literals for the same reason: they're upstream's
 * own values, not independently derived, so reusing them verbatim is
 * both faster and removes a chance to get the salt mapping wrong. */
static inline unsigned char fast_b_mapping(unsigned char ms, unsigned char i,
                                            unsigned char j, unsigned char k)
{
    return v_table[v_table[v_table[ms ^ i] ^ j] ^ k];
}

/* topval[] and l_capturing(): upstream replaced a log()-based length
 * bucketing (see the commented-out float version in tlsh_util.cpp)
 * with this binary-searched lookup table specifically so the digest is
 * reproducible across platforms/libm implementations without relying
 * on floating-point transcendental functions matching bit-for-bit -
 * the exact breakpoints are load-bearing, not tunable. idx 0 is
 * reserved/unreachable in practice (topval[0]=1 covers len<=1) and the
 * search starts at the middle (85) of the 170-entry table. */
static const unsigned int topval[170] = {
    1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656,
    854, 1110, 1443, 1876, 2439, 3171, 3475, 3823, 4205, 4626, 5088, 5597,
    6157, 6772, 7450, 8195, 9014, 9916, 10907, 11998, 13198, 14518, 15970,
    17567, 19323, 21256, 23382, 25720, 28292, 31121, 34233, 37656, 41422,
    45564, 50121, 55133, 60646, 66711, 73382, 80721, 88793, 97672, 107439,
    118183, 130002, 143002, 157302, 173032, 190335, 209369, 230306, 253337,
    278670, 306538, 337191, 370911, 408002, 448802, 493682, 543050, 597356,
    657091, 722800, 795081, 874589, 962048, 1058252, 1164078, 1280486,
    1408534, 1549388, 1704327, 1874759, 2062236, 2268459, 2495305, 2744836,
    3019320, 3321252, 3653374, 4018711, 4420582, 4862641, 5348905, 5883796,
    6472176, 7119394, 7831333, 8614467, 9475909, 10423501, 11465851,
    12612437, 13873681, 15261050, 16787154, 18465870, 20312458, 22343706,
    24578077, 27035886, 29739474, 32713425, 35984770, 39583245, 43541573,
    47895730, 52685306, 57953837, 63749221, 70124148, 77136564, 84850228,
    93335252, 102668779, 112935659, 124229227, 136652151, 150317384,
    165349128, 181884040, 200072456, 220079703, 242087671, 266296456,
    292926096, 322218735, 354440623, 389884688, 428873168, 471760495,
    518936559, 570830240, 627913311, 690704607, 759775136, 835752671,
    919327967, 1011260767, 1112386880, 1223623232, 1345985727, 1480584256,
    1628642751, 1791507135, 1970657856, 2167723648, 2384496256, 2622945920,
    2885240448, 3173764736, 3491141248, 3840255616, 4224281216
};

static unsigned char l_capturing(unsigned int len)
{
    int bottom = 0;
    int top = 170;
    int idx = 85;

    /* Without this, len > topval[169] (~3.9GB+) makes the bisection
     * below converge on idx==170 - one past the last valid index of a
     * 170-entry (0..169) table, an out-of-bounds read. Traced by hand:
     * every iteration takes the "bottom = idx + 1" branch since len
     * never satisfies len < topval[idx], which walks bottom up to 170
     * with top pinned at its initial value the whole time. Saturating
     * at the top bucket for anything beyond the table's range is the
     * only sane behavior anyway - there's no finer length distinction
     * left to make. */
    if (len > topval[169])
        return 169;

    for (;;) {
        if (idx == 0)
            return (unsigned char)idx;
        if (len <= topval[idx] && len > topval[idx - 1])
            return (unsigned char)idx;
        if (len < topval[idx])
            top = idx - 1;
        else
            bottom = idx + 1;
        idx = (bottom + top) / 2;
    }
}

static int mod_diff(unsigned int x, unsigned int y, unsigned int r)
{
    int dl, dr;

    if (y > x) {
        dl = (int)(y - x);
        dr = (int)(x + r - y);
    } else {
        dl = (int)(x - y);
        dr = (int)(y + r - x);
    }
    return dl > dr ? dr : dl;
}

/* bit_pairs_diff_table[256][256]: precomputed pairwise distance between
 * two quartile-packed bytes, upstream-generated (gen_arr2.cpp) and
 * copied verbatim - see tlsh_diff_table.h's own header comment. */
#include "tlsh_diff_table.h"

static int h_distance(const unsigned char *x, const unsigned char *y, int len)
{
    int diff = 0;
    int i;

    for (i = 0; i < len; i++)
        diff += bit_pairs_diff_table[x[i]][y[i]];
    return diff;
}

static unsigned char swap_byte(unsigned char in)
{
    return (unsigned char)(((in & 0xF0) >> 4) | ((in & 0x0F) << 4));
}

/* ---------------------------------------------------------------- */

void tlsh_init(tlsh_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void tlsh_free(tlsh_ctx *ctx)
{
    free(ctx->a_bucket);
    ctx->a_bucket = NULL;
}

void tlsh_update(tlsh_ctx *ctx, const unsigned char *data, unsigned int len)
{
    unsigned int fed_len = ctx->data_len;
    unsigned int i;
    int j;

    /* Sticky: once one call's calloc() has failed, every later call is
     * a no-op, even if THIS call's calloc would succeed - see
     * tlsh_core.h's comment on alloc_failed for why a later success
     * must not be allowed to quietly resume hashing from a fresh
     * bucket array, which would hash only the tail of the stream and
     * still finalize into a normal-looking (but wrong) digest. */
    if (ctx->alloc_failed)
        return;

    /* Lazily allocated like upstream's a_bucket - a file that never
     * gets update()'d at all (empty input) never touches this, and
     * av_tlsh_hash_fd() already treats zero-byte reads as -2 before
     * ever calling update(), so this isn't reachable with len==0 in
     * practice, but calloc'ing on first real call rather than in
     * tlsh_init() mirrors upstream's own lazy-alloc shape. */
    if (ctx->a_bucket == NULL) {
        /* 256, not EFF_BUCKETS(128): fast_b_mapping's output is a full
         * Pearson byte (0-255), and only indices 0..127 end up read
         * back out in tlsh_final()/find_quartile() - see this file's
         * top comment. Under-allocating to 128 would be an
         * out-of-bounds write on every other bucket hit. */
        ctx->a_bucket = calloc(BUCKET_COUNT, sizeof(unsigned int));
        if (ctx->a_bucket == NULL) {
            /* OOM: bail before the unconditional a_bucket[r]++ writes
             * below would dereference NULL, and latch alloc_failed so
             * no later call can paper over this one's missing data by
             * successfully allocating a fresh array instead. */
            ctx->alloc_failed = 1;
            return;
        }
    }

    j = (int)(ctx->data_len % SLIDING_WND_SIZE);
    for (i = 0; i < len; i++, fed_len++, j = (j + 1) % SLIDING_WND_SIZE) {
        ctx->slide_window[j] = data[i];

        if (fed_len >= SLIDING_WND_SIZE - 1) {
            int j1 = (j + SLIDING_WND_SIZE - 1) % SLIDING_WND_SIZE;
            int j2 = (j + SLIDING_WND_SIZE - 2) % SLIDING_WND_SIZE;
            int j3 = (j + SLIDING_WND_SIZE - 3) % SLIDING_WND_SIZE;
            int j4 = (j + SLIDING_WND_SIZE - 4) % SLIDING_WND_SIZE;
            unsigned char *sw = ctx->slide_window;
            unsigned char r;

            /* checksum: salt 1 == v_table[0], i.e. b_mapping(0, cur, prev, checksum) */
            ctx->checksum = fast_b_mapping(1, sw[j], sw[j1], ctx->checksum);

            /* Six bucket hits per byte (salts 49/12/178/166/84/230 ==
             * v_table[2]/[3]/[5]/[7]/[11]/[13], i.e. b_mapping salts
             * 2,3,5,7,11,13) over the 5-byte sliding window's
             * pairs-with-current-byte - this specific set of
             * (offset pairs, salts) is upstream's chosen digest
             * construction, not derivable from first principles. */
            r = fast_b_mapping(49,  sw[j], sw[j1], sw[j2]); ctx->a_bucket[r]++;
            r = fast_b_mapping(12,  sw[j], sw[j1], sw[j3]); ctx->a_bucket[r]++;
            r = fast_b_mapping(178, sw[j], sw[j2], sw[j3]); ctx->a_bucket[r]++;
            r = fast_b_mapping(166, sw[j], sw[j2], sw[j4]); ctx->a_bucket[r]++;
            r = fast_b_mapping(84,  sw[j], sw[j1], sw[j4]); ctx->a_bucket[r]++;
            r = fast_b_mapping(230, sw[j], sw[j3], sw[j4]); ctx->a_bucket[r]++;
        }
    }
    ctx->data_len += len;
}

/* Quickselect-based quartile finder, ported from upstream's
 * find_quartile()/partition() - only reads/reorders the first
 * EFF_BUCKETS(128) of the 256-slot bucket array, matching
 * tlsh_final()'s own use of only those buckets. Kept as an in-place
 * partition on a scratch copy so a_bucket itself is left untouched
 * (upstream does the same, via bucket_copy[]). */
static unsigned int partition(unsigned int *buf, unsigned int left, unsigned int right)
{
    unsigned int ret, pivot, val, i;

    if (left == right)
        return left;
    if (left + 1 == right) {
        if (buf[left] > buf[right]) {
            unsigned int t = buf[left]; buf[left] = buf[right]; buf[right] = t;
        }
        return left;
    }

    ret = left;
    pivot = (left + right) >> 1;
    val = buf[pivot];
    buf[pivot] = buf[right];
    buf[right] = val;

    for (i = left; i < right; i++) {
        if (buf[i] < val) {
            unsigned int t = buf[ret]; buf[ret] = buf[i]; buf[i] = t;
            ret++;
        }
    }
    buf[right] = buf[ret];
    buf[ret] = val;
    return ret;
}

static void find_quartile(unsigned int *q1, unsigned int *q2, unsigned int *q3,
                           const unsigned int *a_bucket)
{
    unsigned int bucket_copy[EFF_BUCKETS];
    unsigned int short_cut_left[EFF_BUCKETS], short_cut_right[EFF_BUCKETS];
    unsigned int spl = 0, spr = 0;
    unsigned int p1 = EFF_BUCKETS / 4 - 1;
    unsigned int p2 = EFF_BUCKETS / 2 - 1;
    unsigned int p3 = EFF_BUCKETS - EFF_BUCKETS / 4 - 1;
    unsigned int end = EFF_BUCKETS - 1;
    unsigned int l, r, i;

    for (i = 0; i <= end; i++)
        bucket_copy[i] = a_bucket[i];

    for (l = 0, r = end; ; ) {
        unsigned int ret = partition(bucket_copy, l, r);
        if (ret > p2) {
            r = ret - 1;
            short_cut_right[spr++] = ret;
        } else if (ret < p2) {
            l = ret + 1;
            short_cut_left[spl++] = ret;
        } else {
            *q2 = bucket_copy[p2];
            break;
        }
    }

    short_cut_left[spl] = p2 - 1;
    short_cut_right[spr] = p2 + 1;

    for (i = 0, l = 0; i <= spl; i++) {
        r = short_cut_left[i];
        if (r > p1) {
            for (;;) {
                unsigned int ret = partition(bucket_copy, l, r);
                if (ret > p1) {
                    r = ret - 1;
                } else if (ret < p1) {
                    l = ret + 1;
                } else {
                    *q1 = bucket_copy[p1];
                    break;
                }
            }
            break;
        } else if (r < p1) {
            l = r;
        } else {
            *q1 = bucket_copy[p1];
            break;
        }
    }

    for (i = 0, r = end; i <= spr; i++) {
        l = short_cut_right[i];
        if (l < p3) {
            for (;;) {
                unsigned int ret = partition(bucket_copy, l, r);
                if (ret > p3) {
                    r = ret - 1;
                } else if (ret < p3) {
                    l = ret + 1;
                } else {
                    *q3 = bucket_copy[p3];
                    break;
                }
            }
            break;
        } else if (l > p3) {
            r = l;
        } else {
            *q3 = bucket_copy[p3];
            break;
        }
    }
}

int tlsh_final(tlsh_ctx *ctx, tlsh_digest *out)
{
    unsigned int q1, q2, q3;
    int nonzero;
    unsigned int i, j;

    /* alloc_failed checked separately from (and before) a_bucket==NULL:
     * a failed call latches alloc_failed but a LATER call could still
     * have gone on to allocate successfully (see tlsh_update()), which
     * would make a_bucket non-NULL again despite the gap in what
     * actually got hashed - alloc_failed is the one thing that stays
     * true regardless. MIN_DATA_LENGTH cutoff below is the unrelated
     * "too short to mean anything, not an error" case - same rationale
     * as the old shim's -2 return documented - preserved here as the
     * same early "invalid" outcome. */
    if (ctx->alloc_failed || ctx->data_len < MIN_DATA_LENGTH || ctx->a_bucket == NULL) {
        tlsh_free(ctx);
        return -1;
    }

    find_quartile(&q1, &q2, &q3, ctx->a_bucket);

    /* q3==0 would divide-by-zero below (Q1/Q2 ratio computation) -
     * upstream's own issue #79 fix, preserved verbatim. Degenerate
     * (near-empty/uniform) input can genuinely hit this. */
    if (q3 == 0) {
        tlsh_free(ctx);
        return -1;
    }

    /* Buckets must be more than 50% non-zero, or the digest would be
     * mostly noise from too little input diversity - upstream's own
     * validity heuristic, not something this port relaxes. */
    nonzero = 0;
    for (i = 0; i < TLSH_CODE_SIZE; i++)
        for (j = 0; j < 4; j++)
            if (ctx->a_bucket[4 * i + j] > 0)
                nonzero++;
    if (nonzero <= 4 * (int)TLSH_CODE_SIZE / 2) {
        tlsh_free(ctx);
        return -1;
    }

    for (i = 0; i < TLSH_CODE_SIZE; i++) {
        unsigned char h = 0;
        for (j = 0; j < 4; j++) {
            unsigned int k = ctx->a_bucket[4 * i + j];
            if (q3 < k)
                h += (unsigned char)(3 << (j * 2));
            else if (q2 < k)
                h += (unsigned char)(2 << (j * 2));
            else if (q1 < k)
                h += (unsigned char)(1 << (j * 2));
        }
        out->tmp_code[i] = h;
    }

    out->checksum = ctx->checksum;
    out->Lvalue = l_capturing(ctx->data_len);
    /* Bitfield packing note (see tlsh_core.h): Q1ratio/Q2ratio are
     * stored as separate fields here, not packed into one byte, until
     * tlsh_to_hex() packs them for serialization - avoids depending on
     * this compiler's/platform's bitfield bit-order at all internally. */
    out->Q1ratio = (unsigned char)(((unsigned long long)q1 * 100 / q3) % 16);
    out->Q2ratio = (unsigned char)(((unsigned long long)q2 * 100 / q3) % 16);

    tlsh_free(ctx);
    return 0;
}

/* ---------------------------------------------------------------- */

static const char hex_upper[] = "0123456789ABCDEF";

void tlsh_to_hex(const tlsh_digest *d, char *buf)
{
    /* Upstream's lsh_bin_hash() nibble-swaps checksum/Lvalue/Q and
     * reverses tmp_code before hex-encoding (see tlsh_impl.cpp) - a
     * historical serialization-order choice baked into every TLSH
     * digest ever produced, not optional. Skipping it would still
     * produce a self-consistent 70-hex-char string (round-trips fine
     * through this port's own tlsh_from_hex()), but it would NOT match
     * real libtlsh's output for the same input - replicated bit-for-
     * bit here rather than "simplified", since compatibility with
     * upstream's actual byte layout is the entire point of this port. */
    unsigned char raw[3 + TLSH_CODE_SIZE];
    unsigned int i;
    char *p = buf;

    raw[0] = swap_byte(d->checksum);
    raw[1] = swap_byte(d->Lvalue);
    raw[2] = swap_byte((unsigned char)(d->Q1ratio | (d->Q2ratio << 4)));
    for (i = 0; i < TLSH_CODE_SIZE; i++)
        raw[3 + i] = d->tmp_code[TLSH_CODE_SIZE - 1 - i];

    for (i = 0; i < sizeof(raw); i++) {
        *p++ = hex_upper[raw[i] >> 4];
        *p++ = hex_upper[raw[i] & 0x0F];
    }
    *p = '\0';
}

static int hex_nibble(char c, unsigned char *v)
{
    if (c >= '0' && c <= '9') { *v = (unsigned char)(c - '0'); return 0; }
    if (c >= 'A' && c <= 'F') { *v = (unsigned char)(c - 'A' + 10); return 0; }
    if (c >= 'a' && c <= 'f') { *v = (unsigned char)(c - 'a' + 10); return 0; }
    return -1;
}

int tlsh_from_hex(const char *str, tlsh_digest *out)
{
    unsigned char raw[3 + TLSH_CODE_SIZE];
    unsigned int i;
    size_t len = strlen(str);

    /* No "T1" prefix accepted - this port's digests never have one
     * (see tlsh_core.h), and silently stripping a prefix here would
     * make av_tlsh_diff() appear to accept hashes this project never
     * produces, masking a real format mismatch instead of rejecting
     * it. */
    if (len != TLSH_DIGEST_HEXLEN)
        return -1;

    for (i = 0; i < sizeof(raw); i++) {
        unsigned char hi, lo;
        if (hex_nibble(str[2 * i], &hi) != 0 || hex_nibble(str[2 * i + 1], &lo) != 0)
            return -1;
        raw[i] = (unsigned char)((hi << 4) | lo);
    }

    /* Inverse of tlsh_to_hex()'s swap+reverse. */
    out->checksum = swap_byte(raw[0]);
    out->Lvalue = swap_byte(raw[1]);
    {
        unsigned char qb = swap_byte(raw[2]);
        out->Q1ratio = (unsigned char)(qb & 0x0F);
        out->Q2ratio = (unsigned char)((qb >> 4) & 0x0F);
    }
    for (i = 0; i < TLSH_CODE_SIZE; i++)
        out->tmp_code[i] = raw[3 + (TLSH_CODE_SIZE - 1 - i)];

    return 0;
}

/* ---------------------------------------------------------------- */

#define RANGE_LVALUE 256
#define RANGE_QRATIO 16
/* Default distance-scoring multipliers - upstream only exposes these
 * as tunable when built with TLSH_DISTANCE_PARAMETERS (a debug/
 * research knob, off by default and not something any distro package
 * enables); the shipped default for both is 12, hardcoded here to
 * match what every real-world libtlsh build (including this project's
 * oracle) actually uses. */
#define LENGTH_MULT 12
#define QRATIO_MULT 12

int tlsh_total_diff(const tlsh_digest *a, const tlsh_digest *b)
{
    int diff = 0;
    int ldiff, q1diff, q2diff;

    /* len_diff=true (upstream's own default, and what the old C++
     * shim always passed) - see tlsh_core.h's comment on why this
     * isn't a parameter here. */
    ldiff = mod_diff(a->Lvalue, b->Lvalue, RANGE_LVALUE);
    if (ldiff == 0)
        diff = 0;
    else if (ldiff == 1)
        diff = 1;
    else
        diff += ldiff * LENGTH_MULT;

    q1diff = mod_diff(a->Q1ratio, b->Q1ratio, RANGE_QRATIO);
    diff += (q1diff <= 1) ? q1diff : (q1diff - 1) * QRATIO_MULT;

    q2diff = mod_diff(a->Q2ratio, b->Q2ratio, RANGE_QRATIO);
    diff += (q2diff <= 1) ? q2diff : (q2diff - 1) * QRATIO_MULT;

    if (a->checksum != b->checksum)
        diff += 1;

    diff += h_distance(a->tmp_code, b->tmp_code, TLSH_CODE_SIZE);

    return diff;
}
