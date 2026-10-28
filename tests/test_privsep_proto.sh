#!/usr/bin/env bash
#
# tests/test_privsep_proto.sh - known-answer and adversarial coverage for
# userspace/avd/privsep_proto.h, the wire format between avd's privileged
# parent and the unprivileged scan worker (#103, Stage 1; see
# docs/privilege-separation.md, "The parent treats every reply as
# untrusted").
#
# The worker parses attacker-influenced file content, so everything it sends
# back is hostile as far as the parent is concerned. This test drives the
# validation function with well-formed replies, each way a reply can be
# malformed (length, magic, version, request id, verdict, flags, reserved),
# hostile rule names, out-of-range numbers, and a few hundred thousand
# deterministic pseudo-random buffers, and checks the parent-visible result
# every time: a validated verdict is always in range with a NUL-terminated,
# allowlisted rule name, and every rejection is exactly the canonical failure
# result (all-zero except CLEAN + inconclusive, with no field of the bad
# reply leaking through). The harness includes the production header
# directly, same arrangement as test_fan_parse.sh, and is built with
# ASan+UBSan.
#
# Pure userspace, no kernel module or root needed:
#   tests/test_privsep_proto.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_privsep_proto.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
# False positive: cleanup() IS invoked via `trap` on the next line.
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

cat > "$BUILD_DIR/harness.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "privsep_proto.h"

static int PASS, FAIL;

#define CHECK(cond, label) do { \
    if (cond) { printf("  PASS: %s\n", label); PASS++; } \
    else { printf("  FAIL: %s\n", label); FAIL++; } \
} while (0)

#define ID 0x1122334455667788ull

static void good_reply(struct ps_reply *r) {
    memset(r, 0, sizeof(*r));
    r->magic = PS_MAGIC;
    r->version = PS_VERSION;
    r->request_id = ID;
    r->verdict = PS_VERDICT_MALICIOUS;
    r->score = 150;
    r->yara_matches = 3;
    r->yara_override = 1;
    snprintf(r->rule_name, sizeof(r->rule_name), "Rule_A,Rule_B");
}

/* The canonical failure result, as the contract defines it. */
static bool is_failure(const struct ps_verdict *v) {
    struct ps_verdict want;
    memset(&want, 0, sizeof(want));
    want.verdict = PS_VERDICT_CLEAN;
    want.inconclusive = true;
    return memcmp(v, &want, sizeof(want)) == 0;
}

/* A verdict the parent may act on and log: in range, NUL-terminated,
 * allowlisted name. */
static bool is_sane(const struct ps_verdict *v) {
    size_t i;
    if (v->verdict != PS_VERDICT_CLEAN && v->verdict != PS_VERDICT_MALICIOUS)
        return false;
    if (v->score < 0 || v->score > PS_SCORE_MAX) return false;
    if (v->yara_matches < 0 || v->yara_matches > PS_COUNT_MAX) return false;
    if (v->yara_override != 0 && v->yara_override != 1) return false;
    if (v->fuzzy_score < 0 || v->fuzzy_score > PS_FUZZY_MAX) return false;
    if (v->tlsh_diff < 0 || v->tlsh_diff > PS_TLSH_MAX) return false;
    for (i = 0; i < PS_RULE_NAME_SIZE && v->rule_name[i]; i++)
        if (!ps_rule_char_ok((unsigned char)v->rule_name[i])) return false;
    return i < PS_RULE_NAME_SIZE; /* found the NUL */
}

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return (uint32_t)(rng >> 16);
}

int main(void) {
    struct ps_reply r;
    struct ps_verdict v;
    struct ps_request rq;
    uint64_t id;
    unsigned char buf[sizeof(struct ps_reply) + 16];

    printf("layout:\n");
    CHECK(sizeof(struct ps_request) == 16, "request is 16 bytes, no padding");
    CHECK(sizeof(struct ps_reply) == 112, "reply is 112 bytes, no padding");

    printf("\nwell-formed replies:\n");
    good_reply(&r);
    CHECK(ps_reply_validate(&r, sizeof(r), ID, &v) && is_sane(&v) &&
          v.verdict == PS_VERDICT_MALICIOUS && !v.inconclusive &&
          v.score == 150 && v.yara_matches == 3 && v.yara_override == 1 &&
          strcmp(v.rule_name, "Rule_A,Rule_B") == 0,
          "malicious reply round-trips");
    good_reply(&r);
    r.verdict = PS_VERDICT_CLEAN; r.inconclusive = 1; r.score = 0;
    r.rule_name[0] = '\0';
    CHECK(ps_reply_validate(&r, sizeof(r), ID, &v) && v.inconclusive &&
          v.verdict == PS_VERDICT_CLEAN && v.rule_name[0] == '\0',
          "inconclusive CLEAN reply accepted as such");
    good_reply(&r);
    snprintf(r.rule_name, sizeof(r.rule_name), "Fuzzy:Evil.Sample(87)");
    CHECK(ps_reply_validate(&r, sizeof(r), ID, &v) &&
          strcmp(v.rule_name, "Fuzzy:Evil.Sample(87)") == 0,
          "names avd produces itself pass through unchanged");

    printf("\nrequest header:\n");
    ps_request_init(&rq, ID);
    CHECK(ps_request_parse(&rq, sizeof(rq), &id) && id == ID,
          "request round-trips");
    CHECK(!ps_request_parse(&rq, sizeof(rq) - 1, &id), "short request rejected");
    CHECK(!ps_request_parse(buf, sizeof(rq) + 1, &id), "long request rejected");
    rq.magic ^= 1;
    CHECK(!ps_request_parse(&rq, sizeof(rq), &id), "bad request magic rejected");
    ps_request_init(&rq, ID); rq.version++;
    CHECK(!ps_request_parse(&rq, sizeof(rq), &id), "bad request version rejected");

    printf("\nmalformed replies become the canonical failure:\n");
    good_reply(&r);
    CHECK(!ps_reply_validate(&r, sizeof(r) - 1, ID, &v) && is_failure(&v),
          "truncated reply");
    CHECK(!ps_reply_validate(&r, 0, ID, &v) && is_failure(&v), "empty reply");
    memset(buf, 0, sizeof(buf)); memcpy(buf, &r, sizeof(r));
    CHECK(!ps_reply_validate(buf, sizeof(r) + 1, ID, &v) && is_failure(&v),
          "oversized reply");
    CHECK(!ps_reply_validate(&r, sizeof(r), ID + 1, &v) && is_failure(&v),
          "wrong request id (a late reply for an earlier scan)");
    good_reply(&r); r.magic = 0;
    CHECK(!ps_reply_validate(&r, sizeof(r), ID, &v) && is_failure(&v), "bad magic");
    good_reply(&r); r.version = PS_VERSION + 1;
    CHECK(!ps_reply_validate(&r, sizeof(r), ID, &v) && is_failure(&v), "bad version");
    good_reply(&r); r.verdict = 2;
    CHECK(!ps_reply_validate(&r, sizeof(r), ID, &v) && is_failure(&v),
          "verdict outside CLEAN/MALICIOUS");
    good_reply(&r); r.verdict = 0xffffffffu;
    CHECK(!ps_reply_validate(&r, sizeof(r), ID, &v) && is_failure(&v),
          "verdict 0xffffffff");
    good_reply(&r); r.inconclusive = 2;
    CHECK(!ps_reply_validate(&r, sizeof(r), ID, &v) && is_failure(&v),
          "inconclusive flag other than 0/1");
    good_reply(&r); r.reserved = 1;
    CHECK(!ps_reply_validate(&r, sizeof(r), ID, &v) && is_failure(&v),
          "non-zero reserved field");
    good_reply(&r); r.score = 9999;
    r.verdict = 7;
    CHECK(!ps_reply_validate(&r, sizeof(r), ID, &v) && v.score == 0 &&
          v.rule_name[0] == '\0' && is_failure(&v),
          "no field of a rejected reply leaks into the failure result");

    printf("\nclamping:\n");
    good_reply(&r);
    r.score = 0x7fffffff; r.yara_matches = 0x7fffffff;
    r.fuzzy_score = 0x7fffffff; r.tlsh_diff = 0x7fffffff;
    CHECK(ps_reply_validate(&r, sizeof(r), ID, &v) && v.score == PS_SCORE_MAX &&
          v.yara_matches == PS_COUNT_MAX && v.fuzzy_score == PS_FUZZY_MAX &&
          v.tlsh_diff == PS_TLSH_MAX, "oversized numbers clamped to the ceiling");
    r.score = (int32_t)0x80000000u; r.yara_matches = -1;
    r.fuzzy_score = -5; r.tlsh_diff = -100000;
    CHECK(ps_reply_validate(&r, sizeof(r), ID, &v) && v.score == 0 &&
          v.yara_matches == 0 && v.fuzzy_score == 0 && v.tlsh_diff == 0,
          "negative numbers clamped to zero");
    good_reply(&r); r.yara_override = 12345;
    CHECK(ps_reply_validate(&r, sizeof(r), ID, &v) && v.yara_override == 1,
          "override flag normalised to 0/1");

    printf("\nhostile rule names:\n");
    good_reply(&r);
    memset(r.rule_name, 'A', sizeof(r.rule_name));      /* no NUL at all */
    CHECK(ps_reply_validate(&r, sizeof(r), ID, &v) && is_sane(&v) &&
          strlen(v.rule_name) == PS_RULE_NAME_SIZE - 1,
          "name without a NUL is forced to terminate inside the buffer");
    good_reply(&r);
    memcpy(r.rule_name, "a\nb\rc\"d'e/f\\g..\x01\x7f\xff", 19);
    r.rule_name[19] = '\0';
    CHECK(ps_reply_validate(&r, sizeof(r), ID, &v) && is_sane(&v) &&
          !strpbrk(v.rule_name, "\n\r\"'/\\") &&
          strcmp(v.rule_name, "a_b_c_d_e_f_g.._" "__") == 0,
          "control chars, quotes and path separators replaced, name kept");
    good_reply(&r);
    memcpy(r.rule_name, "../../etc/passwd", 17);
    CHECK(ps_reply_validate(&r, sizeof(r), ID, &v) &&
          strchr(v.rule_name, '/') == NULL,
          "path traversal in a name cannot survive");
    good_reply(&r);
    memset(r.rule_name, 0, sizeof(r.rule_name));
    memcpy(r.rule_name, "ok", 3);
    memset(r.rule_name + 10, 'Z', 20);                  /* junk after the NUL */
    CHECK(ps_reply_validate(&r, sizeof(r), ID, &v) &&
          strcmp(v.rule_name, "ok") == 0 && v.rule_name[10] == '\0',
          "bytes after the first NUL never reach the result");

    printf("\ndeterministic random buffers:\n");
    {
        long i, ok = 0, rej = 0, bad = 0;
        for (i = 0; i < 400000; i++) {
            size_t j, len = sizeof(r);
            struct ps_verdict pv;
            unsigned char raw[sizeof(struct ps_reply)];
            bool accepted;

            for (j = 0; j < sizeof(raw); j++) raw[j] = (unsigned char)rnd();
            /* Make most buffers survive the header checks so the later
             * checks and the sanitiser see real traffic. */
            if (rnd() % 8) {
                struct ps_reply *p = (struct ps_reply *)raw;
                p->magic = PS_MAGIC; p->version = PS_VERSION;
                p->request_id = ID;
                p->verdict = rnd() % 3;
                p->inconclusive = rnd() % 3;
                p->reserved = (rnd() % 16) == 0 ? rnd() : 0;
            }
            if (rnd() % 64 == 0) len = rnd() % (sizeof(raw) + 1);
            accepted = ps_reply_validate(raw, len, ID, &pv);
            if (accepted) { ok++; if (!is_sane(&pv)) bad++; }
            else { rej++; if (!is_failure(&pv)) bad++; }
        }
        printf("  accepted %ld, rejected %ld\n", ok, rej);
        CHECK(bad == 0, "every outcome is a sane verdict or exactly the failure result");
        CHECK(ok > 1000 && rej > 1000, "the random run exercised both outcomes");
    }

    printf("\n===================================\n");
    printf("privsep_proto: %d passed, %d failed\n", PASS, FAIL);
    printf("===================================\n");
    return FAIL ? 1 : 0;
}
EOF

if ! cc -Wall -Wextra -O1 -g -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined -I "$REPO_ROOT/userspace/avd" \
        "$BUILD_DIR/harness.c" -o "$BUILD_DIR/harness" 2>"$BUILD_DIR/build.log"; then
    echo "FAIL: could not build the privsep_proto harness - see build log:"
    cat "$BUILD_DIR/build.log"
    exit 1
fi

"$BUILD_DIR/harness"
exit $?
