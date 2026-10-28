/*
 * privsep_proto.h - wire format between avd's privileged parent and the
 * unprivileged scan worker (#103, Stage 1; see docs/privilege-separation.md,
 * "IPC" and "The parent treats every reply as untrusted").
 *
 * The worker parses attacker-influenced file content, so the parent must
 * assume anything it reads back from a worker may have been written by an
 * attacker. This header is the whole of that boundary: fixed-size structs
 * with no padding, and one validation function that turns a raw reply into
 * either a clean ps_verdict or the canonical failure result. Nothing else in
 * the parent may look at reply bytes.
 *
 * Same single-source-of-truth arrangement as control_parse.h and
 * fan_parse.h: avd.c includes this header (today for compile-time checks
 * against the netlink protocol; the live path arrives with the spawner and
 * worker), and tests/test_privsep_proto.sh and
 * tests/fuzz/fuzz_privsep_reply.c compile this same header standalone.
 * Dependency-free (standard headers only).
 */

#ifndef AV_PRIVSEP_PROTO_H
#define AV_PRIVSEP_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PS_MAGIC 0x41565053u /* "AVPS" */
#define PS_VERSION 1u

/* Same numeric values as AV_VERDICT_CLEAN / AV_VERDICT_MALICIOUS in
 * av/netlink_proto.h; avd.c asserts the equality at compile time. Kept
 * local so this header stays standalone. */
#define PS_VERDICT_CLEAN 0u
#define PS_VERDICT_MALICIOUS 1u

/* AV_RULE_NAME_MAXLEN (63) + the NUL; avd.c asserts the equality. */
#define PS_RULE_NAME_SIZE 64

/* Display-only fields are clamped to these ranges. The score ceiling is far
 * above any sum of rule weights shipped today (MALICIOUS_SCORE_THRESHOLD is
 * 100). Nothing is decided from any of them. */
#define PS_SCORE_MAX 10000
#define PS_COUNT_MAX 65535
#define PS_FUZZY_MAX 100
#define PS_TLSH_MAX 100000

/* parent -> worker: the scan fd travels alongside as SCM_RIGHTS. */
struct ps_request {
  uint32_t magic;
  uint32_t version;
  uint64_t request_id;
};

/* worker -> parent. Every field is fixed width and laid out so the struct has
 * no padding (checked below): the parent never reads a byte the worker did
 * not deliberately put there, and a short or long message cannot be mistaken
 * for a valid one. There is deliberately no digest: the parent computes
 * SHA-256 itself, because the digest ends up in quarantine metadata and
 * verdict history and must not be something a compromised worker can set. */
struct ps_reply {
  uint32_t magic;
  uint32_t version;
  uint64_t request_id;
  uint32_t verdict;      /* PS_VERDICT_CLEAN or PS_VERDICT_MALICIOUS */
  uint32_t inconclusive; /* 0 or 1 */
  int32_t score;         /* YARA aggregate score, display only */
  int32_t yara_matches;  /* rules that matched, display only */
  int32_t yara_override; /* an override rule fired (0/1), display only */
  int32_t fuzzy_score;   /* ssdeep similarity 0-100, display only */
  int32_t tlsh_diff;     /* TLSH distance, display only */
  uint32_t reserved;     /* must be zero */
  char rule_name[PS_RULE_NAME_SIZE];
};

_Static_assert(sizeof(struct ps_request) == 16, "ps_request has padding");
_Static_assert(sizeof(struct ps_reply) == 16 + 8 * 4 + PS_RULE_NAME_SIZE,
               "ps_reply has padding");

/* What the parent keeps from a validated reply. Every field is in range and
 * rule_name is NUL-terminated and printable-allowlisted, so it is safe to
 * log, to write to the quarantine sidecar and to store in verdict history. */
struct ps_verdict {
  uint8_t verdict;
  bool inconclusive;
  int score;
  int yara_matches;
  int yara_override;
  int fuzzy_score;
  int tlsh_diff;
  char rule_name[PS_RULE_NAME_SIZE];
};

/* The canonical failure result (docs/privilege-separation.md, "Failure
 * handling"): everything zeroed first, so no field of an earlier or partly
 * parsed reply can leak into it, then CLEAN + inconclusive. Contract 5
 * (fail open is CLEAN plus inconclusive) needs exactly this. */
static inline void ps_verdict_failure(struct ps_verdict *out) {
  memset(out, 0, sizeof(*out));
  out->verdict = PS_VERDICT_CLEAN;
  out->inconclusive = true;
}

static inline int32_t ps_clamp32(int32_t v, int32_t hi) {
  return v < 0 ? 0 : (v > hi ? hi : v);
}

/* Characters a rule name may keep. Covers every name avd produces today
 * ("Sig:<name>", "Fuzzy:<name>(<n>)", "TLSH:<name>(<n>)" and the comma-joined
 * YARA rule list) and excludes what makes a name dangerous in a log line or
 * a sidecar file: control characters, newlines, quotes and path separators.
 * Anything else is replaced with '_' rather than rejected, so one odd byte
 * does not turn a real conviction into a failure. */
static inline bool ps_rule_char_ok(unsigned char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == ' ' || c == '_' || c == ':' ||
         c == '.' || c == ',' || c == '(' || c == ')' || c == '-' ||
         c == '+' || c == '=';
}

/* Copy `src` (PS_RULE_NAME_SIZE bytes, not trusted to contain a NUL) into
 * `dst`, forcing termination and applying the allowlist. Stops at the first
 * NUL the worker supplied. */
static inline void ps_sanitize_rule_name(char dst[PS_RULE_NAME_SIZE],
                                         const char src[PS_RULE_NAME_SIZE]) {
  size_t i;

  for (i = 0; i < PS_RULE_NAME_SIZE - 1 && src[i]; i++)
    dst[i] = ps_rule_char_ok((unsigned char)src[i]) ? src[i] : '_';
  dst[i] = '\0';
  for (i++; i < PS_RULE_NAME_SIZE; i++)
    dst[i] = '\0';
}

/* Build the request header. */
static inline void ps_request_init(struct ps_request *rq, uint64_t request_id) {
  memset(rq, 0, sizeof(*rq));
  rq->magic = PS_MAGIC;
  rq->version = PS_VERSION;
  rq->request_id = request_id;
}

/* Worker side: parse a request. Exactly the struct size, right magic and
 * version; the id is returned for echoing. */
static inline bool ps_request_parse(const void *buf, size_t len,
                                    uint64_t *request_id) {
  struct ps_request rq;

  if (len != sizeof(rq))
    return false;
  memcpy(&rq, buf, sizeof(rq));
  if (rq.magic != PS_MAGIC || rq.version != PS_VERSION)
    return false;
  *request_id = rq.request_id;
  return true;
}

/* Parent side: validate one reply. Returns true and fills `out` only for a
 * well-formed reply to `expect_id`; on any anomaly returns false and leaves
 * `out` as the canonical failure result, so a caller that ignores the return
 * value still fails open correctly. The caller must also kill the worker and
 * stop using its socket after a false return (a late reply must never be
 * matched to a later scan).
 *
 * Checked: exact length, magic, version, request id, verdict in {CLEAN,
 * MALICIOUS}, inconclusive in {0,1}, reserved zero. Clamped: score and the
 * advisory fields. Sanitized: rule_name. */
static inline bool ps_reply_validate(const void *buf, size_t len,
                                     uint64_t expect_id,
                                     struct ps_verdict *out) {
  struct ps_reply r;

  ps_verdict_failure(out);

  if (len != sizeof(r))
    return false;
  memcpy(&r, buf, sizeof(r));

  if (r.magic != PS_MAGIC || r.version != PS_VERSION)
    return false;
  if (r.request_id != expect_id)
    return false;
  if (r.verdict != PS_VERDICT_CLEAN && r.verdict != PS_VERDICT_MALICIOUS)
    return false;
  if (r.inconclusive > 1u)
    return false;
  if (r.reserved != 0)
    return false;

  out->verdict = (uint8_t)r.verdict;
  out->inconclusive = r.inconclusive != 0;
  out->score = ps_clamp32(r.score, PS_SCORE_MAX);
  out->yara_matches = ps_clamp32(r.yara_matches, PS_COUNT_MAX);
  out->yara_override = r.yara_override != 0;
  out->fuzzy_score = ps_clamp32(r.fuzzy_score, PS_FUZZY_MAX);
  out->tlsh_diff = ps_clamp32(r.tlsh_diff, PS_TLSH_MAX);
  ps_sanitize_rule_name(out->rule_name, r.rule_name);
  return true;
}

#endif /* AV_PRIVSEP_PROTO_H */
