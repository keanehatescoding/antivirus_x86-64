/*
 * fuzz_privsep_reply.c - libFuzzer target for userspace/avd/privsep_proto.h,
 * the validation of replies the unprivileged scan worker sends back to avd's
 * privileged parent (#103, #105).
 *
 * The worker parses attacker-influenced file content, so a reply is
 * attacker-influenced bytes. The input is the reply, byte for byte; the
 * request id the parent expects is taken from the input's own id field half
 * the time, so the checks after the id comparison are reached as well as the
 * mismatch path. Beyond "no crash under ASan/UBSan", the documented contract
 * is asserted: a rejection is exactly the canonical failure result, and an
 * acceptance is a verdict the parent may act on and log.
 *
 * Build and run through tests/fuzz/Makefile.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "privsep_proto.h"

#define REQUIRE(cond)                                                          \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "contract violated: %s (%s:%d)\n", #cond, __FILE__,      \
              __LINE__);                                                       \
      abort();                                                                 \
    }                                                                          \
  } while (0)

static int is_failure(const struct ps_verdict *v) {
  struct ps_verdict want;

  memset(&want, 0, sizeof(want));
  want.verdict = PS_VERDICT_CLEAN;
  want.inconclusive = true;
  return memcmp(v, &want, sizeof(want)) == 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ps_verdict v;
  uint64_t expect = 0x1122334455667788ull;
  size_t i;
  bool ok;

  /* Half the time, expect exactly the id the input carries. */
  if (size >= sizeof(struct ps_reply) && (data[0] & 1)) {
    struct ps_reply r;

    memcpy(&r, data, sizeof(r));
    expect = r.request_id;
  }

  /* Poison the output so a path that forgets to initialise it is caught. */
  memset(&v, 0xA5, sizeof(v));
  ok = ps_reply_validate(data, size, expect, &v);

  if (!ok) {
    REQUIRE(is_failure(&v));
    return 0;
  }

  REQUIRE(size == sizeof(struct ps_reply));
  REQUIRE(v.verdict == PS_VERDICT_CLEAN || v.verdict == PS_VERDICT_MALICIOUS);
  REQUIRE(v.score >= 0 && v.score <= PS_SCORE_MAX);
  REQUIRE(v.yara_matches >= 0 && v.yara_matches <= PS_COUNT_MAX);
  REQUIRE(v.yara_override == 0 || v.yara_override == 1);
  REQUIRE(v.fuzzy_score >= 0 && v.fuzzy_score <= PS_FUZZY_MAX);
  REQUIRE(v.tlsh_diff >= 0 && v.tlsh_diff <= PS_TLSH_MAX);
  for (i = 0; i < PS_RULE_NAME_SIZE && v.rule_name[i]; i++)
    REQUIRE(ps_rule_char_ok((unsigned char)v.rule_name[i]));
  REQUIRE(i < PS_RULE_NAME_SIZE);
  for (; i < PS_RULE_NAME_SIZE; i++)
    REQUIRE(v.rule_name[i] == '\0'); /* nothing after the NUL survives */

  /* The request side shares the header checks. */
  {
    uint64_t id;

    if (ps_request_parse(data, size, &id))
      REQUIRE(size == sizeof(struct ps_request));
  }
  return 0;
}
