/*
 * fuzz_fan_parse.c - libFuzzer target for userspace/avd/fan_parse.h, the
 * parsers behind avd's fanotify listener (#176, #105): one
 * /proc/self/mountinfo line, one /proc/kernel_av_signatures line, the
 * octal unescape and the filesystem-type deny list.
 *
 * The first input byte picks the parser, the rest is the line. Beyond
 * "no crash under ASan/UBSan", each parser's documented contract is
 * asserted, so a silent contract break (not just memory corruption) is
 * a finding too.
 *
 * Build and run through tests/fuzz/Makefile.
 */
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fan_parse.h"

#define MAX_LINE 4096

#define REQUIRE(cond)                                                          \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "contract violated: %s (%s:%d)\n", #cond, __FILE__,      \
              __LINE__);                                                       \
      abort();                                                                 \
    }                                                                          \
  } while (0)

static int in_buf(const char *p, const char *buf, size_t len) {
  return p >= buf && p < buf + len + 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char line[MAX_LINE + 1];
  size_t len;
  uint8_t sel;

  if (size < 1)
    return 0;
  sel = data[0] % 5;
  len = size - 1 > MAX_LINE ? MAX_LINE : size - 1;
  /* Parsers take NUL-terminated strings (they come from fgets()/getline()
   * in avd), so cut at the first NUL like the real callers effectively do. */
  memcpy(line, data + 1, len);
  line[len] = '\0';
  len = strlen(line);

  switch (sel) {
  case 0: {
    char *mp = NULL, *fs = NULL;
    unsigned maj = 0, min = 0;
    bool noexec = false;
    int rc = fan_mountinfo_parse_line(line, &maj, &min, &mp, &fs, &noexec);

    if (rc == 0) {
      REQUIRE(mp && fs);
      REQUIRE(in_buf(mp, line, len));
      REQUIRE(in_buf(fs, line, len));
      REQUIRE(mp[0] == '/');
      REQUIRE(fs[0] != '\0');
      /* Neither pointer may carry a separator the tokenizer split on. */
      REQUIRE(!strpbrk(fs, " \n"));
      (void)fan_fstype_markable(fs);
    } else {
      REQUIRE(rc == -1);
    }
    break;
  }
  case 1: {
    char *algo = NULL, *hex = NULL, *name = NULL;
    int rc = fan_sig_parse_line(line, &algo, &hex, &name);
    size_t i;

    REQUIRE(rc == -1 || rc == 0 || rc == 1);
    if (rc == 1) {
      REQUIRE(hex && name && algo);
      REQUIRE(in_buf(hex, line, len) && in_buf(name, line, len));
      REQUIRE(!strcmp(algo, "sha256"));
      REQUIRE(strlen(hex) == 64);
      for (i = 0; i < 64; i++)
        REQUIRE(isxdigit((unsigned char)hex[i]) && !isupper((unsigned char)hex[i]));
      REQUIRE(name[0] != '\0' && name[0] != ' ' && name[0] != '\t');
    } else if (rc == 0) {
      REQUIRE(algo && in_buf(algo, line, len));
      REQUIRE(strcmp(algo, "sha256") != 0);
    }
    break;
  }
  case 2: {
    size_t before = len, after;

    fan_unescape_octal(line);
    after = strlen(line);
    /* In-place unescape can only shrink. */
    REQUIRE(after <= before);
    break;
  }
  case 3:
    (void)fan_fstype_markable(line);
    break;
  default: {
    /* Positive path: a line built to be valid must be ACCEPTED, with the
     * hex lowercased. The other cases only check what an accepted parse
     * returns, so a parser that wrongly rejected valid signatures would
     * otherwise go unnoticed. The 64 digits and the name come from the
     * fuzz input, mapped onto the allowed alphabets. */
    static const char hexd[] = "0123456789abcdefABCDEF";
    char valid[MAX_LINE];
    char want[65];
    char *algo = NULL, *hex = NULL, *name = NULL;
    size_t i, n = len;
    int rc, o;

    for (i = 0; i < 64; i++) {
      char c = hexd[(i < n ? (unsigned char)line[i] : i) % (sizeof(hexd) - 1)];

      want[i] = (char)tolower((unsigned char)c);
      valid[i] = c;
    }
    want[64] = '\0';
    valid[64] = '\0';
    /* Name: the rest of the input, restricted to printable non-blank. */
    o = snprintf(line, sizeof(line), "sha256 %s ", valid);
    REQUIRE(o > 0);
    for (i = 64; i < n && (size_t)o < sizeof(line) - 2; i++) {
      unsigned char c = (unsigned char)data[1 + i];

      line[o++] = (c > ' ' && c < 0x7f) ? (char)c : '_';
    }
    if (line[o - 1] == ' ') /* guarantee a non-empty name */
      line[o++] = 'N';
    line[o] = '\0';

    rc = fan_sig_parse_line(line, &algo, &hex, &name);
    REQUIRE(rc == 1);
    REQUIRE(!strcmp(hex, want));
    REQUIRE(name[0] != '\0');
    break;
  }
  }
  return 0;
}
