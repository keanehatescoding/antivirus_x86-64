/*
 * fuzz_control_parse.c - libFuzzer target for userspace/avd/control_parse.h,
 * the helpers on avd's control-socket request path (#105):
 *
 *   read_line()           - bounded line reader over a stream
 *   quarantine_id_valid() - the only guard against path traversal in
 *                           QUARANTINE RESTORE/DELETE
 *   parse_verdicts_count() - VERDICTS RECENT argument
 *
 * The first input byte picks the helper, the rest is its input. Each
 * helper's documented contract is asserted against an independent oracle,
 * so a silent contract break fails the run, not only memory corruption.
 *
 * Build and run through tests/fuzz/Makefile.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "control_parse.h"

#define FUZZ_MAX_INPUT 8192

#define REQUIRE(cond)                                                          \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "contract violated: %s (%s:%d)\n", #cond, __FILE__,      \
              __LINE__);                                                       \
      abort();                                                                 \
    }                                                                          \
  } while (0)

/* Hand `data` to read_line() through a memfd (one syscall, no 64K pipe
 * limit, and EOF arrives exactly after the last byte). */
static ssize_t run_read_line(const uint8_t *data, size_t len, char *out,
                             size_t outsz) {
  int fd = memfd_create("fuzz", 0);
  ssize_t r;

  if (fd < 0)
    abort();
  if (len && write(fd, data, len) != (ssize_t)len)
    abort();
  if (lseek(fd, 0, SEEK_SET) != 0)
    abort();
  r = read_line(fd, out, outsz);
  close(fd);
  return r;
}

static void check_read_line(const uint8_t *data, size_t len, size_t outsz) {
  char out[256];
  ssize_t r;
  const uint8_t *nl;
  size_t limit;

  REQUIRE(outsz >= 2 && outsz <= sizeof(out));
  memset(out, 0x5a, sizeof(out));
  r = run_read_line(data, len, out, outsz);

  /* A reader may consume at most outsz-1 bytes before giving up. */
  limit = outsz - 1;
  nl = memchr(data, '\n', len < limit ? len : limit);

  if (nl) {
    /* A newline within reach must yield exactly the bytes before it. */
    REQUIRE(r == (ssize_t)(nl - data));
    REQUIRE(out[r] == '\0');
    REQUIRE(memcmp(out, data, (size_t)r) == 0);
    REQUIRE(!memchr(out, '\n', (size_t)r));
  } else if (len == 0) {
    REQUIRE(r == 0); /* clean EOF before any data */
  } else {
    /* No newline within reach: too long, or EOF mid-line. Never a line. */
    REQUIRE(r == -1);
  }
  /* Nothing past the buffer the caller offered may be touched. */
  for (size_t i = outsz; i < sizeof(out); i++)
    REQUIRE((unsigned char)out[i] == 0x5a);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char str[FUZZ_MAX_INPUT + 1];
  size_t len;
  uint8_t sel;

  if (size < 1)
    return 0;
  sel = data[0] % 3;
  data++;
  size--;
  if (size > FUZZ_MAX_INPUT)
    size = FUZZ_MAX_INPUT;

  switch (sel) {
  case 0: {
    /* Second byte varies the destination buffer size (2..255). */
    size_t outsz = 2;

    if (size >= 1) {
      outsz = 2 + (size_t)(data[0] % 254);
      data++;
      size--;
    }
    check_read_line(data, size, outsz);
    break;
  }
  case 1: {
    int ok;

    memcpy(str, data, size);
    str[size] = '\0';
    len = strlen(str);
    ok = quarantine_id_valid(str);
    /* Oracle: the traversal guard written out independently. */
    if (ok) {
      REQUIRE(len > 0);
      REQUIRE(!strchr(str, '/'));
      REQUIRE(strcmp(str, ".") != 0 && strcmp(str, "..") != 0);
      REQUIRE(len < (size_t)(PATH_MAX - 32));
    } else {
      REQUIRE(len == 0 || strchr(str, '/') || !strcmp(str, ".") ||
              !strcmp(str, "..") || len >= (size_t)(PATH_MAX - 32));
    }
    break;
  }
  default: {
    unsigned long n = 0;
    int ok;

    memcpy(str, data, size);
    str[size] = '\0';
    ok = parse_verdicts_count(str, &n);
    /* Independent grammar, written without strtoul(): optional leading
     * whitespace, optional sign, one or more digits, nothing after. Both
     * directions are checked, so a parser that rejects every argument
     * (or accepts garbage) fails on the plain-number seeds too. */
    {
      const char *p = str;
      size_t digits = 0;
      unsigned long v = 0;
      int negative = 0, overflow = 0;

      while (*p == ' ' || (*p >= '\t' && *p <= '\r'))
        p++;
      if (*p == '+' || *p == '-')
        negative = *p++ == '-';
      for (; *p >= '0' && *p <= '9'; p++, digits++) {
        unsigned digit = (unsigned)(*p - '0');

        if (!overflow) {
          if (v > ((unsigned long)-1 - digit) / 10)
            overflow = 1;
          else
            v = v * 10 + digit;
        }
      }
      REQUIRE(ok == (digits > 0 && *p == '\0'));
      if (ok) {
        /* Out of range saturates to the maximum (the sign is not applied
         * then); a minus sign otherwise negates modulo 2^N. */
        unsigned long expected = overflow ? (unsigned long)-1
                                          : (negative ? 0UL - v : v);

        REQUIRE(n == expected);
      }
    }
    break;
  }
  }
  return 0;
}
