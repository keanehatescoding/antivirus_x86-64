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

/* Independent model of fan_sig_parse_line(): what it must return for `s`,
 * worked out from the documented "<algo> <hex> <name>" format and the
 * kernel's three algorithms, not by calling the parser. Tokens: algo and
 * hex end at the first space, tab or newline; the name is the rest up to a
 * newline, minus leading blanks, and must be non-empty. */
static int expect_sig_rc(const char *s) {
  static const char dl[] = " \t\n";
  const char *algo, *hex, *name;
  size_t alen, hlen, want, i;

  algo = s + strspn(s, dl);
  alen = strcspn(algo, dl);
  if (!algo[alen])
    return -1;
  hex = algo + alen + strspn(algo + alen, dl);
  hlen = strcspn(hex, dl);
  if (!hex[hlen])
    return -1;
  /* One delimiter ends the hex token. The parser then cuts the name at the
   * next newline (skipping leading newlines) and only afterwards trims
   * leading blanks, so a blank-only name is empty. */
  name = hex + hlen + 1;
  name += strspn(name, "\n");
  if (strspn(name, " \t") >= strcspn(name, "\n"))
    return -1;
  if (alen == 6 && !strncmp(algo, "sha256", 6))
    want = 64;
  else if (alen == 4 && !strncmp(algo, "sha1", 4))
    want = 40;
  else if (alen == 3 && !strncmp(algo, "md5", 3))
    want = 32;
  else
    return -1;
  if (hlen != want)
    return -1;
  for (i = 0; i < hlen; i++)
    if (!isxdigit((unsigned char)hex[i]))
      return -1;
  return want == 64 ? 1 : 0;
}

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
    char orig[MAX_LINE + 1];
    int rc, want_rc;
    size_t i;

    /* The model runs on a copy: the parser tokenizes `line` in place. */
    memcpy(orig, line, len + 1);
    want_rc = expect_sig_rc(orig);
    rc = fan_sig_parse_line(line, &algo, &hex, &name);

    REQUIRE(rc == want_rc);
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
      REQUIRE(!strcmp(algo, "md5") || !strcmp(algo, "sha1"));
    }
    break;
  }
  case 2: {
    /* Expected output built first, from the documented rule: a backslash
     * plus exactly three octal digits (first 0-3) is one byte; anything
     * else, including a malformed escape, stays literal. */
    char expected[MAX_LINE + 1];
    size_t i = 0, e = 0;

    while (i < len) {
      if (i + 3 < len && line[i] == '\\' && line[i + 1] >= '0' &&
          line[i + 1] <= '3' && line[i + 2] >= '0' && line[i + 2] <= '7' &&
          line[i + 3] >= '0' && line[i + 3] <= '7') {
        expected[e++] = (char)(((line[i + 1] - '0') << 6) |
                               ((line[i + 2] - '0') << 3) | (line[i + 3] - '0'));
        i += 4;
      } else {
        expected[e++] = line[i++];
      }
    }
    expected[e] = '\0';
    fan_unescape_octal(line);
    REQUIRE(!strcmp(line, expected));
    break;
  }
  case 3: {
    /* Independent oracle: the pseudo/network filesystems that must not be
     * marked, spelled out here rather than read from the implementation. */
    static const char *const never[] = {
        "proc",    "sysfs",    "cgroup",  "cgroup2", "devpts",      "mqueue",
        "debugfs", "tracefs",  "securityfs", "pstore", "bpf",       "configfs",
        "fusectl", "hugetlbfs", "autofs", "binfmt_misc", "efivarfs", "nsfs",
        "selinuxfs", "rpc_pipefs", "nfsd", "nfs",     "nfs4",    "cifs",
        "smb3",    "smbfs",    "9p",      "ceph",    "glusterfs",   "afs",
        "sshfs",   "fuse",     "fuseblk"};
    bool want = line[0] != '\0' && strncmp(line, "fuse.", 5) != 0;
    size_t k;

    for (k = 0; k < sizeof(never) / sizeof(never[0]); k++)
      if (!strcmp(line, never[k]))
        want = false;
    REQUIRE(fan_fstype_markable(line) == want);
    break;
  }
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
