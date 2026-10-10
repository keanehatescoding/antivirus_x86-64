// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * logfmt.c - escaping for untrusted strings in quoted log fields.
 *
 * Why not printk's %*pE: with its default flags (ESCAPE_ANY_NP) every
 * printable byte passes through untouched before any escape class is
 * consulted, and '"' is printable - so a filename containing
 * `" reason="trusted` closes the quoted path field early and forges
 * the fields after it. No %pE flag combination escapes '"' while
 * leaving other printable bytes readable; the kernel's own fix for
 * that (string_escape_mem()'s ESCAPE_APPEND) only exists from 5.13,
 * and this module targets 5.7+.
 *
 * Output: bytes that are isprint() pass through (same set %pE leaves
 * alone, so ordinary paths render identically), except '"' and '\\',
 * which become \" and \\ - escaping the backslash too keeps the
 * encoding unambiguous, so a literal `\042` in a filename can't pass
 * itself off as an escaped byte. Everything else (newlines, other
 * control bytes, non-printable high bytes) becomes a 3-digit \ooo
 * octal escape, which also keeps a record on one dmesg line.
 */

#include <linux/ctype.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "logfmt.h"

static size_t escaped_len(unsigned char c) {
  if (c == '"' || c == '\\')
    return 2;
  return isprint(c) ? 1 : 4;
}

char *av_log_escape(const char *s, gfp_t gfp) {
  size_t n = strnlen(s, PATH_MAX);
  size_t i, len = 0;
  char *out, *p;

  /* Two passes (size, then fill) so a typical path costs a small
   * allocation, not the 4 * PATH_MAX worst case. */
  for (i = 0; i < n; i++)
    len += escaped_len((unsigned char)s[i]);

  out = kmalloc(len + 1, gfp);
  if (!out)
    return NULL;

  p = out;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];

    if (c == '"' || c == '\\') {
      *p++ = '\\';
      *p++ = c;
    } else if (isprint(c)) {
      *p++ = c;
    } else {
      *p++ = '\\';
      *p++ = '0' + ((c >> 6) & 7);
      *p++ = '0' + ((c >> 3) & 7);
      *p++ = '0' + (c & 7);
    }
  }
  *p = '\0';
  return out;
}
