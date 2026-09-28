/*
 * logfmt.h - escaping for untrusted strings (paths) embedded in the
 * module's quoted key=value log records.
 */

#ifndef AV_LOGFMT_H
#define AV_LOGFMT_H

#include <linux/gfp.h>

/* Returns a kmalloc'd copy of @s (at most PATH_MAX bytes of it) safe to
 * print between double quotes with %s, or NULL on allocation failure.
 * Caller kfree()s it. Pass the result through av_log_str() so a NULL
 * degrades to a placeholder instead of a "(null)" field. */
char *av_log_escape(const char *s, gfp_t gfp);

static inline const char *av_log_str(const char *escaped) {
  return escaped ? escaped : "?";
}

#endif /* AV_LOGFMT_H */
