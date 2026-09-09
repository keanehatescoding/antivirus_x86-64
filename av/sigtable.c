/*
 * sigtable.c - hashtable-backed signature store + /proc interface.
 *
 * Locking: everything here runs in process context (the /proc write
 * comes from a userspace syscall; the match lookup runs from our
 * workqueue - see main.c) so a plain mutex is enough. No spinlocks/RCU
 * needed at this stage.
 *
 * /proc/kernel_av_signatures usage:
 *   cat  /proc/kernel_av_signatures                  - list entries
 *   echo "add sha256 <hex> <name>" > .../kernel_av_signatures
 *   echo "del sha256 <hex>"        > .../kernel_av_signatures
 */

#include <linux/ctype.h>
#include <linux/capability.h>
#include <linux/hashtable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "sigtable.h"

struct av_sig_entry {
  struct hlist_node node;
  enum av_algo algo;
  char name[AV_SIG_NAME_LEN];
  char hex[AV_HASH_HEX_MAXLEN + 1];
};

#define SIGTABLE_BITS 10 /* 1024 buckets - plenty for a student-scale DB */
/* Upper bound on stored signatures - without this, repeated `sig add`
writes grow the table without limit (each entry is a kmalloc'd node),
so a privileged writer (or, before the capable() gate below, any
writer that passes the proc file's DAC check) could exhaust kernel
memory. 8192 matches MAX_BEHAVIOR_ENTRIES in behavior.c and caps
worst-case usage at ~1-2MB. Enforced inside av_sigtable_add() under
sig_lock so the check and the insert below are atomic - no TOCTOU
between "table not full" and "insert". Returns -ENOSPC when full. */
#define MAX_SIG_ENTRIES 8192
static DEFINE_HASHTABLE(sig_table, SIGTABLE_BITS);
static DEFINE_MUTEX(sig_lock);
static size_t sig_count; /* read via READ_ONCE(), written under sig_lock - see
                            av_sigtable_count() */
static size_t sig_count_algo[AV_ALGO_COUNT]; /* same convention as sig_count */

static const size_t algo_hexlen[AV_ALGO_COUNT] = {32, 40, 64};
static const char *const algo_names[AV_ALGO_COUNT] = {"md5", "sha1", "sha256"};

static u32 hex_key(const char *hex) {
  return full_name_hash(NULL, hex, strlen(hex));
}

/* hex_key() hashes the raw bytes of the string, but av_sigtable_match()/
 * av_sigtable_del() compare with strncasecmp() (case-insensitive). Those
 * two have to agree on a canonical case, or a signature added with
 * different casing than a query digest lands in a different hash
 * bucket and is never found - even though strncasecmp() would call it
 * a match if it were ever compared directly. bin_to_hex() in main.c
 * always emits lowercase, so lowercase is the canonical form; this
 * normalizes any input (from avctl/echo) to match before it's ever
 * hashed or stored. */
static void hex_tolower(char *hex) {
  for (; *hex; hex++)
    *hex = tolower(*hex);
}

static const char *digest_for_algo(const struct av_digest *d,
                                   enum av_algo algo) {
  switch (algo) {
  case AV_ALGO_MD5:
    return d->md5;
  case AV_ALGO_SHA1:
    return d->sha1;
  case AV_ALGO_SHA256:
    return d->sha256;
  default:
    return NULL;
  }
}

static int parse_algo(const char *s, enum av_algo *out) {
  if (!strcasecmp(s, "md5"))
    *out = AV_ALGO_MD5;
  else if (!strcasecmp(s, "sha1"))
    *out = AV_ALGO_SHA1;
  else if (!strcasecmp(s, "sha256"))
    *out = AV_ALGO_SHA256;
  else
    return -EINVAL;
  return 0;
}

int av_sigtable_add(enum av_algo algo, const char *hex, const char *name) {
  /* existing is initialized to NULL only to satisfy static analyzers
   * that can't expand hash_for_each_possible() without full kernel
   * headers - see av_sigtable_del() below for the same workaround. */
  struct av_sig_entry *existing = NULL;
  struct av_sig_entry *e;
  size_t i;

  if (algo >= AV_ALGO_COUNT)
    return -EINVAL;
  if (strlen(hex) != algo_hexlen[algo])
    return -EINVAL;
  for (i = 0; i < algo_hexlen[algo]; i++)
    if (!isxdigit(hex[i]))
      return -EINVAL;

  e = kmalloc(sizeof(*e), GFP_KERNEL);
  if (!e)
    return -ENOMEM;

  e->algo = algo;
  strscpy(e->hex, hex, sizeof(e->hex));
  hex_tolower(e->hex); /* canonicalize before hashing - see hex_key() */
  strscpy(e->name, name, sizeof(e->name));

  mutex_lock(&sig_lock);
  /* Reject a duplicate (same algo + hex) instead of silently adding
   * a second entry alongside it - av_sigtable_match() would still
   * only ever find one of them (whichever hash_for_each_possible()
   * happens to walk to first), so a second copy was pure waste, not
   * a second layer of anything. Checked under the same lock as the
   * insert below - no separate pre-check, so no TOCTOU window
   * between "no duplicate" and "insert". */
  hash_for_each_possible(sig_table, existing, node, hex_key(e->hex)) {
    if (existing->algo == algo &&
        !strncasecmp(existing->hex, e->hex, algo_hexlen[algo])) {
      mutex_unlock(&sig_lock);
      kfree(e);
      return -EEXIST;
    }
  }
  /* Bound total entries - see MAX_SIG_ENTRIES above. Checked under
   * sig_lock alongside the duplicate check and the insert, so two
   * concurrent adds cannot both pass the check and overshoot the cap. */
  if (READ_ONCE(sig_count) >= MAX_SIG_ENTRIES) {
    mutex_unlock(&sig_lock);
    kfree(e);
    return -ENOSPC;
  }
  hash_add(sig_table, &e->node, hex_key(e->hex));
  WRITE_ONCE(sig_count, sig_count + 1);
  WRITE_ONCE(sig_count_algo[algo], sig_count_algo[algo] + 1);
  mutex_unlock(&sig_lock);

  return 0;
}

int av_sigtable_del(enum av_algo algo, const char *hex) {
  /* e is initialized to NULL only to satisfy static analyzers that
   * can't expand hash_for_each_possible() without full kernel
   * headers - see get_or_create_entry() in behavior.c for the same
   * workaround and full explanation. */
  struct av_sig_entry *e = NULL;
  char lower_hex[AV_HASH_HEX_MAXLEN + 1];
  int ret = -ENOENT;

  strscpy(lower_hex, hex, sizeof(lower_hex));
  hex_tolower(lower_hex);

  mutex_lock(&sig_lock);
  hash_for_each_possible(sig_table, e, node, hex_key(lower_hex)) {
    if (e->algo == algo && !strncasecmp(e->hex, hex, algo_hexlen[algo])) {
      hash_del(&e->node);
      kfree(e);
      WRITE_ONCE(sig_count, sig_count - 1);
      WRITE_ONCE(sig_count_algo[algo], sig_count_algo[algo] - 1);
      ret = 0;
      break;
    }
  }
  mutex_unlock(&sig_lock);
  return ret;
}

int av_sigtable_match(const struct av_digest *d, char *name_out,
                      size_t name_out_len) {
  /* Same false-positive workaround as av_sigtable_del() above. */
  struct av_sig_entry *e = NULL;
  int algo;
  int found = 0;

  mutex_lock(&sig_lock);
  for (algo = 0; algo < AV_ALGO_COUNT; algo++) {
    const char *hex = digest_for_algo(d, algo);

    hash_for_each_possible(sig_table, e, node, hex_key(hex)) {
      if (e->algo == algo && !strncasecmp(e->hex, hex, algo_hexlen[algo])) {
        strscpy(name_out, e->name, name_out_len);
        found = 1;
        goto out;
      }
    }
  }
out:
  mutex_unlock(&sig_lock);
  return found;
}

size_t av_sigtable_count(void) {
  /* Benign without the lock - this is a stats read, not used for any
   * correctness decision - but READ_ONCE()/WRITE_ONCE() on both ends
   * documents that intent explicitly and avoids leaving a plain,
   * unannotated concurrent read/write pair for the next person (or
   * a future KCSAN run) to have to re-derive as "is this actually
   * fine?" from scratch. */
  return READ_ONCE(sig_count);
}

size_t av_sigtable_algo_count(enum av_algo algo) {
  if (algo >= AV_ALGO_COUNT)
    return 0;
  return READ_ONCE(sig_count_algo[algo]); /* see av_sigtable_algo_count */
}
/* ---- /proc interface ---- */

static int sig_proc_show(struct seq_file *m, void *v) {
  struct av_sig_entry *e;
  int bkt;

  mutex_lock(&sig_lock);
  hash_for_each(sig_table, bkt, e, node) {
    seq_printf(m, "%s %s %s\n", algo_names[e->algo], e->hex, e->name);
  }
  mutex_unlock(&sig_lock);
  return 0;
}

static int sig_proc_open(struct inode *inode, struct file *file) {
  return single_open(file, sig_proc_show, NULL);
}

static ssize_t sig_proc_write(struct file *file, const char __user *ubuf,
                              size_t count, loff_t *ppos) {
  char kbuf[256];
  char cmd[8], algo_str[8], hex[AV_HASH_HEX_MAXLEN + 1], name[AV_SIG_NAME_LEN];
  enum av_algo algo;
  int n;

  /* DAC mode (0644) alone only checks UID 0, not the capability that
   * UID actually holds - any root process, even one that dropped
   * CAP_SYS_ADMIN, could otherwise mutate the signature table. The
   * netlink channel gates the equivalent operation behind
   * GENL_ADMIN_PERM; this proc handler needs the same bar. Matches
   * trust_proc_write() (behavior.c) and protected_proc_write(). */
  if (!capable(CAP_SYS_ADMIN))
    return -EPERM;

  /* Reject oversized writes instead of silently truncating them.
   * The old min(count, sizeof(kbuf) - 1) read a short prefix of an
   * over-long write but still returned `count` as if the whole
   * thing had been consumed - so "add <algo> <hex> <name>" followed
   * by enough trailing garbage to push it past 255 bytes got
   * silently truncated mid-token (a corrupted name, or the command
   * itself cut off) yet reported to the caller as a full success. */
  if (count >= sizeof(kbuf))
    return -EINVAL;

  if (copy_from_user(kbuf, ubuf, count))
    return -EFAULT;
  kbuf[count] = '\0';

  n = sscanf(kbuf, "%7s %7s %64s %63[^\n]", cmd, algo_str, hex, name);
  if (n < 3)
    return -EINVAL;

  if (parse_algo(algo_str, &algo))
    return -EINVAL;

  if (!strcasecmp(cmd, "add")) {
    int ret;

    if (n < 4)
      return -EINVAL;
    /* Propagate the real error - specifically -EEXIST for a
     * duplicate add and -ENOSPC when the table is at MAX_SIG_ENTRIES -
     * rather than flattening every failure to -EINVAL. avctl's
     * write_command() reports strerror(errno),
     * so this is the difference between a caller seeing "File
     * exists" (duplicate, an actionable answer) and "Invalid
     * argument" (which duplicate adds used to report too, even
     * though nothing about the input was actually invalid). */
    ret = av_sigtable_add(algo, hex, name);
    if (ret)
      return ret;
  } else if (!strcasecmp(cmd, "del")) {
    /* cppcheck-suppress knownConditionTrueFalse
     * False positive: cppcheck can't expand hash_for_each_possible()
     * without full kernel headers, so its value-flow analysis
     * concludes av_sigtable_del() always returns -ENOENT. At
     * runtime the hashtable genuinely can contain a matching
     * entry - this is a real condition, not dead code. Same class
     * of false positive as av_behavior_trust_del()'s call site in
     * behavior.c; the NULL-initializer inside av_sigtable_del()
     * itself isn't enough to silence it here, hence the explicit
     * suppression. */
    if (av_sigtable_del(algo, hex))
      return -ENOENT;
  } else {
    return -EINVAL;
  }

  return count;
}

static const struct proc_ops sig_proc_ops = {
    .proc_open = sig_proc_open,
    .proc_read = seq_read,
    .proc_write = sig_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *sig_proc_entry;

int av_sigtable_proc_init(void) {
  sig_proc_entry =
      proc_create("kernel_av_signatures", 0644, NULL, &sig_proc_ops);
  if (!sig_proc_entry)
    return -ENOMEM;
  return 0;
}

void av_sigtable_proc_exit(void) { proc_remove(sig_proc_entry); }

int av_sigtable_init(void) {
  hash_init(sig_table);
  return 0;
}

void av_sigtable_exit(void) {
  struct av_sig_entry *e;
  struct hlist_node *tmp;
  int bkt;

  mutex_lock(&sig_lock);
  hash_for_each_safe(sig_table, bkt, tmp, e, node) {
    hash_del(&e->node);
    kfree(e);
  }
  mutex_unlock(&sig_lock);
}
