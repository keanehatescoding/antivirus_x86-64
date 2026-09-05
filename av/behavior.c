/*
 * behavior.c - v0.8.0: behavioral heuristics implementation.
 * See behavior.h for the design summary.
 *
 * v0.8.1: per-PID entries in behavior_table were never reclaimed on
 * process exit - fine for a demo session, a real leak on long uptime
 * (every process that ever did a write-intent open or an execve leaves
 * a permanent kzalloc'd entry). Fixed with a periodic GC sweep
 * (behavior_gc_fn) rather than hooking process exit directly: our key
 * is a tgid, and correctly detecting "the whole process is gone" from
 * an exit hook means reasoning about thread-group-leader-vs-last-
 * thread teardown timing, which is exactly the kind of version-
 * fragile kernel API area main.c's openat/write() comment already
 * avoids elsewhere. A sweep that checks liveness via
 * pid_task(find_vpid(pid), PIDTYPE_TGID) gets the same end state
 * (stale entries eventually reclaimed) without that fragility, and
 * reuses the same delayed_work idiom as everything else here.
 *
 * Later fix: the rapid-write/rename counters were a FIXED (discrete)
 * window despite being called "sliding" in comments/docs - the
 * counter reset to 0/1 whenever more than WINDOW_MS had elapsed since
 * the window started, with no memory of activity in the PREVIOUS
 * window. A process could write up to THRESHOLD files, pause just
 * past the window boundary, and repeat indefinitely without ever
 * tripping either heuristic, regardless of total volume over time -
 * documented as evasion finding #4 in docs/evasion-findings.md.
 * sliding_window_note() (below) replaces the reset-on-boundary logic
 * with a real trailing window: each ring slot now carries its own
 * jiffies timestamp, and the count checked against each threshold is
 * "how many distinct entries fall within the last WINDOW_MS as of
 * right now", continuously, not "how many since the window last
 * reset". There is no longer a boundary to pace around.
 */

#include <linux/capability.h>
#include <linux/dcache.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/stringhash.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include "behavior.h"

#define BEHAVIOR_BITS 10          /* 1024 buckets */
/* Hard cap on live behavior_table entries. Each entry is a
 * kzalloc(sizeof(struct av_behavior_entry)) slab (~5-8KB, dominated by
 * the PATH_MAX exec_path buffer) reachable by any unprivileged process
 * that can execve() - see get_or_create_entry() below. Without a cap,
 * `while true; do /bin/true; done` from any local shell allocates
 * unreclaimable kernel memory as fast as GC_INTERVAL_MS lets exited
 * entries fall behind. 8192 entries is ~48MB worst case, comfortably
 * above any realistic concurrent-process count while still bounding
 * the DoS. */
#define MAX_BEHAVIOR_ENTRIES 8192
#define WRITE_OPEN_WINDOW_MS 2000 /* sliding window size */
#define WRITE_OPEN_THRESHOLD                                                   \
  50 /* DISTINCT write-intent opens within                                     \
      * the window that trip the "rapid                                        \
      * modification" heuristic - tunable,                                     \
      * not derived from any real                                              \
      * ransomware sample; raised from an                                      \
      * initial 20 after real VM testing                                       \
      * showed systemd's routine cgroup                                        \
      * writes tripping it well within                                         \
      * normal boot activity - see README                                      \
      * for the incident writeup */
#define MAX_TRACKED_PATHS WRITE_OPEN_THRESHOLD
/* Sized to exactly cover the
 * threshold: a real mass-distinct-
 * file writer will trip `rapid`
 * from the dedup set alone by the
 * time it's full, so there's no
 * window where the ring buffer
 * overflowing could hide a genuine
 * positive. See the note on
 * recent_path_hashes below for why
 * distinct-path counting exists at
 * all. */

#define GC_INTERVAL_MS                                                         \
  30000 /* how often to sweep behavior_table for                               \
         * entries whose process has since exited.                             \
         * Tunable - not latency-sensitive (this                               \
         * is purely memory reclamation, not a                                 \
         * detection path), and sweep cost is                                  \
         * O(number of tracked processes), which                               \
         * stays small in practice. 30s is a                                   \
         * starting point, not a tuned value. */

#define RENAME_WINDOW_MS 2000
#define RENAME_THRESHOLD                                                       \
  20 /* DISTINCT extension-append renames                                      \
      * within the window before this trips -                                  \
      * tunable, not derived from a real                                       \
      * ransomware sample. Deliberately LOWER                                  \
      * than WRITE_OPEN_THRESHOLD (50): this                                   \
      * only counts renames matching the                                       \
      * specific extension-append SHAPE (see                                   \
      * is_extension_append_rename() below),                                   \
      * not "any rename" the way the write                                     \
      * counter counts "any write-intent                                       \
      * open" - that's already a much rarer,                                   \
      * more specific signal, so it can trip                                   \
      * sooner without the same false-positive                                 \
      * exposure. */
#define MAX_TRACKED_RENAMES RENAME_THRESHOLD
/* Same sizing rationale as
 * MAX_TRACKED_PATHS above - sized
 * to exactly cover the threshold. */

/* Paths under these prefixes are excluded from BOTH the rapid-write
 * counter and the sensitive-path check entirely - not just given a
 * pass on one heuristic. These are pseudo-filesystems (sysfs, procfs)
 * and device nodes, not user data: systemd alone writes to dozens of
 * cgroup control files under /sys/fs/cgroup/ as completely routine
 * service management, and terminal I/O under /dev/tty* triggered a
 * false positive in real testing. Ransomware-style "rapid file
 * modification" is meaningful for user data (documents, /home,
 * mounted volumes) - it is not meaningful for kernel control-plane
 * interfaces, and treating them the same caused this heuristic to
 * try to kill PID 1 during ordinary system operation. */
static const char *const excluded_path_prefixes[] = {
    "/sys/",
    "/proc/",
    "/dev/",
};
#define NUM_EXCLUDED_PREFIXES ARRAY_SIZE(excluded_path_prefixes)

/* Substring match (not prefix - these can appear anywhere in a path,
 * e.g. /home/keane/.cache/zen/...) for directories whose whole PURPOSE
 * is disposable, regenerable data - real ransomware has essentially no
 * reason to target application cache, whereas the rapid-write heuristic
 * can't tell that apart from bulk-encrypting user documents. Added
 * after real testing: Zen browser's cache2 entries under ~/.cache/zen/
 * tripped this heuristic (pid 1921) even after the earlier distinct-
 * path-dedup fix, since the dedup fix only stops COUNTING REPEATS of
 * the same file - it does nothing when 50+ genuinely distinct cache
 * files get touched in one window, which is normal browser behavior. */
static const char *const excluded_path_cache_substrings[] = {
    "/.cache/",
};
#define NUM_EXCLUDED_CACHE_SUBSTRINGS ARRAY_SIZE(excluded_path_cache_substrings)

/* Suffix match for SQLite's own transient implementation files.
 * -journal and -wal files are created and deleted by SQLite as part of
 * ordinary transaction commits - not user content, and their churn
 * rate scales with how many SQLite databases an application has open,
 * not with anything resembling malicious intent. Added after real
 * testing: Zen/Firefox-style browsers keep many small SQLite databases
 * (permissions, bounce-tracking-protection, places, etc.) and normal
 * startup/browsing activity legitimately touches 50+ distinct -journal
 * paths within a couple of seconds. -shm (SQLite's shared-memory index
 * file) is the same family and included for the same reason. */
static const char *const excluded_path_suffixes[] = {
    "-journal",
    "-wal",
    "-shm",
};
#define NUM_EXCLUDED_SUFFIXES ARRAY_SIZE(excluded_path_suffixes)

/* Pseudo-filesystem/device paths (see excluded_path_prefixes above) are
 * exempt from EVERY behavior check, sensitive-path included - /sys, /proc,
 * and /dev aren't user data and were never meant to be reachable via the
 * sensitive-path list either. */
static bool path_is_pseudo_fs(const char *path) {
  size_t i;

  for (i = 0; i < NUM_EXCLUDED_PREFIXES; i++) {
    size_t len = strlen(excluded_path_prefixes[i]);

    if (!strncmp(path, excluded_path_prefixes[i], len))
      return true;
  }

  return false;
}

/* Cache/journal/wal/shm paths (see excluded_path_cache_substrings and
 * excluded_path_suffixes above) are noise ONLY for the volume-based
 * rapid-write/rapid-rename counters - they must NOT exempt a path from
 * path_is_sensitive(). A path like ~/.cache/staged is trivially attacker-
 * controlled; folding this into the same check that also skips the
 * sensitive-path test let a rename such as
 * `mv ~/.cache/staged ~/.ssh/authorized_keys` bypass detection entirely
 * via the old-path cache match. Callers must run path_is_sensitive()
 * unconditionally and use this function only to gate the rapid-write
 * heuristics. */
static bool path_is_rapid_write_noise(const char *path) {
  size_t i;
  size_t path_len = strlen(path);

  for (i = 0; i < NUM_EXCLUDED_CACHE_SUBSTRINGS; i++) {
    if (strstr(path, excluded_path_cache_substrings[i]))
      return true;
  }

  for (i = 0; i < NUM_EXCLUDED_SUFFIXES; i++) {
    size_t suffix_len = strlen(excluded_path_suffixes[i]);

    if (path_len >= suffix_len &&
        !strcmp(path + path_len - suffix_len, excluded_path_suffixes[i]))
      return true;
  }

  return false;
}

/* Substring match against these flags the corresponding heuristic.
 * Deliberately simple (no regex/glob) to keep this fully atomic-safe
 * if ever needed in a tighter path later, and easy to reason about. */
static const char *const sensitive_path_substrings[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/.ssh/",
};
#define NUM_SENSITIVE_SUBSTRINGS ARRAY_SIZE(sensitive_path_substrings)

/* Prefix match, not substring - "/boot/" as a bare substring flagged
 * any path containing a directory literally named "boot" anywhere
 * (Quasar/other web-framework src/boot/ directories, u-boot project
 * trees, etc.), which is a common legitimate directory name and not
 * remotely the same thing as the actual /boot filesystem. Unlike
 * /etc/passwd, /etc/shadow, and /.ssh/ - specific enough that a
 * substring match rarely fires outside the real path - "boot" alone
 * needed the same anchored-prefix treatment path_is_pseudo_fs() above
 * already uses for excluded_path_prefixes[]. */
static const char *const sensitive_path_prefixes[] = {
    "/boot/",
};
#define NUM_SENSITIVE_PREFIXES ARRAY_SIZE(sensitive_path_prefixes)

struct av_behavior_entry {
  struct hlist_node node;
  pid_t pid; /* tgid (process ID), not a thread id - see behavior.h */
  char exec_path[PATH_MAX]; /* recorded at execve time, empty if unknown */

  /* Dedup ring buffer for the rapid-write-open heuristic - counts
   * DISTINCT paths written in a TRUE trailing window (see
   * sliding_window_note() below), not raw open() calls and not a
   * fixed/discrete window that resets on an interval boundary (the
   * v0.8.x behavior - see evasion finding #4 in
   * docs/evasion-findings.md: pacing bursts just under the threshold,
   * one per fixed window, evaded it indefinitely, since the window
   * had no memory of the PREVIOUS window's activity). Without the
   * dedup half of this, a process rewriting a handful of its own
   * files repeatedly (browser IndexedDB/storage metadata, sqlite WAL
   * files, log rotation) trips the same counter as one touching 50
   * separate user documents - a real false positive seen in testing
   * (Firefox/Zen's storage engine rewriting its own ".metadata-v2"
   * file). Real mass-encryption ransomware still trips this because
   * it touches many DISTINCT files within any trailing window; an app
   * hammering its own small file set no longer does. Hashes only (not
   * full paths) to keep this cheap and fixed-size - a 32-bit hash
   * collision could theoretically under-count two different paths as
   * one, which only makes the heuristic slightly less sensitive,
   * never more trigger-happy. recent_path_jiffies is co-indexed with
   * recent_path_hashes (same slot = same event), NOT necessarily in
   * oldest-to-newest order once the ring has wrapped - sliding_window_
   * note() does a full scan every time rather than assuming order,
   * since MAX_TRACKED_PATHS (50) is small enough that this costs
   * nothing meaningful. */
  u32 recent_path_hashes[MAX_TRACKED_PATHS];
  unsigned long recent_path_jiffies[MAX_TRACKED_PATHS];
  unsigned int recent_path_next; /* ring buffer write cursor */
  unsigned int
      recent_path_filled; /* valid entries, caps at MAX_TRACKED_PATHS */

  /* Same true-sliding-window dedup-ring-buffer idea as
   * recent_path_hashes above, but for the rename heuristic: counts
   * DISTINCT source files renamed with an extension-append shape
   * within a trailing window, keyed on the OLD path (the file's
   * identity before the rename, mirroring "distinct paths written"
   * for the write-open counter). See av_behavior_check_rename() and
   * is_extension_append_rename(). */
  u32 recent_rename_hashes[MAX_TRACKED_RENAMES];
  unsigned long recent_rename_jiffies[MAX_TRACKED_RENAMES];
  unsigned int recent_rename_next;
  unsigned int recent_rename_filled;

  bool trusted; /* set at record_exec time if this binary's SHA-256
                 * is on the trust list - exempts the rapid-write
                 * counter specifically, see behavior.h */

  u64 start_time; /* task_struct->start_time of the task that last
                   * recorded an exec into this entry - set at fork
                   * and unchanged across that same task's own later
                   * execve() calls, so comparing it against the
                   * current exec's start_time lets
                   * av_behavior_record_exec() tell a genuine pid
                   * reuse (different task, different start_time)
                   * apart from the same still-running process
                   * exec'ing again. See that function for why this
                   * matters. */

  unsigned long last_touched; /* jiffies at the most recent
                               * get_or_create_entry() lookup (hit or
                               * miss) for this pid - see that
                               * function's LRU-eviction comment for
                               * why this exists. */
};

/* Shared true-sliding-window dedup check for both the write-open and
 * rename counters (same pattern, different ring buffers - see the
 * struct comment above for why a fixed/discrete window doesn't hold
 * up against paced bursts). `hashes`/`jiffies_arr` are co-indexed ring
 * buffers of capacity `cap`; `*filled` is how many of their first
 * `cap` slots hold valid entries (not necessarily oldest-to-newest
 * once the ring has wrapped) and `*next` is the write cursor.
 *
 * Scans every currently-valid slot, counting how many fall within the
 * trailing `window_ms` (jiffies_to_msecs(now - timestamp) <=
 * window_ms - entries older than that have "aged out" of the window
 * without needing to be physically removed; they simply stop counting
 * until the ring cursor eventually overwrites them) and whether `hash`
 * is already among them. If `hash` is already present within the
 * window, this is a repeat of something already counted - return 0
 * (nothing new to add) without touching the ring. Otherwise records
 * `hash` at the ring cursor (evicting whatever was there, which by
 * construction can only still be within-window in the exact edge case
 * where the returned count below already exceeds any real-world
 * threshold - see the call sites) and returns the number of distinct
 * entries within the window INCLUDING this new one, for the caller to
 * compare against its own threshold. */
static unsigned int sliding_window_note(u32 hash, unsigned long now,
                                        unsigned int window_ms, u32 *hashes,
                                        unsigned long *jiffies_arr,
                                        unsigned int cap, unsigned int *next,
                                        unsigned int *filled) {
  unsigned int in_window = 0;
  unsigned int i;
  bool seen = false;

  for (i = 0; i < *filled; i++) {
    if (jiffies_to_msecs(now - jiffies_arr[i]) <= window_ms) {
      in_window++;
      if (hashes[i] == hash)
        seen = true;
    }
  }

  if (seen)
    return 0;

  hashes[*next] = hash;
  jiffies_arr[*next] = now;
  *next = (*next + 1) % cap;
  if (*filled < cap)
    (*filled)++;

  return in_window + 1;
}

static DEFINE_HASHTABLE(behavior_table, BEHAVIOR_BITS);
static DEFINE_MUTEX(behavior_lock);
/* Live entry count, always read/written under behavior_lock - see
 * MAX_BEHAVIOR_ENTRIES and get_or_create_entry(). */
static unsigned int behavior_table_count;

static struct workqueue_struct *behavior_gc_wq;
static struct delayed_work behavior_gc_work;

/* ---- trusted-binary-hash table, mirroring sigtable.c's pattern ---- */

#define TRUST_BITS 8 /* 256 buckets - plenty for a trusted-app list */
#define SHA256_HEX_LEN 64
#define TRUST_NAME_LEN 64

struct av_trust_entry {
  struct hlist_node node;
  char sha256_hex[SHA256_HEX_LEN + 1];
  char name[TRUST_NAME_LEN];
};

static DEFINE_HASHTABLE(trust_table, TRUST_BITS);
static DEFINE_MUTEX(trust_lock);

static u32 hex_key(const char *hex) {
  return full_name_hash(NULL, hex, strlen(hex));
}

static bool hash_is_trusted(const char *sha256_hex, char *name_out,
                            size_t name_out_len) {
  /* e initialized to NULL only to satisfy static analyzers that
   * can't expand hash_for_each_possible() without full kernel
   * headers - see get_or_create_entry() above and av_sigtable_del()
   * in sigtable.c for the same workaround. */
  struct av_trust_entry *e = NULL;
  bool found = false;

  mutex_lock(&trust_lock);
  hash_for_each_possible(trust_table, e, node, hex_key(sha256_hex)) {
    if (!strncasecmp(e->sha256_hex, sha256_hex, SHA256_HEX_LEN)) {
      if (name_out)
        strscpy(name_out, e->name, name_out_len);
      found = true;
      break;
    }
  }
  mutex_unlock(&trust_lock);
  return found;
}
static void hex_tolower(char *hex) {
  for (; *hex; hex++)
    *hex = tolower(*hex);
}

int av_behavior_trust_add(const char *sha256_hex, const char *name) {
  /* Same NULL-initializer workaround as hash_is_trusted() above. */
  struct av_trust_entry *existing = NULL;
  struct av_trust_entry *e;
  char lower_hex[SHA256_HEX_LEN + 1];

  if (strlen(sha256_hex) != SHA256_HEX_LEN)
    return -EINVAL;

  strscpy(lower_hex, sha256_hex, sizeof(lower_hex));
  hex_tolower(lower_hex); /* canonicalize before hashing - see hex_key() */

  e = kmalloc(sizeof(*e), GFP_KERNEL);
  if (!e)
    return -ENOMEM;

  strscpy(e->sha256_hex, lower_hex, sizeof(e->sha256_hex));
  strscpy(e->name, name, sizeof(e->name));

  mutex_lock(&trust_lock);
  /* Reject a duplicate instead of silently adding a second entry
   * alongside it - same reasoning as av_behavior_protect_add()'s
   * duplicate check above. Without this, av_behavior_trust_del()
   * would only ever remove ONE of the two entries, leaving the hash
   * still trusted after what looks like a successful `trust del`.
   * Checked under the same lock as the insert below - no separate
   * pre-check, so no TOCTOU window. */
  hash_for_each_possible(trust_table, existing, node, hex_key(lower_hex)) {
    if (!strncasecmp(existing->sha256_hex, lower_hex, SHA256_HEX_LEN)) {
      mutex_unlock(&trust_lock);
      kfree(e);
      return -EEXIST;
    }
  }
  hash_add(trust_table, &e->node, hex_key(lower_hex));
  mutex_unlock(&trust_lock);

  return 0;
}

int av_behavior_trust_del(const char *sha256_hex) {
  /* Same NULL-initializer workaround as hash_is_trusted() above. */
  struct av_trust_entry *e = NULL;
  struct hlist_node *tmp = NULL;
  int ret = -ENOENT;
  char lower_hex[SHA256_HEX_LEN + 1];

  if (strlen(sha256_hex) != SHA256_HEX_LEN)
    return -EINVAL;

  strscpy(lower_hex, sha256_hex, sizeof(lower_hex));
  hex_tolower(lower_hex);

  mutex_lock(&trust_lock);
  /* _safe iteration + no break: av_behavior_trust_add() now rejects
   * duplicates going forward, but any dupes already stored by an
   * older build should still all be cleared by a single del(). */
  hash_for_each_possible_safe(trust_table, e, tmp, node, hex_key(lower_hex)) {
    if (!strncasecmp(e->sha256_hex, lower_hex, SHA256_HEX_LEN)) {
      hash_del(&e->node);
      kfree(e);
      ret = 0;
    }
  }
  mutex_unlock(&trust_lock);
  return ret;
}

static int trust_proc_show(struct seq_file *m, void *v) {
  struct av_trust_entry *e;
  int bkt;

  mutex_lock(&trust_lock);
  hash_for_each(trust_table, bkt, e, node) {
    seq_printf(m, "%s %s\n", e->sha256_hex, e->name);
  }
  mutex_unlock(&trust_lock);
  return 0;
}

static int trust_proc_open(struct inode *inode, struct file *file) {
  return single_open(file, trust_proc_show, NULL);
}

/* ppos is only read here, but proc_write must match struct proc_ops's
 * fixed non-const loff_t * signature exactly - same class of false
 * positive as protected_proc_write()'s own identical suppression
 * below. */
/* cppcheck-suppress constParameterCallback */
static ssize_t trust_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
  char kbuf[192];
  char cmd[8], hex[SHA256_HEX_LEN + 1], name[TRUST_NAME_LEN];
  int n;
  size_t len;

  /* DAC mode (0644) alone only checks UID 0, not the capability that
   * UID actually holds - any root process, even one that dropped
   * CAP_SYS_ADMIN, could otherwise mutate the trust list. The
   * netlink channel gates the equivalent operation behind
   * GENL_ADMIN_PERM; this proc handler needs the same bar. */
  if (!capable(CAP_SYS_ADMIN))
    return -EPERM;

  /* Reject anything but the first write to a freshly-opened fd - same
   * multi-chunk-truncation defense as protected_proc_write() below;
   * see its comment for why a size cap alone doesn't catch a large
   * write arriving as several separate, individually-small calls. */
  if (*ppos != 0)
    return -EINVAL;

  /* Reject oversized writes instead of silently truncating them -
   * same fix, same reasoning as sig_proc_write() in sigtable.c: the
   * old min(count, sizeof(kbuf) - 1) truncated the copied prefix
   * but still reported `count` bytes written, so a >191-byte write
   * got silently mangled yet looked like a full success to the
   * caller. */
  if (count >= sizeof(kbuf))
    return -EINVAL;

  if (copy_from_user(kbuf, ubuf, count))
    return -EFAULT;
  kbuf[count] = '\0';

  /* Require (and then strip) a trailing newline terminator - the other
   * half of the multi-chunk defense above: a write truncated mid-content
   * by chunked delivery ends mid-field, not on a newline, so this is
   * what actually rejects a truncated fragment instead of silently
   * parsing it as a short-but-valid hex hash. Same convention as
   * protected_proc_write()'s trailing-terminator requirement, optional
   * preceding \r included. */
  len = strlen(kbuf);
  if (len == 0 || kbuf[len - 1] != '\n')
    return -EINVAL;
  kbuf[--len] = '\0';
  if (len > 0 && kbuf[len - 1] == '\r')
    kbuf[--len] = '\0';

  n = sscanf(kbuf, "%7s %64s %63[^\n]", cmd, hex, name);
  if (n < 2)
    return -EINVAL;

  if (!strcasecmp(cmd, "add")) {
    if (n < 3)
      return -EINVAL;
    if (av_behavior_trust_add(hex, name))
      return -EINVAL;
  } else if (!strcasecmp(cmd, "del")) {
    /* cppcheck-suppress knownConditionTrueFalse
     * False positive: cppcheck can't expand hash_for_each_possible()
     * without full kernel headers, so its value-flow analysis
     * concludes av_behavior_trust_del() always returns -ENOENT.
     * At runtime the hashtable genuinely can contain a matching
     * entry - this is a real condition, not dead code. Same class
     * of false positive as av_sigtable_del() in sigtable.c;
     * version-dependent whether a NULL-initializer alone silences
     * it, hence the explicit suppression here instead. */
    if (av_behavior_trust_del(hex))
      return -ENOENT;
  } else {
    return -EINVAL;
  }

  return count;
}

static const struct proc_ops trust_proc_ops = {
    .proc_open = trust_proc_open,
    .proc_read = seq_read,
    .proc_write = trust_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *trust_proc_entry;

int av_behavior_trust_proc_init(void) {
  trust_proc_entry =
      proc_create("kernel_av_trusted", 0644, NULL, &trust_proc_ops);
  if (!trust_proc_entry)
    return -ENOMEM;
  return 0;
}

void av_behavior_trust_proc_exit(void) { proc_remove(trust_proc_entry); }

static void trust_table_destroy(void) {
  struct av_trust_entry *e;
  struct hlist_node *tmp;
  int bkt;

  mutex_lock(&trust_lock);
  hash_for_each_safe(trust_table, bkt, tmp, e, node) {
    hash_del(&e->node);
    kfree(e);
  }
  mutex_unlock(&trust_lock);
}

/* ---- protected-path allow-list ----
 *
 * The only hard-coded kill guard anywhere in this module is "never
 * target PID 1" (see kill_with_reason() below and av_kill() in
 * main.c) - deliberately minimal, since a loadable module has no
 * portable, distro-independent way to know which OTHER binaries on a
 * given system are "critical" (systemd's own path varies by distro,
 * sshd might be OpenSSH or something else entirely, etc.). Baking in
 * a hardcoded binary-name list would be exactly the kind of fragile,
 * distro-specific guess this codebase avoids elsewhere.
 *
 * Instead: an operator-managed allow-list of exact absolute exe
 * paths, mirroring the trusted-hash-list pattern above almost
 * exactly. A match here suppresses the KILL action only (same
 * log-then-skip shape as the PID-1 guard) - detection itself, and the
 * log line explaining what would have happened, are unaffected.
 * Exact-path match rather than prefix: protecting "/usr/bin/ssh"
 * shouldn't silently also protect "/usr/bin/ssh-agent" or anything
 * else an operator didn't explicitly list. */

#define PROTECTED_PATH_LEN PATH_MAX

struct av_protected_entry {
  struct hlist_node node;
  char path[PROTECTED_PATH_LEN];
};

static DEFINE_HASHTABLE(protected_table, TRUST_BITS);
static DEFINE_MUTEX(protected_lock);

static u32 path_key(const char *path) {
  return full_name_hash(NULL, path, strlen(path));
}

static bool path_is_on_protected_list(const char *path) {
  /* Same NULL-initializer workaround as hash_is_trusted() above. */
  struct av_protected_entry *e = NULL;
  bool found = false;

  mutex_lock(&protected_lock);
  hash_for_each_possible(protected_table, e, node, path_key(path)) {
    if (!strcmp(e->path, path)) {
      found = true;
      break;
    }
  }
  mutex_unlock(&protected_lock);
  return found;
}

int av_behavior_protect_add(const char *path) {
  /* Same NULL-initializer workaround as hash_is_trusted() above. */
  struct av_protected_entry *existing = NULL;
  struct av_protected_entry *e;

  if (path[0] != '/' || strlen(path) >= PROTECTED_PATH_LEN)
    return -EINVAL;

  e = kmalloc(sizeof(*e), GFP_KERNEL);
  if (!e)
    return -ENOMEM;

  strscpy(e->path, path, sizeof(e->path));

  mutex_lock(&protected_lock);
  /* Reject a duplicate instead of silently adding a second entry
   * alongside it - same reasoning as av_sigtable_add()'s duplicate
   * check in sigtable.c. Without this, av_behavior_protect_del()
   * would only ever remove ONE of the two entries (it stops at the
   * first match), leaving the path still protected after what looks
   * like a successful `protect del`. Checked under the same lock as
   * the insert below - no separate pre-check, so no TOCTOU window. */
  hash_for_each_possible(protected_table, existing, node, path_key(e->path)) {
    if (!strcmp(existing->path, e->path)) {
      mutex_unlock(&protected_lock);
      kfree(e);
      return -EEXIST;
    }
  }
  hash_add(protected_table, &e->node, path_key(e->path));
  mutex_unlock(&protected_lock);

  return 0;
}

int av_behavior_protect_del(const char *path) {
  /* Same NULL-initializer workaround as hash_is_trusted() above. */
  struct av_protected_entry *e = NULL;
  int ret = -ENOENT;

  mutex_lock(&protected_lock);
  hash_for_each_possible(protected_table, e, node, path_key(path)) {
    if (!strcmp(e->path, path)) {
      hash_del(&e->node);
      kfree(e);
      ret = 0;
      break;
    }
  }
  mutex_unlock(&protected_lock);
  return ret;
}

/* Resolves target_pid's own exe path (task->mm->exe_file, i.e. what
 * ACTUALLY exec'd - not any path string a caller might be passing
 * around for logging) and checks it against the protected list.
 * get_task_mm() is the standard, safe kernel API for the mm; the exe
 * file itself is pulled via get_file_rcu(&mm->exe_file) rather than
 * the more convenient get_mm_exe_file() wrapper, which does exactly
 * the same rcu_read_lock()+get_file_rcu() internally but is NOT
 * EXPORT_SYMBOL'd - confirmed against this kernel's own Module.symvers
 * (absent entirely, unlike get_task_mm/mmput/fput/d_path, all
 * EXPORT_SYMBOL(_GPL)), so an out-of-tree module can't link against it
 * even though it's declared in the public mm.h header. Handle a task
 * with no mm (kernel thread, already past exit_mm() during exit) by
 * simply returning false, same fail-open-on-inconclusive-info stance
 * as the rest of this codebase. Sleepable (get_task_mm() itself does
 * not sleep, but this is only ever called from workqueue/process
 * context here, same as everything else that calls kill_with_reason()/
 * av_kill()). `path_out` (optional) is filled with the resolved path
 * on a match, for logging. */
bool av_behavior_target_is_protected(struct pid *target_pid, char *path_out,
                                     size_t path_out_len) {
  struct task_struct *task;
  struct mm_struct *mm;
  struct file *exe_file;
  char *buf;
  bool protected = false;

  rcu_read_lock();
  task = pid_task(target_pid, PIDTYPE_PID);
  if (task)
    get_task_struct(task);
  rcu_read_unlock();

  if (!task)
    return false;

  mm = get_task_mm(task);
  put_task_struct(task);
  if (!mm)
    return false;

  rcu_read_lock();
  exe_file = get_file_rcu(&mm->exe_file);
  rcu_read_unlock();
  mmput(mm);
  if (!exe_file)
    return false;

  buf = kmalloc(PATH_MAX, GFP_KERNEL);
  if (buf) {
    char *resolved = d_path(&exe_file->f_path, buf, PATH_MAX);

    /* cppcheck-suppress knownConditionTrueFalse
     * Same false positive as hash_is_trusted()'s call site above -
     * path_is_on_protected_list() genuinely returns true at runtime
     * for a path added via av_behavior_protect_add(); cppcheck just
     * cannot trace hash_for_each_possible() without full kernel
     * headers. */
    if (!IS_ERR(resolved) && path_is_on_protected_list(resolved)) {
      protected = true;
      if (path_out)
        strscpy(path_out, resolved, path_out_len);
    }
    kfree(buf);
  }
  fput(exe_file);

  return protected;
}

static int protected_proc_show(struct seq_file *m, void *v) {
  struct av_protected_entry *e;
  int bkt;

  mutex_lock(&protected_lock);
  hash_for_each(protected_table, bkt, e, node) {
    seq_printf(m, "%s\n", e->path);
  }
  mutex_unlock(&protected_lock);
  return 0;
}

static int protected_proc_open(struct inode *inode, struct file *file) {
  return single_open(file, protected_proc_show, NULL);
}

/* Content this write handler will accept in a single call: the "add "/
 * "del " prefix, a full PATH_MAX-1 path, a mandatory trailing
 * terminator (see the *ppos/terminator comments below), and slack for
 * the NUL. Sized to the full path range avctl itself already accepts
 * (userspace/avctl/avctl.c rejects a path at or above PATH_MAX before
 * ever sending it) - a shorter cap here would silently reject
 * otherwise-valid CLI input with no way for the caller to tell why. */
#define PROTECTED_WRITE_MAXLEN (PATH_MAX + 16)

/* ppos is only read here, but proc_write must match struct proc_ops's
 * fixed non-const loff_t * signature exactly - same class of false
 * positive as av_netlink_notify()'s data parameter in netlink_chan.c. */
/* cppcheck-suppress constParameterCallback */
static ssize_t protected_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
  /* kbuf/path are PATH_MAX-scale buffers (unlike sig_proc_write()/
   * trust_proc_write(), which only ever handle a 64-hex-char digest) -
   * heap-allocate both rather than declare them on the kernel stack;
   * this write handler runs in ordinary process context (a user's
   * write() syscall), so GFP_KERNEL is fine. */
  char *kbuf;
  char cmd[8];
  char *path;
  int n;
  ssize_t ret;

  /* Same DAC-vs-capability gap as trust_proc_write() above - see its
   * comment. */
  if (!capable(CAP_SYS_ADMIN))
    return -EPERM;

  /* Reject anything but the first write to a freshly-opened fd - a
   * genuine continuation of an earlier call (its *ppos already
   * advanced past 0) is never a complete, standalone command on its
   * own and must not be parsed as one. This alone is not enough,
   * though: verified empirically that a single userspace write() near
   * PAGE_SIZE does NOT reliably arrive here as one call in the first
   * place - common libc/shell stdio buffering (bash's own `>`/
   * `printf` redirection included) flushes in ~4096-byte chunks, so a
   * large enough write shows up as SEVERAL separate calls, each
   * individually small enough to slip under a size check that doesn't
   * also know whether the content it received is actually complete.
   * The mandatory trailing terminator required below is what actually
   * closes that gap (a truncated first chunk from mid-content
   * splitting won't end in one), not the size cap alone. */
  if (*ppos != 0)
    return -EINVAL;

  /* Reject oversized writes instead of silently truncating them - same
   * reasoning as sig_proc_write()/trust_proc_write(). */
  if (count >= PROTECTED_WRITE_MAXLEN)
    return -EINVAL;

  kbuf = kmalloc(PROTECTED_WRITE_MAXLEN, GFP_KERNEL);
  path = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!kbuf || !path) {
    ret = -ENOMEM;
    goto out;
  }

  if (copy_from_user(kbuf, ubuf, count)) {
    ret = -EFAULT;
    goto out;
  }
  kbuf[count] = '\0';

  /* Not sscanf("%7s %4095[^\n]", ...) for the path half: a FIXED-width
   * field silently truncates an oversized path to 4095 bytes rather
   * than rejecting it, and the truncated result can still be short
   * enough to pass av_behavior_protect_add()'s own length check -
   * i.e. a >PATH_MAX write here would silently protect/unprotect a
   * DIFFERENT (truncated) path than the one the caller actually sent,
   * without any error. Parse cmd the same way, but take the path as
   * "everything after cmd and its following whitespace" directly, so
   * an oversized path is detected and rejected instead of quietly
   * mutated. */
  n = sscanf(kbuf, "%7s", cmd);
  if (n < 1) {
    ret = -EINVAL;
    goto out;
  }

  {
    char *rest = kbuf + strcspn(kbuf, " \t");
    size_t rest_len;

    rest += strspn(rest, " \t");
    rest_len = strlen(rest);

    /* Require (and then strip) a trailing terminator rather than
     * just taking whatever's left as the path:
     *
     * 1. It's the real fix for the multi-chunk truncation risk the
     *    *ppos check above only partially covers - a write that got
     *    cut mid-content by chunked delivery ends mid-path, not on a
     *    newline, so requiring one here is what actually rejects a
     *    truncated fragment instead of silently accepting it as a
     *    complete path.
     * 2. Without stripping it, a completely ordinary `echo "add
     *    /path" > .../kernel_av_protected` (this proc file's own
     *    documented usage pattern, same as sigtable.c's) would store
     *    "/path\n" - trailing newline included - which then never
     *    matches any real resolved executable path (d_path() output
     *    never ends in a newline), silently making every entry added
     *    this way permanently ineffective. avctl's own writes get the
     *    same terminator via write_command_to() so this applies
     *    uniformly regardless of caller.
     *
     * An optional preceding \r is stripped too, for a caller on the
     * other side of a CRLF-translating pipe. */
    if (rest_len == 0 || rest[rest_len - 1] != '\n') {
      ret = -EINVAL;
      goto out;
    }
    rest[--rest_len] = '\0';
    if (rest_len > 0 && rest[rest_len - 1] == '\r')
      rest[--rest_len] = '\0';

    if (rest_len == 0 || rest_len >= PATH_MAX) {
      ret = -EINVAL;
      goto out;
    }
    strscpy(path, rest, PATH_MAX);
  }

  if (!strcasecmp(cmd, "add")) {
    /* Propagate the real error - specifically -EEXIST for a
     * duplicate add - rather than flattening every failure to
     * -EINVAL, same reasoning as sig_proc_write()'s identical fix
     * in sigtable.c. */
    ret = av_behavior_protect_add(path);
    if (ret)
      goto out;
  } else if (!strcasecmp(cmd, "del")) {
    /* cppcheck-suppress knownConditionTrueFalse
     * Same false positive as av_behavior_trust_del()'s call site
     * above - cppcheck cannot expand hash_for_each_possible() without
     * full kernel headers. */
    if (av_behavior_protect_del(path)) {
      ret = -ENOENT;
      goto out;
    }
  } else {
    ret = -EINVAL;
    goto out;
  }

  ret = count;
out:
  kfree(path);
  kfree(kbuf);
  return ret;
}

static const struct proc_ops protected_proc_ops = {
    .proc_open = protected_proc_open,
    .proc_read = seq_read,
    .proc_write = protected_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *protected_proc_entry;

int av_behavior_protect_proc_init(void) {
  protected_proc_entry =
      proc_create("kernel_av_protected", 0644, NULL, &protected_proc_ops);
  if (!protected_proc_entry)
    return -ENOMEM;
  return 0;
}

void av_behavior_protect_proc_exit(void) { proc_remove(protected_proc_entry); }

static void protected_table_destroy(void) {
  struct av_protected_entry *e;
  struct hlist_node *tmp;
  int bkt;

  mutex_lock(&protected_lock);
  hash_for_each_safe(protected_table, bkt, tmp, e, node) {
    hash_del(&e->node);
    kfree(e);
  }
  mutex_unlock(&protected_lock);
}

/* Returns the raw key for hash_add()/hash_for_each_possible() to hash
 * themselves via hash_min() - same convention as hex_key() above.
 * Previously pre-hashed with hash_32(pid, BEHAVIOR_BITS), which already
 * folds down to a BEHAVIOR_BITS-wide value; hash_min() then hashed that
 * *again* down to the same width. Harmless (insert and lookup used the
 * same function, so entries were always found), just redundant work
 * repeated on every insert and lookup - hash_min() already does the one
 * reduction that is needed. */
static u32 pid_key(pid_t pid) { return (u32)pid; }

/* Evicts the single least-recently-touched entry in behavior_table
 * (smallest last_touched, updated by every get_or_create_entry()
 * lookup below - see that field's comment) to make room for a new
 * one when the table is already at MAX_BEHAVIOR_ENTRIES. O(n) full
 * scan, same cost class as behavior_gc_fn()'s existing sweep at the
 * same scale, called only on the create-while-full path (not every
 * lookup). Returns false if the table was empty (can't happen in
 * practice - this is only ever called once behavior_table_count has
 * already reached a nonzero MAX_BEHAVIOR_ENTRIES - but checked rather
 * than assumed).
 *
 * Why eviction instead of an outright refusal (this cap's original
 * shape): a hard "refuse once full" cap has no reclaim path for
 * entries whose *process is still alive* - behavior_gc_fn() only
 * reclaims dead pids. An unprivileged user well within a typical
 * RLIMIT_NPROC can start MAX_BEHAVIOR_ENTRIES live processes (no
 * malicious activity needed, just staying alive) and permanently fill
 * the table with entries GC will never touch. Every subsequent
 * process then gets e == NULL from get_or_create_entry() forever -
 * and av_behavior_check_unlink()'s self-delete kill depends entirely
 * on exec_path having been recorded, which never happens for an
 * untracked pid. That's not "only degrading the volume-based
 * heuristics" (this function's stance before this comment) - it's a
 * cheap, durable bypass of a real kill path. LRU eviction closes that:
 * the table can never stay permanently full of untouchable entries,
 * because SOME entry is always the least-recently-touched one and
 * becomes evictable. A process actively triggering the checks that
 * matter (openat/unlink/rename/exec) keeps refreshing its own
 * last_touched and is never the eviction target; only idle entries -
 * the ones least likely to be mid-attack right now - get reclaimed
 * under pressure. */
static bool evict_lru_entry(void) {
  /* e deliberately left uninitialized (unlike get_or_create_entry()'s
   * NULL-initialized e above) - hash_for_each() always assigns it via
   * hlist_entry_safe() before the loop body runs, same as
   * hash_for_each_possible() elsewhere in this file, but cppcheck's
   * inability to expand this macro without full kernel headers
   * manifests differently here: instead of a knownConditionTrueFalse
   * false positive on `e` itself, it misreads the whole `oldest = e`
   * assignment below as copying from an uninitialized struct. Explicit
   * suppression, same false-positive class as every other
   * hash_for_each*() call site in this file. */
  struct av_behavior_entry *e, *oldest = NULL;
  int bkt;

  hash_for_each(behavior_table, bkt, e, node) {
    /* cppcheck-suppress knownConditionTrueFalse
     * False positive: cppcheck can't see that hash_for_each() may run
     * its body zero or more times, so it doesn't track `oldest`
     * possibly still being NULL here across iterations - at runtime
     * this genuinely can be true on the first matching iteration. */
    if (!oldest || time_before(e->last_touched, oldest->last_touched))
      /* cppcheck-suppress uninitvar
       * See the comment on `e`'s declaration above - hash_for_each()
       * always assigns e to a real table entry before this runs. */
      oldest = e;
  }

  if (!oldest)
    return false;

  hash_del(&oldest->node);
  kfree(oldest);
  behavior_table_count--;
  return true;
}

/* Finds or creates the entry for `pid`. Always called under
 * behavior_lock. Returns NULL only on allocation failure (kzalloc, or
 * the table was somehow at capacity with nothing evictable - see
 * evict_lru_entry()'s "can't happen in practice" note). */
static struct av_behavior_entry *get_or_create_entry(pid_t pid) {
  /* Initialized to NULL only to satisfy static analyzers that can't
   * expand hash_for_each_possible() (a nested kernel macro requiring
   * full kernel headers to resolve) - the macro itself always
   * assigns e via hlist_entry_safe() before the loop body runs, so
   * this has no effect on actual behavior, just quiets a known false
   * positive category for Linux kernel list-iteration macros. */
  struct av_behavior_entry *e = NULL;

  hash_for_each_possible(behavior_table, e, node, pid_key(pid)) {
    if (e->pid == pid) {
      e->last_touched = jiffies;
      return e;
    }
  }

  if (behavior_table_count >= MAX_BEHAVIOR_ENTRIES) {
    /* At capacity - kick GC to run as soon as possible (instead of
     * waiting up to GC_INTERVAL_MS) so a burst of short-lived,
     * already-exited processes recovers headroom quickly, then evict
     * whichever live entry has gone longest untouched to make room
     * regardless - see evict_lru_entry()'s comment for why a live
     * table can't be allowed to just stay full. */
    mod_delayed_work(behavior_gc_wq, &behavior_gc_work, 0);
    if (!evict_lru_entry())
      return NULL;
  }

  e = kzalloc(sizeof(*e), GFP_KERNEL);
  if (!e)
    return NULL;

  e->pid = pid;
  e->last_touched = jiffies;
  hash_add(behavior_table, &e->node, pid_key(pid));
  behavior_table_count++;
  return e;
}

/* strstr() alone treats "/etc/passwd" as a substring match against
 * "/etc/passwd.bak", "/etc/passwd.new", or any other .../etc/passwd*
 * path - not just the real file. Since this feeds a heuristic that
 * can get a process killed (path_is_sensitive() below, via
 * av_behavior_check_openat()/_unlink()/_rename()), a backup/staging
 * file with the real name as a prefix shouldn't count as touching
 * the sensitive path itself. Requires a '/' or end-of-string right
 * after the match - i.e. the matched segment has to be a complete
 * path component, not merely a prefix of one. Needles that already
 * end in '/' (like "/.ssh/") are self-anchored on that side by
 * construction - a false positive on this side of a
 * "/.ssh/id_rsa"-style match structurally can't happen. */
static bool path_has_bounded_substring(const char *path, const char *needle) {
  size_t needle_len = strlen(needle);
  bool self_anchored = needle_len > 0 && needle[needle_len - 1] == '/';
  const char *p = path;

  while ((p = strstr(p, needle)) != NULL) {
    if (self_anchored || p[needle_len] == '\0' || p[needle_len] == '/')
      return true;
    p++;
  }
  return false;
}

static bool path_is_sensitive(const char *path) {
  size_t i;

  for (i = 0; i < NUM_SENSITIVE_PREFIXES; i++) {
    size_t len = strlen(sensitive_path_prefixes[i]);

    if (!strncmp(path, sensitive_path_prefixes[i], len))
      return true;
  }

  for (i = 0; i < NUM_SENSITIVE_SUBSTRINGS; i++) {
    if (path_has_bounded_substring(path, sensitive_path_substrings[i]))
      return true;
  }
  return false;
}

static const char *path_basename(const char *path) {
  const char *slash = strrchr(path, '/');

  return slash ? slash + 1 : path;
}

/* True if new_path's basename is old_path's basename with a non-empty
 * ".something" suffix appended - the observable shape of ransomware's
 * encryption pass (document.docx -> document.docx.crypt), independent
 * of which specific extension string a given family happens to use.
 *
 * Deliberately does NOT match:
 *   - moves that preserve the basename (mv file.txt newdir/file.txt -
 *     same length, not "extended")
 *   - ordinary renames to an unrelated name (draft.txt -> final.txt -
 *     not a prefix relationship at all)
 *   - atomic write-then-rename / temp-file finalization
 *     (file.txt.tmp -> file.txt - shorter, not an addition)
 * all of which are extremely common legitimate patterns that a bare
 * "did the extension change" check would also have caught. */
static bool is_extension_append_rename(const char *old_path,
                                       const char *new_path) {
  const char *old_base = path_basename(old_path);
  const char *new_base = path_basename(new_path);
  size_t old_len = strlen(old_base);
  size_t new_len = strlen(new_base);

  if (new_len <= old_len)
    return false;
  if (strncmp(old_base, new_base, old_len))
    return false;
  return new_base[old_len] == '.';
}

/* Shared kill-and-log helper - same pid_task/rcu_read_lock/send_sig
 * pattern used in main.c's execve path, duplicated here rather than
 * shared across modules to keep behavior.c self-contained.
 *
 * SAFETY NET: never target PID 1, full stop, regardless of what
 * triggered detection. Killing init can panic the kernel outright.
 * This was NOT a hypothetical risk - an earlier version of this
 * heuristic actually tried to kill PID 1 on real hardware/VM testing
 * (systemd's routine cgroup writes tripped the rapid-write threshold).
 * The real fix is not over-triggering in the first place (see the
 * path exclusions below), but this guard stays regardless - defense
 * in depth for a security tool that can SIGKILL things is worth the
 * one branch.
 *
 * v1.0.0-merge: structured key=value log format, matching main.c's
 * av_kill - see its comment for why. */
static void kill_with_reason(struct pid *target_pid, const char *path,
                             const char *reason) {
  struct task_struct *task;
  /* PATH_MAX (4096) is far too large for the kernel stack (typically
   * 8-16KB total, shared with everything else on this call path) -
   * heap-allocate rather than declare a PATH_MAX array here. Sleepable
   * context (workqueue), so GFP_KERNEL is fine. A kmalloc failure just
   * means the protected-exe path is missing from the log line below,
   * not that the protection check is skipped - av_behavior_target_
   * is_protected() tolerates a NULL path_out for exactly this case. */
  char *protected_path = kmalloc(PATH_MAX, GFP_KERNEL);

  if (pid_nr(target_pid) == 1) {
    pr_alert("kernel-av: event=suppressed action=none type=behavioral "
             "path=\"%s\" reason=\"%s\" pid=1\n",
             path, reason);
    kfree(protected_path);
    return;
  }

  if (av_behavior_target_is_protected(target_pid, protected_path, PATH_MAX)) {
    pr_alert("kernel-av: event=suppressed action=none type=behavioral "
             "path=\"%s\" reason=\"%s\" pid=%d protected_exe=\"%s\"\n",
             path, reason, pid_nr(target_pid),
             protected_path ? protected_path : "?");
    kfree(protected_path);
    return;
  }
  kfree(protected_path);

  rcu_read_lock();
  task = pid_task(target_pid, PIDTYPE_PID);
  if (task) {
    pr_alert("kernel-av: event=detected action=kill type=behavioral "
             "path=\"%s\" reason=\"%s\" pid=%d\n",
             path, reason, pid_nr(target_pid));
    send_sig(SIGKILL, task, 0);
  }
  rcu_read_unlock();
}

/* Periodic sweep: reclaims behavior_table entries for processes that
 * have since exited. Runs from process context (workqueue), so it's
 * fine to hold behavior_lock across the whole scan - this never runs
 * on the atomic kprobe path.
 *
 * Liveness check: find_vpid(pid) resolves the tgid number back to a
 * struct pid in this namespace (NULL if no such pid exists at all -
 * fully exited and reaped); pid_task(..., PIDTYPE_TGID) then confirms
 * a task in that thread group is still attached (NULL for a pid that
 * exists only as, e.g., a distinct PID-namespace artifact). Either
 * NULL means "gone" - safe to reclaim.
 *
 * PID reuse: if the pid number gets recycled by an unrelated new process
 * before this sweep runs, the stale entry still looks "alive" by the
 * pid-exists check alone. Compare the live task's start_time against the
 * entry's recorded start_time (same discriminator av_behavior_record_exec()
 * uses): a mismatch with a non-zero recorded start_time means this pid was
 * recycled since the entry's last exec, so reset the sliding-window state
 * and drop the stale exec_path/trust rather than letting the new occupant
 * inherit the previous process's counters before its own first execve
 * overwrites them. Entries that never recorded an exec (start_time == 0)
 * are left alone - they may still belong to the same pre-exec process,
 * and record_exec() will initialise them on its first exec. */
static void behavior_gc_fn(struct work_struct *w) {
  /* Initialized to NULL only to satisfy static analyzers that can't
   * expand hash_for_each_safe() (same false-positive category as
   * get_or_create_entry()'s hash_for_each_possible() NULL init below) -
   * the macro always assigns e before the loop body runs. */
  struct av_behavior_entry *e = NULL;
  struct hlist_node *tmp;
  int bkt;
  unsigned int removed = 0;

  mutex_lock(&behavior_lock);
  hash_for_each_safe(behavior_table, bkt, tmp, e, node) {
    struct pid *p;
    struct task_struct *task;
    bool alive;
    u64 cur_start = 0;

    rcu_read_lock();
    p = find_vpid(e->pid);
    task = p ? pid_task(p, PIDTYPE_TGID) : NULL;
    if (task)
      cur_start = READ_ONCE(task->start_time);
    alive = (task != NULL);
    rcu_read_unlock();

    if (!alive) {
      hash_del(&e->node);
      kfree(e);
      removed++;
    } else if (e->start_time != 0 && e->start_time != cur_start) {
      /* PID recycled since this entry's last exec - start clean so the
       * new occupant is never judged on the previous process's activity. */
      e->start_time = cur_start;
      e->exec_path[0] = '\0';
      e->trusted = false;
      e->recent_path_next = 0;
      e->recent_path_filled = 0;
      e->recent_rename_next = 0;
      e->recent_rename_filled = 0;
    }
  }
  behavior_table_count -= removed;
  mutex_unlock(&behavior_lock);

  if (removed)
    pr_debug("kernel-av: event=gc type=behavioral reclaimed=%u\n", removed);

  queue_delayed_work(behavior_gc_wq, &behavior_gc_work,
                     msecs_to_jiffies(GC_INTERVAL_MS));
}

void av_behavior_record_exec(pid_t pid, const char *path,
                             const char *sha256_hex, u64 start_time) {
  struct av_behavior_entry *e;
  /* cppcheck-suppress knownConditionTrueFalse
   * Same false positive as av_behavior_trust_del() above -
   * hash_is_trusted() genuinely returns true at runtime for a hash
   * that was added via av_behavior_trust_add(); cppcheck just can't
   * trace hash_for_each_possible() without full kernel headers. */
  bool trusted = hash_is_trusted(sha256_hex, NULL, 0);

  mutex_lock(&behavior_lock);
  e = get_or_create_entry(pid);
  if (e) {
    strscpy(e->exec_path, path, sizeof(e->exec_path));
    e->trusted = trusted;
    /* A reused pid can land on a stale entry left behind by a
     * previous, unrelated process (get_or_create_entry() matches on
     * pid alone), but av_behavior_record_exec() also fires on every
     * OTHER execve of a process that's still running (e.g. a shell
     * `exec`, or a process re-executing itself) - NOT just on actual
     * pid reuse. Resetting the window unconditionally on every exec
     * would let any process wipe its own write/rename counters on
     * demand simply by exec'ing something, turning this into an
     * attacker-controlled evasion primitive instead of a PID-reuse
     * fix. task_struct->start_time is set at fork and untouched by
     * that same task's own later execve() calls, so a differing
     * start_time (including the zeroed value on a freshly-kzalloc'd
     * entry) reliably means this pid was actually recycled by a
     * different task - only then is it safe to clear the sliding-
     * window state rather than letting it age out on its own over up
     * to WRITE_OPEN_WINDOW_MS. */
    if (e->start_time != start_time) {
      e->start_time = start_time;
      e->recent_path_next = 0;
      e->recent_path_filled = 0;
      e->recent_rename_next = 0;
      e->recent_rename_filled = 0;
    }
  }
  mutex_unlock(&behavior_lock);
}

void av_behavior_check_openat(pid_t pid, const char *path, int flags,
                              struct pid *target_pid) {
  struct av_behavior_entry *e;
  bool sensitive;
  bool rapid = false;

  /* Read-only opens aren't interesting for either heuristic here. */
  if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
    return;

  /* Pseudo-filesystem/device paths never count toward either
   * heuristic - see the comment on excluded_path_prefixes for why. */
  if (path_is_pseudo_fs(path))
    return;

  sensitive = path_is_sensitive(path);

  mutex_lock(&behavior_lock);
  e = get_or_create_entry(pid);
  if (e && !e->trusted && !path_is_rapid_write_noise(path)) {
    /* Rapid-write counting is skipped ENTIRELY for a trusted
     * process (see behavior.h) or a cache/journal-shaped path -
     * not just given a higher threshold. The sensitive-path check
     * above still applies regardless; only the volume-based signal
     * is exempted. */
    u32 path_hash = full_name_hash(NULL, path, strlen(path));
    unsigned int in_window = sliding_window_note(
        path_hash, jiffies, WRITE_OPEN_WINDOW_MS, e->recent_path_hashes,
        e->recent_path_jiffies, MAX_TRACKED_PATHS, &e->recent_path_next,
        &e->recent_path_filled);

    if (in_window > WRITE_OPEN_THRESHOLD)
      rapid = true;
  }
  mutex_unlock(&behavior_lock);

  if (sensitive)
    kill_with_reason(target_pid, path, "write-intent open of sensitive path");
  else if (rapid)
    kill_with_reason(target_pid, path,
                     "rapid file modification (possible ransomware pattern)");
}

void av_behavior_check_unlink(pid_t pid, const char *path,
                              struct pid *target_pid) {
  const struct av_behavior_entry *e;
  bool self_delete = false;
  bool sensitive;

  if (path_is_pseudo_fs(path))
    return;

  mutex_lock(&behavior_lock);
  e = get_or_create_entry(pid);
  /* Both sides must be genuinely-resolved absolute paths (path[0] ==
   * '/' is the same litmus test resolve_absolute_path() itself uses
   * for "already absolute") before trusting a strcmp() match as real
   * identity. resolve_absolute_path() falls back to copying the raw,
   * still-relative `path` through unresolved on a handful of rare
   * failure paths (allocation failure, d_path() failure, or - see its
   * own comment - a would-be truncating concatenation) rather than
   * silently dropping the event; two DIFFERENT files that both hit
   * one of those fallbacks could otherwise share the exact same
   * leftover relative remainder and falsely strcmp() equal here,
   * triggering a self-delete kill of an unrelated process. */
  if (e && e->exec_path[0] == '/' && path[0] == '/' &&
      !strcmp(e->exec_path, path))
    self_delete = true;
  mutex_unlock(&behavior_lock);

  sensitive = path_is_sensitive(path);

  if (self_delete)
    kill_with_reason(target_pid, path,
                     "self-deleting binary (possible dropper/backdoor)");
  else if (sensitive)
    kill_with_reason(target_pid, path, "deletion of sensitive path");
}

void av_behavior_check_rename(pid_t pid, const char *oldpath,
                              const char *newpath, struct pid *target_pid) {
  struct av_behavior_entry *e;
  bool sensitive;
  bool rapid = false;

  /* Sensitive-path check applies to either end - renaming FROM a
   * sensitive path (e.g. relocating /etc/shadow out from under the
   * system) or TO one (e.g. clobbering /etc/passwd via rename) are
   * both worth flagging, and neither direction is really "safer"
   * than the other. Computed unconditionally, and NOT folded into the
   * pseudo-fs skip below: an early return on "either end is pseudo-fs"
   * would let a rename like `mv /dev/shm/x /etc/shadow` suppress
   * detection of the genuinely sensitive newpath just because oldpath
   * happened to match /dev/ - the two paths are independent, and a
   * pseudo-fs match on one end says nothing about the other end. */
  sensitive = path_is_sensitive(oldpath) || path_is_sensitive(newpath);

  /* Pseudo-filesystem/device paths never count toward the volume-based
   * heuristic - same reasoning as av_behavior_check_openat. Checked on
   * BOTH ends: a rename touching /proc, /sys, or /dev on either side
   * isn't a meaningful signal for that heuristic. This only gates the
   * rapid-rename counter below, never the sensitive-path check above. */
  if (is_extension_append_rename(oldpath, newpath)) {
    mutex_lock(&behavior_lock);
    e = get_or_create_entry(pid);
    if (e && !e->trusted && !path_is_pseudo_fs(oldpath) &&
        !path_is_pseudo_fs(newpath) && !path_is_rapid_write_noise(oldpath) &&
        !path_is_rapid_write_noise(newpath)) {
      /* Same true-sliding-window + distinct-source-file dedup pattern
       * as av_behavior_check_openat's write-open counter, just with
       * its own independent ring-buffer fields - see the struct
       * comment. Trust and cache/journal-shaped-path exemptions are
       * identical too: they skip ONLY this volume-based signal, the
       * sensitive-path check above still applies regardless. */
      u32 path_hash = full_name_hash(NULL, oldpath, strlen(oldpath));
      unsigned int in_window = sliding_window_note(
          path_hash, jiffies, RENAME_WINDOW_MS, e->recent_rename_hashes,
          e->recent_rename_jiffies, MAX_TRACKED_RENAMES,
          &e->recent_rename_next, &e->recent_rename_filled);

      if (in_window > RENAME_THRESHOLD)
        rapid = true;
    }
    mutex_unlock(&behavior_lock);
  }

  if (sensitive)
    kill_with_reason(target_pid, newpath, "rename involving sensitive path");
  else if (rapid)
    kill_with_reason(
        target_pid, newpath,
        "rapid extension-append renames (possible ransomware encryption pass)");
}

int av_behavior_init(void) {
  int ret;

  hash_init(behavior_table);
  hash_init(trust_table);
  hash_init(protected_table);

  ret = av_behavior_trust_proc_init();
  if (ret)
    return ret;

  ret = av_behavior_protect_proc_init();
  if (ret) {
    av_behavior_trust_proc_exit();
    return ret;
  }

  behavior_gc_wq = alloc_workqueue("kernel_av_behavior_gc", WQ_UNBOUND, 0);
  if (!behavior_gc_wq) {
    av_behavior_protect_proc_exit();
    av_behavior_trust_proc_exit();
    return -ENOMEM;
  }

  INIT_DELAYED_WORK(&behavior_gc_work, behavior_gc_fn);
  queue_delayed_work(behavior_gc_wq, &behavior_gc_work,
                     msecs_to_jiffies(GC_INTERVAL_MS));
  return 0;
}

void av_behavior_exit(void) {
  struct av_behavior_entry *e;
  struct hlist_node *tmp;
  int bkt;

  /* _sync so no gc_fn invocation can still be running (or queued to
   * run) once we start tearing down and freeing entries below. */
  cancel_delayed_work_sync(&behavior_gc_work);
  if (behavior_gc_wq) {
    destroy_workqueue(behavior_gc_wq);
    behavior_gc_wq = NULL;
  }

  mutex_lock(&behavior_lock);
  hash_for_each_safe(behavior_table, bkt, tmp, e, node) {
    hash_del(&e->node);
    kfree(e);
  }
  mutex_unlock(&behavior_lock);

  av_behavior_protect_proc_exit();
  protected_table_destroy();
  av_behavior_trust_proc_exit();
  trust_table_destroy();
}
