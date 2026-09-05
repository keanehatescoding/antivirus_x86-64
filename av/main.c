/*
 * main.c - av module entry point: kprobe on execve, workqueue-deferred
 * multi-algorithm hashing (MD5/SHA-1/SHA-256), lookup against the
 * runtime-managed signature table (sigtable.c), kill on match.
 *
 * ARCHITECTURE NOTE: kprobe pre-handlers run in an ATOMIC context - no
 * sleeping, no file I/O, no GFP_KERNEL. handler_pre() only copies the
 * exec path (GFP_ATOMIC) and schedules a work item; all file I/O,
 * hashing, and signature lookups happen in av_work_fn(), which runs in
 * a normal sleepable process context via a dedicated workqueue. See the
 * v0.1.0 changelog for the incident that made this non-negotiable: an
 * earlier version did the hashing directly in the kprobe handler and
 * corrupted kernel state on every execve.
 *
 * v0.2.0 changes from v0.1.0:
 *   - signatures are no longer hardcoded - they live in a kernel
 *     hashtable (sigtable.c), managed at runtime via
 *     /proc/kernel_av_signatures
 *   - hashes are computed for MD5, SHA-1, and SHA-256 in a single file
 *     read pass; a match on any one algorithm triggers a kill
 *
 * v0.3.0-prep changes:
 *   - added a Generic Netlink channel (netlink_chan.c) to a userspace
 *     daemon (avd). On a signature miss, the daemon gets a second look
 *     (stubbed as always-clean until the real YARA/heuristic logic
 *     lands in avd - see docs/netlink-protocol.md and
 *     userspace/avd/avd.c). Fail-open if no daemon is connected or it
 *     doesn't respond within DAEMON_TIMEOUT_MS.
 *
 * v0.8.0 changes: behavioral heuristics (behavior.c), back on the
 * kernel side after several userspace-only milestones. Three new
 * kprobe hooks - openat, unlink, unlinkat - follow the SAME atomic-
 * context discipline as the execve hook: pre-handlers only copy a
 * path string (GFP_ATOMIC) and schedule work; all logic (sensitive-
 * path matching, sliding-window counting, self-delete comparison,
 * the actual kill) happens in behavior.c, called from workqueue
 * context. Deliberately hooks openat (path directly available as a
 * user pointer) rather than write() (only gives an fd - resolving
 * that to a path from a DIFFERENT process's file table inside a
 * workqueue is a genuinely risky, version-fragile kernel API area
 * that this design avoids entirely).
 *
 * Later addition: rename/renameat/renameat2 hooks, closing a
 * previously-documented gap - ransomware's actual encryption-pass
 * signature is renaming files to add an extension (document.docx ->
 * document.docx.crypt), which none of the hooks above observed. Same
 * atomic-context discipline again: pre-handlers copy TWO path strings
 * and schedule work; av_behavior_check_rename() in behavior.c does
 * the actual extension-append-shape detection, sliding-window
 * counting, and sensitive-path check. See behavior.h/behavior.c and
 * README.md for the detection design.
 *
 * Build:   make
 * Load:    sudo insmod av.ko
 * Seed:    a default EICAR SHA-256 signature is added at module load
 *          (see av_init) so testing works out of the box; add more via
 *          /proc/kernel_av_signatures or the avctl CLI
 *          (userspace/avctl/).
 * Check:   dmesg | tail -20
 * Unload:  sudo rmmod av
 */

#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/dcache.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include "behavior.h"
#include "netlink_chan.h"
#include "netlink_proto.h"
#include "sigtable.h"

/* x86_64 only, for now (see CONTRIBUTING.md) - every hook below is
 * registered by hardcoded __x64_sys_* symbol name. On an arch using a
 * different wrapper naming (e.g. arm64's __arm64_sys_*), those symbols
 * don't exist: register_kprobe() would fail for each hook in turn and
 * av_init() unwinds and refuses to load, so this was never actually a
 * silent-inertness risk at runtime - but that failure mode only shows
 * up as a handful of "register_kprobe(execve) failed: -22" dmesg lines
 * with no indication of *why*, on a kernel someone spent real time
 * building this module against. Fail at compile time instead, with an
 * explicit reason, rather than letting a builder discover the
 * architecture mismatch via cryptic runtime errors. */
#ifndef CONFIG_X86_64
#error "av.ko is x86_64-only for now - it resolves __x64_sys_* symbols by name; porting to another arch means finding the equivalent wrapper symbols throughout, not just relaxing this check (see CONTRIBUTING.md)"
#endif

#define HOOKED_SYSCALL_NAME "__x64_sys_execve" /* see README re: arch */
#define HOOKED_SYSCALLAT_NAME                                                  \
  "__x64_sys_execveat" /* see README re: arch -                                \
                        * same x86_64-only caveat as                           \
                        * HOOKED_SYSCALL_NAME; the arm64                       \
                        * equivalent is __arm64_sys_execveat. */
#define READ_CHUNK_SIZE 4096
#define MAX_HASH_FILE_SIZE                                                     \
  (256 * 1024 * 1024) /* 256 MB cap on what                                    \
                       * hash_file_multi() will read - without                 \
                       * it, execve of a multi-GB binary hashes                \
                       * the whole thing inline in the worker,                 \
                       * and execve of a FIFO/device (which                    \
                       * fails in the exec syscall itself, but                 \
                       * still reaches record_exec's queued                    \
                       * work) blocks kernel_read() forever on                 \
                       * a FIFO with no writer. Neither is                     \
                       * fatal on its own, but both tie up a                   \
                       * workqueue thread indefinitely; see                    \
                       * the S_ISREG/i_size checks below. */
#define DAEMON_TIMEOUT_MS                                                      \
  12000 /* fail-open if the daemon doesn't answer                              \
         * in time - see docs/netlink-protocol.md                              \
         * for the fail-open vs fail-closed                                    \
         * discussion.                                                         \
         *                                                                     \
         * Was 2000: avd's own SCAN_TIMEOUT_SECS                               \
         * (avd.c) is 10s, so any scan taking                                  \
         * longer than 2s had its verdict                                      \
         * dropped as an "unknown/expired reqid"                               \
         * here regardless of what avd decided -                               \
         * the exec got killed by THIS timeout's                               \
         * fail-open path, and avd's 10s budget                                \
         * was effectively dead code. 12000ms                                  \
         * gives a couple seconds of headroom                                  \
         * over avd's real worst case rather                                   \
         * than matching it exactly, so a scan                                 \
         * that legitimately takes close to 10s                                \
         * still gets to deliver its verdict                                   \
         * instead of racing this timeout. */

static struct kprobe kp_execve = {
    .symbol_name = HOOKED_SYSCALL_NAME,
};
static struct kprobe kp_execveat = {
    .symbol_name = HOOKED_SYSCALLAT_NAME,
};
static struct kprobe kp_openat = {
    .symbol_name = "__x64_sys_openat",
};
static struct kprobe kp_unlink = {
    .symbol_name = "__x64_sys_unlink",
};
static struct kprobe kp_unlinkat = {
    .symbol_name = "__x64_sys_unlinkat",
};
static struct kprobe kp_rename = {
    .symbol_name = "__x64_sys_rename",
};
static struct kprobe kp_renameat = {
    .symbol_name = "__x64_sys_renameat",
};
static struct kprobe kp_renameat2 = {
    .symbol_name = "__x64_sys_renameat2",
};

static struct workqueue_struct *av_wq;

/* Bound on struct av_work / av_openat_work / av_unlink_work /
 * av_rename_work allocations currently in flight - kmalloc'd by a
 * kprobe *_pre handler in atomic context, not yet kfree'd by the
 * matching *_work_fn() once it runs on av_wq. Each of these structs
 * carries one or two PATH_MAX buffers, so with no cap here a fast
 * unlink/rename/openat storm (rm -rf on a big tree, a git checkout,
 * a container build, or an attacker's own loop) queues an unbounded
 * number of GFP_ATOMIC allocations - gigabytes off the atomic
 * reserves - before a single item is drained by the workqueue.
 * Past this bound, handlers fail open (skip the event, exec/open/
 * unlink/rename proceeds unobserved) rather than allocate further -
 * a handful of dropped behavioral events under extreme, sustained
 * load is a far smaller risk than exhausting atomic memory
 * system-wide, which affects every other kernel subsystem too. */
#define AV_MAX_INFLIGHT_WORK 4096
/* Slots reserved exclusively for execve/execveat: openat/unlink/
 * unlinkat/rename/renameat/renameat2 are capped at
 * (AV_MAX_INFLIGHT_WORK - AV_EXEC_RESERVED_WORK) via
 * av_work_admit_nonexec() below, so a burst of those (e.g. `rm -rf`
 * on a big tree) can never fully starve exec detection - exec always
 * has this much headroom to itself, on top of whatever the non-exec
 * hooks aren't currently using. One shared counter, not a separate
 * one per class: exec is still free to use the full budget when
 * non-exec traffic is quiet, it just can't be shut out entirely. */
#define AV_EXEC_RESERVED_WORK 512
static atomic_t av_inflight_work = ATOMIC_INIT(0);

/* Workqueue concurrency cap - see the comment beside its use in
 * av_init() below. A module param (not just a compile-time constant)
 * since the right value depends on the host's core count and how
 * bursty its exec/write workload is, which an operator shouldn't have
 * to rebuild the module to tune. Read-only: av_wq is created once at
 * module load from this value, so changing it after load wouldn't do
 * anything without also plumbing workqueue_set_max_active() through a
 * write callback - not worth the complexity for a knob this rarely
 * touched. Set it at `insmod`/modprobe.d time instead. */
#define AV_WQ_MAX_ACTIVE_DEFAULT 32
#define AV_WQ_MAX_ACTIVE_MIN 1
/* WQ_UNBOUND_MAX_ACTIVE (include/linux/workqueue.h) is the kernel's
 * own hard cap on an unbound workqueue's max_active - alloc_workqueue()
 * silently clamps anything above it down rather than erroring, so
 * accepting a wider range here would let an operator set a value this
 * module keeps reporting back via the module param while the
 * actually-effective cap was silently lower. This constant has moved
 * across kernel versions (512 for a long time, later bumped higher) -
 * referencing it directly, rather than hardcoding whatever number
 * today's kernel happens to define, means this bound always matches
 * whatever the kernel THIS MODULE WAS ACTUALLY BUILT AGAINST enforces,
 * regardless of version. */
#define AV_WQ_MAX_ACTIVE_MAX WQ_UNBOUND_MAX_ACTIVE
static int av_wq_max_active = AV_WQ_MAX_ACTIVE_DEFAULT;
module_param(av_wq_max_active, int, 0444);
MODULE_PARM_DESC(av_wq_max_active,
                 "Max concurrently-running kernel_av_wq workers (default 32; must be within [1, the kernel's own WQ_UNBOUND_MAX_ACTIVE ceiling], otherwise reset to the default)");

static inline bool av_work_admit_capped(unsigned int cap) {
  if (atomic_inc_return(&av_inflight_work) > cap) {
    atomic_dec(&av_inflight_work);
    return false;
  }
  return true;
}

/* Call before allocating a *_work struct in an execve/execveat *_pre
 * handler. Returns true if under the cap (caller may proceed to
 * kmalloc); false if at or over it (caller must skip the event
 * without allocating). Must be paired with exactly one
 * av_work_release() call on every path that follows a true return,
 * whether the *_pre handler bails out early afterward (validation
 * failure) or the work item runs to completion on the workqueue. */
static inline bool av_work_admit(void) {
  return av_work_admit_capped(AV_MAX_INFLIGHT_WORK);
}

/* Same contract as av_work_admit(), for the non-exec hooks (openat/
 * unlink/unlinkat/rename/renameat/renameat2) - capped short of the
 * full budget so those always leave AV_EXEC_RESERVED_WORK slots for
 * exec detection. */
static inline bool av_work_admit_nonexec(void) {
  return av_work_admit_capped(AV_MAX_INFLIGHT_WORK - AV_EXEC_RESERVED_WORK);
}

static inline void av_work_release(void) {
  atomic_dec(&av_inflight_work);
}

/* Resolves a syscall's `dfd` argument into a struct path suitable as
 * the base for a later relative-path lookup, mirroring the get_fs_pwd()
 * capture execve's handler_pre() already did. Callable from ATOMIC
 * (kprobe) context: AT_FDCWD is by far the common case (plain
 * openat/unlink/rename with no real base fd) and just reuses the same
 * cwd capture; a real fd only needs fget_raw() to look up the
 * descriptor table entry and bump its refcount - no I/O, no sleeping,
 * same atomic-safety class as get_fs_pwd(). Uses fget_raw()/fput()
 * rather than the newer fdget_raw()/fdput() struct-fd pair: the latter
 * isn't EXPORT_SYMBOL'd for out-of-tree modules on every kernel (it
 * modpost-failed as an undefined symbol on 7.1.6-cachyos), while
 * fget_raw() is the long-standing exported entry point for exactly
 * this "look up a file by fd, take a real reference" use case - same
 * underlying RCU/refcount lookup, just a plain struct file* instead of
 * struct fd. This is the fix for the
 * dfd-ignored evasion: openat(fd_for_/etc, "shadow", ...) previously
 * reached behavior.c as bare "shadow", which trivially bypassed every
 * sensitive-path check. `out` is populated with a path reference the
 * caller must path_put() - released in each work_fn's cleanup, same
 * lifetime discipline as av_work's existing pwd field. Returns false
 * (nothing to put) if dfd is a real fd but doesn't resolve to an open
 * file - e.g. a bogus/already-closed fd racing the syscall itself. */
static bool resolve_dfd_path(int dfd, struct path *out) {
  if (dfd == AT_FDCWD) {
    get_fs_pwd(current->fs, out);
    return true;
  }

  {
    struct file *f = fget_raw(dfd);

    if (!f)
      return false;

    *out = f->f_path;
    path_get(out);
    fput(f);
  }

  return true;
}
/* Lexically collapses "." / ".." components and duplicate '/'
 * separators in `path` (which must already start with '/'), rewriting
 * it in place. Pure string manipulation - matches what the shell/
 * kernel do lexically, not a filesystem operation: by the time
 * resolve_absolute_path() calls this the target may not exist yet
 * (rename()'s newpath, an O_CREAT openat target) or may be a symlink
 * unlink() must not follow, so this deliberately never touches the
 * filesystem or resolves symlinks. Its only job is making two
 * differently-spelled-but-lexically-identical paths (e.g.
 * "/cwd/./foo" and "/cwd/foo") compare equal via strcmp() - see the
 * self-delete correlation in behavior.c and the prefix/substring
 * matching referenced in resolve_absolute_path()'s comment below,
 * which this now actually delivers on. A ".." that would walk above
 * the leading "/" is dropped rather than treated as an error - same
 * as normal path semantics ("/.." collapses to "/"). On allocation
 * failure, leaves `path` as the unnormalized (pre-fix) string rather
 * than crashing or truncating it. */
static void normalize_abs_path(char *path, size_t path_len) {
  char *stack[128];
  int depth = 0;
  char *tmp, *saveptr, *tok;
  bool overflowed = false;

  tmp = kstrdup(path, GFP_KERNEL);
  if (!tmp)
    return;

  saveptr = tmp;
  while ((tok = strsep(&saveptr, "/")) != NULL) {
    if (tok[0] == '\0' || (tok[0] == '.' && tok[1] == '\0'))
      continue;
    if (tok[0] == '.' && tok[1] == '.' && tok[2] == '\0') {
      if (depth > 0)
        depth--;
      continue;
    }
    if (depth < ARRAY_SIZE(stack)) {
      stack[depth++] = tok;
    } else {
      /* Path has more components than we can track. Silently
       * dropping the excess would collapse two genuinely different
       * deep paths onto the same normalized string (e.g. two
       * distinct files under a shared >128-component prefix), which
       * downstream self-delete/trust checks treat as identity via
       * strcmp. Bail out instead of producing a lossy, potentially
       * colliding result - leave `path` untouched (still the
       * original, un-normalized string) so callers compare the real
       * path rather than a truncated stand-in. */
      overflowed = true;
      break;
    }
  }

  if (overflowed) {
    kfree(tmp);
    return;
  }

  path[0] = '\0';
  if (depth == 0)
    strlcat(path, "/", path_len);
  for (int i = 0; i < depth; i++) {
    strlcat(path, "/", path_len);
    strlcat(path, stack[i], path_len);
  }

  kfree(tmp);
}

/* Resolves `path` into a NUL-terminated absolute path string written
 * into `out` (capacity out_len), using `base` (captured by
 * resolve_dfd_path() above, in atomic context, back when `path` was
 * still meaningful relative to the calling process) when `path` itself
 * isn't already absolute. Must run from SLEEPABLE context - d_path()
 * can be called under most locks but the whole point here is to be
 * called from the workqueue, consistent with every other non-atomic-
 * safe operation in this file.
 *
 * Deliberately does NOT use vfs_path_lookup()/full canonicalization:
 * unlike open_exec_target() (which needs a real open fd and so must
 * fully resolve the target), rename's newpath and an O_CREAT openat
 * target may not exist yet, and unlink's target may be a symlink we
 * must NOT follow. Instead this resolves only the base directory (dfd)
 * to its absolute path via d_path() and string-concatenates the
 * (still possibly containing "." / ".." components) relative
 * remainder onto it. That's sufficient for behavior.c's prefix/
 * substring matching and exec_path self-delete comparison once
 * normalize_abs_path() (below) collapses those components - lexical
 * normalization only, not a canonical realpath() (no symlink
 * resolution, no filesystem access to confirm anything exists). On any
 * failure this falls back to copying `path` through unresolved rather
 * than dropping the event - a degraded (pre-fix) check on this one
 * call is better than silently skipping it. */
static void resolve_absolute_path(const char *path, const struct path *base,
                                  char *out, size_t out_len) {
  char *tmp;
  char *dirpath;

  /* AT_EMPTY_PATH sentinel - see handler_pre_execveat() and
   * open_exec_target() below. `path` is deliberately empty and `base`
   * IS the exec target itself (resolve_dfd_path() resolved dfd
   * directly to it, not to a directory `path` is relative to), so
   * resolve base's own path directly rather than treating this as
   * "empty relative component under base" (which would wrongly
   * concatenate a trailing "/" onto base's own path below). Every
   * OTHER caller's `path` is guaranteed non-empty (strncpy_from_user()
   * rejects a zero-length copy everywhere else - see handler_pre() and
   * friends), so an empty string is an unambiguous, safe sentinel for
   * this one case. */
  if (path[0] == '\0') {
    tmp = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!tmp) {
      out[0] = '\0';
      return;
    }
    dirpath = d_path(base, tmp, PATH_MAX);
    if (IS_ERR(dirpath))
      out[0] = '\0';
    else
      strscpy(out, dirpath, out_len);
    kfree(tmp);
    return;
  }

  if (path[0] == '/') {
    strscpy(out, path, out_len);
    normalize_abs_path(out, out_len);
    return;
  }

  tmp = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!tmp) {
    strscpy(out, path, out_len);
    return;
  }

  dirpath = d_path(base, tmp, PATH_MAX);
  if (IS_ERR(dirpath))
    strscpy(out, path, out_len);
  else {
    /* snprintf()'s return value is how many bytes WOULD have been
     * written absent truncation - checking it against out_len catches
     * silent truncation the assignment-and-move-on version above
     * couldn't. Two distinct, deeply-nested files whose combined
     * dirpath+path exceeds out_len would otherwise truncate to the
     * identical string, which self-delete correlation (a plain
     * strcmp() on this output) would then treat as the same file -
     * same lossy-result-is-dangerous reasoning as normalize_abs_path()'s
     * own >128-component bail-out above. Falling back to the
     * unresolved relative path (not absolute, but not truncated
     * either) matches this function's existing degraded-not-dropped
     * fallback stance for the d_path() failure case just above - it
     * doesn't fully rule out a collision between two different
     * fallback results, which is why av_behavior_check_unlink() in
     * behavior.c separately requires both sides of its self-delete
     * comparison to start with '/' before trusting a match; this
     * fallback deliberately never produces that.
     *
     * Known, accepted tradeoff: path_is_sensitive() in behavior.c
     * also runs against this output, and its "/boot/" prefix check
     * (and, in practice, its "/etc/passwd"-shaped substring checks
     * too, whenever the sensitive directory context lived in `dirpath`
     * rather than the trailing `path` component - the common shape
     * for this overflow case, e.g. a deeply nested ~/.ssh/... tree)
     * can no longer fire once `dirpath` is discarded here. Before this
     * truncation guard existed, the (collision-prone) truncated-but-
     * still-absolute result could still trigger that detection if the
     * sensitive segment survived truncation. There's no single output
     * string that's simultaneously safe for strcmp()-based identity
     * comparison AND guaranteed to retain sensitive-path context once
     * `dirpath` no longer fits - collision-safety was judged worth
     * more than sensitive-path recall in this narrow (approaching
     * PATH_MAX nesting depth), rarely-hit fallback, not a change made
     * without noticing the cost. */
    int need = snprintf(out, out_len, "%s/%s", dirpath, path);

    if (need < 0 || (size_t)need >= out_len)
      strscpy(out, path, out_len);
    else
      normalize_abs_path(out, out_len);
  }

  kfree(tmp);
}

struct av_work {
  struct work_struct work;
  struct pid *target_pid;
  pid_t tgid;      /* thread-group (process) ID - see the tgid-vs-pid note
                    * on av_openat_work below; captured here so
                    * av_behavior_record_exec() keys behavior state by
                    * process rather than by the individual thread that
                    * happened to call execve(). */
  u64 start_time;  /* current->start_time, captured here while still
                    * running in the exec'ing task's own context - see
                    * av_behavior_record_exec()'s comment for why this
                    * is needed to distinguish a genuine pid reuse from
                    * the same process exec'ing again. */
  struct path pwd; /* the exec'ing process's cwd at the moment
                    * handler_pre() ran, captured via get_fs_pwd()
                    * (atomic-safe: it's just a refcount bump under
                    * current->fs->lock, no I/O). A relative `path`
                    * below must be resolved against THIS, not
                    * against whatever the workqueue thread's own
                    * cwd happens to be by the time av_work_fn()
                    * runs - see open_exec_target(). Released with
                    * path_put() in av_work_fn()'s cleanup. */
  bool fail_closed; /* av_daemon_fail_closed, snapshotted here (kprobe
                     * time) rather than re-read in av_work_fn() at
                     * verdict time - see the policy-flip race note on
                     * av_daemon_fail_closed's own declaration below.
                     * Locks in "policy as of launch" semantics instead
                     * of "policy as of verdict", so an operator toggling
                     * fail-closed mid-flight can no longer retroactively
                     * kill an exec that was already committed under
                     * fail-open. */
  char path[PATH_MAX];
};

struct algo_ctx {
  const char *crypto_name;
  bool active;
  struct crypto_shash *tfm;
  struct shash_desc *desc;
  u8 *digest_bin;
  size_t digest_bin_len;
  char *digest_hex; /* points into the matching field of av_digest */
};

/* Captures the identity of the file that was ACTUALLY opened and
 * hashed by hash_file_multi(), so a signature/daemon verdict can be
 * logged against something more forensically specific than a path
 * string alone. This does NOT close the TOCTOU described on
 * av_work_fn() below - it's captured well after the real exec already
 * happened, from our own (possibly-already-raced) open - it just makes
 * a post-incident "was this really the file that ran" check possible
 * from the dmesg record instead of impossible. */
struct av_file_identity {
  dev_t dev;
  unsigned long ino;
  loff_t size;
};

static void bin_to_hex(const u8 *bin, size_t bin_len, char *hex_out) {
  size_t i;

  for (i = 0; i < bin_len; i++)
    snprintf(hex_out + i * 2, 3, "%02x", bin[i]);
  hex_out[bin_len * 2] = '\0';
}

/* Resolves and opens the exec target, honoring `path` as relative to
 * `pwd` (the calling process's cwd at exec time - see the av_work
 * comment) rather than to whatever directory this happens to run in.
 * Called from av_work_fn(), i.e. sleepable process context, so
 * vfs_path_lookup()'s potential I/O is fine here even though it would
 * not have been back in handler_pre().
 *
 * An absolute path needs no resolution against pwd at all (and pwd may
 * be garbage/unused in that case - filp_open() ignores it). This is
 * also why plain filp_open(path, ...) worked "by accident" for every
 * absolute-path exec: glibc's execvp() always resolves PATH lookups to
 * an absolute path before the actual execve() syscall, so this bug
 * only ever showed up for a program calling execve() directly with a
 * relative filename. */
static struct file *open_exec_target(const char *path, const struct path *pwd) {
  struct file *f;

  if (path[0] == '\0') {
    /* AT_EMPTY_PATH sentinel - see resolve_absolute_path()'s matching
     * comment and handler_pre_execveat() below. `pwd` IS the target
     * file itself here, already opened once by resolve_dfd_path()'s
     * fget_raw() back in the kprobe handler - dentry_open() opens a
     * fresh fd against that same dentry/mnt directly, no lookup at
     * all (there is nothing to look up: dfd already named the exact
     * file). */
    f = dentry_open(pwd, O_RDONLY, current_cred());
  } else if (path[0] == '/') {
    f = filp_open(path, O_RDONLY, 0);
  } else {
    struct path resolved;
    int err;

    err =
        vfs_path_lookup(pwd->dentry, pwd->mnt, path, LOOKUP_FOLLOW, &resolved);
    if (err)
      return ERR_PTR(err);

    f = dentry_open(&resolved, O_RDONLY, current_cred());
    path_put(&resolved);
  }

  return f;
}

/* Computes MD5, SHA-1, and SHA-256 of the file at `path` in a single
 * read pass. MUST be called from a sleepable (process) context only.
 * `ident_out` (optional, may be NULL) is filled in with the identity
 * of the file actually opened - see struct av_file_identity above and
 * the TOCTOU note on av_work_fn(). */
static int hash_file_multi(const char *path, const struct path *pwd,
                           struct av_digest *out,
                           struct av_file_identity *ident_out) {
  struct file *f;
  u8 md5_bin[16], sha1_bin[20], sha256_bin[32];
  /* SHA-256 is always computed - av_behavior_record_exec()'s
   * self-delete correlation and the netlink scan request to avd
   * both key on it unconditionally, regardless of what the sigtable
   * holds. MD5/SHA-1 exist purely to match against sigtable entries
   * of that algo, so skip computing them when the sigtable holds
   * none - wasted crypto work in the common case (SHA-256-only
   * signature DBs). */
  bool need_md5 = av_sigtable_algo_count(AV_ALGO_MD5) > 0;
  bool need_sha1 = av_sigtable_algo_count(AV_ALGO_SHA1) > 0;
  struct algo_ctx ctx[3] = {
      {"md5", need_md5, NULL, NULL, md5_bin, sizeof(md5_bin), out->md5},
      {"sha1", need_sha1, NULL, NULL, sha1_bin, sizeof(sha1_bin), out->sha1},
      {"sha256", true, NULL, NULL, sha256_bin, sizeof(sha256_bin), out->sha256},
  };
  void *buf = NULL;
  loff_t pos = 0;
  ssize_t n;
  int ret = 0;
  int i;

  /* Skipped algos' out->{md5,sha1} must not be left as uninitialized
   * stack garbage - av_sigtable_match() will still strlen()/hash
   * whatever's in there for every algo, even ones with zero entries
   * to match against, so an unterminated buffer here is a kernel
   * out-of-bounds read waiting to happen. */

  memset(out, 0, sizeof(*out));
  f = open_exec_target(path, pwd);
  if (IS_ERR(f))
    return PTR_ERR(f);

  /* Only hash regular files, and only up to MAX_HASH_FILE_SIZE - see
   * the macro comment. A FIFO/device/socket reaching here means the
   * execve() that triggered this work already failed for the caller
   * (you can't exec a FIFO), but av_work_fn() queued the work before
   * that failure was knowable, so we still have to guard against it
   * here rather than assume the caller filtered it out. */
  if (!S_ISREG(file_inode(f)->i_mode)) {
    ret = -EINVAL;
    goto out;
  }
  if (i_size_read(file_inode(f)) > MAX_HASH_FILE_SIZE) {
    ret = -EFBIG;
    goto out;
  }

  /* Identity of the file we're about to hash - captured here, right
   * after confirming it's a regular file we're actually going to
   * read, so it reflects the exact inode the digest below was
   * computed from. */
  if (ident_out) {
    struct inode *inode = file_inode(f);

    ident_out->dev = inode->i_sb->s_dev;
    ident_out->ino = inode->i_ino;
    ident_out->size = i_size_read(inode);
  }

  for (i = 0; i < 3; i++) {
    if (!ctx[i].active)
      continue;
    ctx[i].tfm = crypto_alloc_shash(ctx[i].crypto_name, 0, 0);
    if (IS_ERR(ctx[i].tfm)) {
      ret = PTR_ERR(ctx[i].tfm);
      ctx[i].tfm = NULL;
      goto out;
    }
    ctx[i].desc = kmalloc(
        sizeof(*ctx[i].desc) + crypto_shash_descsize(ctx[i].tfm), GFP_KERNEL);
    if (!ctx[i].desc) {
      ret = -ENOMEM;
      goto out;
    }
    ctx[i].desc->tfm = ctx[i].tfm;
    ret = crypto_shash_init(ctx[i].desc);
    if (ret)
      goto out;
  }

  buf = kmalloc(READ_CHUNK_SIZE, GFP_KERNEL);
  if (!buf) {
    ret = -ENOMEM;
    goto out;
  }

  while ((n = kernel_read(f, buf, READ_CHUNK_SIZE, &pos)) > 0) {
    /* The i_size_read() check above only bounds the size at open
     * time - a file that keeps growing while this loop reads it
     * (e.g. a shell script appending to itself; ETXTBSY only
     * protects an exec'd interpreter's own image, not a script file
     * it's reading) would otherwise let kernel_read() keep consuming
     * data forever, pinning this worker thread indefinitely. `pos`
     * is kernel_read()'s own running byte count, so re-checking it
     * against the same cap here catches that case the same way. */
    if (pos > MAX_HASH_FILE_SIZE) {
      ret = -EFBIG;
      goto out;
    }
    for (i = 0; i < 3; i++) {
      if (!ctx[i].active)
        continue;
      ret = crypto_shash_update(ctx[i].desc, buf, n);
      if (ret)
        goto out;
    }
  }
  if (n < 0) {
    ret = n;
    goto out;
  }

  for (i = 0; i < 3; i++) {
    if (!ctx[i].active)
      continue;
    ret = crypto_shash_final(ctx[i].desc, ctx[i].digest_bin);
    if (ret)
      goto out;
    bin_to_hex(ctx[i].digest_bin, ctx[i].digest_bin_len, ctx[i].digest_hex);
  }

out:
  kfree(buf);
  for (i = 0; i < 3; i++) {
    kfree(ctx[i].desc);
    if (ctx[i].tfm)
      crypto_free_shash(ctx[i].tfm);
  }
  filp_close(f, NULL);
  return ret;
}

/* ---- operator-configurable daemon-unavailable policy ----
 *
 * See docs/netlink-protocol.md's fail-open/fail-closed discussion:
 * when av_netlink_scan_request() below returns non-zero (no daemon
 * registered, or it didn't answer within DAEMON_TIMEOUT_MS), the
 * original design always failed open (let the exec proceed, log it
 * as such) on the reasoning that avd crashing/restarting shouldn't
 * itself become a denial-of-service against every unsigned exec on
 * the system. That's still the default (0 = fail-open) - this only
 * makes it a runtime choice instead of a fixed one, for an operator
 * who'd rather block on "no verdict" than risk letting something
 * through unscanned (a hardened/high-assurance deployment, e.g.).
 * Plain atomic_t, not a mutex-guarded value: it's a single word read
 * on every daemon-path exec and written rarely (an operator toggling
 * it), so atomic load/store is both sufficient and cheaper than a
 * lock for this access pattern.
 *
 * TIMING NOTE, and the fix for it: this flag used to be read directly
 * inside av_work_fn() below - i.e. asynchronously, whenever that
 * exec's workqueue item happened to run - rather than captured at the
 * kprobe/exec moment itself. That meant an exec that started (and was
 * allowed past the kprobe) while this was still fail-open could still
 * be killed if an operator flipped it to fail-closed before that
 * specific exec's work item was processed - the process saw the
 * policy as of *verdict* time, not launch time, and that window grew
 * with workqueue backlog. handler_pre()/handler_pre_execveat() now
 * snapshot this into struct av_work's fail_closed field at kprobe
 * time instead, so av_work_fn() enforces the policy that was in
 * effect when the exec was actually observed - flipping this
 * interactively no longer risks retroactively killing execs (including
 * your own shell's) that already committed under the old policy. */
static atomic_t av_daemon_fail_closed = ATOMIC_INIT(0);

static int daemon_policy_proc_show(struct seq_file *m, void *v) {
  seq_printf(m, "%s\n",
             atomic_read(&av_daemon_fail_closed) ? "fail-closed" : "fail-open");
  return 0;
}

static int daemon_policy_proc_open(struct inode *inode, struct file *file) {
  return single_open(file, daemon_policy_proc_show, NULL);
}

/* Small, fixed-vocabulary write ("fail-open" or "fail-closed" plus a
 * trailing newline) - same terminator-required convention as
 * protected_proc_write() in behavior.c, for the same reason (a
 * mandatory trailing newline is what actually distinguishes a
 * complete write from a truncated first chunk of a larger one, not
 * just the size cap alone). ppos is only read here, but proc_write
 * must match struct proc_ops's fixed non-const loff_t * signature
 * exactly - same class of false positive as protected_proc_write()'s
 * own identical suppression. */
/* cppcheck-suppress constParameterCallback */
static ssize_t daemon_policy_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
  char kbuf[32];
  size_t len;

  if (*ppos != 0)
    return -EINVAL;
  if (count >= sizeof(kbuf))
    return -EINVAL;
  if (copy_from_user(kbuf, ubuf, count))
    return -EFAULT;
  kbuf[count] = '\0';

  len = strlen(kbuf);
  if (len == 0 || kbuf[len - 1] != '\n')
    return -EINVAL;
  kbuf[--len] = '\0';
  if (len > 0 && kbuf[len - 1] == '\r')
    kbuf[--len] = '\0';

  /* Compare the fully trimmed buffer directly, not just its first
   * whitespace-delimited token (an earlier sscanf(kbuf, "%15s", ...)
   * version parsed only the first token, so a write like
   * "fail-closed unexpected\n" silently enabled fail-closed instead
   * of being rejected - this keeps the proc interface's documented
   * fixed-vocabulary contract actually enforced). */
  if (!strcasecmp(kbuf, "fail-open")) {
    atomic_set(&av_daemon_fail_closed, 0);
  } else if (!strcasecmp(kbuf, "fail-closed")) {
    atomic_set(&av_daemon_fail_closed, 1);
  } else {
    return -EINVAL;
  }

  pr_info("kernel-av: daemon-unavailable policy set to %s\n", kbuf);
  return count;
}

static const struct proc_ops daemon_policy_proc_ops = {
    .proc_open = daemon_policy_proc_open,
    .proc_read = seq_read,
    .proc_write = daemon_policy_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *daemon_policy_proc_entry;

/* Shared kill-and-log helper, mirroring behavior.c's kill_with_reason -
 * see its comment for why the PID-1 guard is unconditional and
 * non-negotiable regardless of what triggered detection.
 *
 * v1.0.0-merge: structured key=value log format (event=... type=...
 * etc.) instead of free-form sentences, so dmesg output is grep/awk-
 * parseable for any future log aggregation. Kept on one line per
 * event deliberately. */
static void av_kill(struct pid *target_pid, const char *path, const char *type,
                    const char *reason, const struct av_file_identity *ident) {
  struct task_struct *task;
  /* PATH_MAX (4096) is far too large for the kernel stack - heap-
   * allocate rather than declare a PATH_MAX array here, same reasoning
   * as kill_with_reason()'s identical pattern in behavior.c. Sleepable
   * context (workqueue), GFP_KERNEL is fine. A kmalloc failure just
   * drops the protected-exe path from the log line, not the check
   * itself - av_behavior_target_is_protected() tolerates NULL path_out. */
  char *protected_path = kmalloc(PATH_MAX, GFP_KERNEL);

  if (pid_nr(target_pid) == 1) {
    pr_alert("kernel-av: event=suppressed action=none type=%s "
             "path=\"%s\" reason=\"%s\" pid=1\n",
             type, path, reason);
    kfree(protected_path);
    return;
  }

  /* See behavior.h's comment on av_behavior_target_is_protected() -
   * an operator-managed allow-list, same suppressed-not-skipped
   * treatment as the PID-1 guard above. */
  if (av_behavior_target_is_protected(target_pid, protected_path, PATH_MAX)) {
    pr_alert("kernel-av: event=suppressed action=none type=%s "
             "path=\"%s\" reason=\"%s\" pid=%d protected_exe=\"%s\"\n",
             type, path, reason, pid_nr(target_pid),
             protected_path ? protected_path : "?");
    kfree(protected_path);
    return;
  }
  kfree(protected_path);

  rcu_read_lock();
  task = pid_task(target_pid, PIDTYPE_PID);
  if (task) {
    /* The only current callers always pass &ident (a local struct,
     * never NULL) - but av_kill() takes a pointer and this is a
     * module that SIGKILLs things, so a cheap guard against a future
     * caller passing NULL (or ident becoming optional) is worth it
     * over a kernel NULL-deref here. Falls back to a log line
     * without the dev/ino/size identity fields rather than skipping
     * the kill - inconclusive identity info doesn't mean don't act
     * on the type/reason that got us to av_kill() in the first
     * place. */
    if (ident) {
      pr_alert(
          "kernel-av: event=detected action=kill type=%s "
          "path=\"%s\" reason=\"%s\" pid=%d dev=%u:%u ino=%lu size=%lld\n",
          type, path, reason, pid_nr(target_pid), MAJOR(ident->dev),
          MINOR(ident->dev), ident->ino, (long long)ident->size);
    } else {
      pr_alert("kernel-av: event=detected action=kill type=%s "
               "path=\"%s\" reason=\"%s\" pid=%d\n",
               type, path, reason, pid_nr(target_pid));
    }
    send_sig(SIGKILL, task, 0);
  }
  rcu_read_unlock();
}

/* Runs in a kernel worker thread - safe to sleep, do file I/O, use
 * GFP_KERNEL. This is where all "heavy" work happens.
 *
 * KNOWN TOCTOU (see review item #3 / README): by the time this runs,
 * the real execve() already completed and the target process is
 * already running - the kernel resolved and mapped ITS OWN copy of
 * the executable well before this workqueue item was even scheduled.
 * hash_file_multi() below does a SEPARATE, LATER open of `aw->path`
 * (resolved against the cwd captured back in handler_pre() - see
 * av_work's pwd field) to compute a hash for the signature/daemon
 * check. Nothing guarantees these are the same inode: an attacker who
 * can win the race (replace the file, or repoint a symlink in the
 * path, between the real exec and this open) can make the signature
 * check run against a swapped-in decoy while their actual malicious
 * code is already executing, undetected. This is inherent to the
 * defer-to-workqueue design (see the ARCHITECTURE NOTE at the top of
 * this file - hashing can't happen in the atomic kprobe path) and
 * can't be closed from a kprobe on the syscall boundary; genuinely
 * closing it means moving to a hook with access to the kernel's own
 * already-resolved struct file for the exec (e.g. an LSM
 * bprm_check_security hook), which is a real redesign, not a patch.
 * Two things this file does instead, short of that redesign: (1)
 * av_file_identity below records exactly which inode was hashed, so a
 * post-incident dmesg review can at least tell whether that inode
 * still matches what's on disk; (2) O_NOFOLLOW was deliberately NOT
 * added to open_exec_target() - it would only guard the narrow case
 * where the final path component itself is a symlink, at the cost of
 * breaking hashing for every LEGITIMATELY symlinked binary (/usr/bin/
 * python and friends), while doing nothing for a same-path file
 * replacement, which is the more general form of this race. */
static void av_work_fn(struct work_struct *w) {
  struct av_work *aw = container_of(w, struct av_work, work);
  struct av_digest digest;
  struct av_file_identity ident;
  char sig_name[AV_SIG_NAME_LEN];
  char reason[AV_SIG_NAME_LEN + 32];
  char *abs_path;
  int ret;

  /* hash_file_multi()/open_exec_target() already resolve a relative
   * aw->path against aw->pwd correctly for the purpose of opening the
   * right file. But what gets RECORDED as this process's exec_path
   * (for the unlink hook's self-delete comparison, av_behavior_check_
   * unlink()) was still the raw, possibly-relative string - so
   * `./payload` exec'd and `payload` unlinked from the same cwd never
   * matched. Resolve once here so exec_path and the (now also
   * resolved - see resolve_dfd_path()/resolve_absolute_path() above)
   * unlink path are directly comparable strings. */
  abs_path = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!abs_path) {
    path_put(&aw->pwd);
    put_pid(aw->target_pid);
    kfree(aw);
    av_work_release();
    return;
  }
  resolve_absolute_path(aw->path, &aw->pwd, abs_path, PATH_MAX);

  ret = hash_file_multi(aw->path, &aw->pwd, &digest, &ident);
  if (ret) {
    /* Couldn't open/hash it (permissions, already gone, etc.) -
     * not the job of the signature path, just skip. */
    goto out;
  }

  /* Record regardless of verdict below - if this process gets killed
   * immediately it'll never reach the unlink hook anyway, and this
   * keeps the recording logic in one place rather than duplicated
   * across the signature-match/daemon-match/clean branches. */
  av_behavior_record_exec(aw->tgid, abs_path, digest.sha256, aw->start_time);

  if (av_sigtable_match(&digest, sig_name, sizeof(sig_name))) {
    snprintf(reason, sizeof(reason), "signature:%s", sig_name);
    av_kill(aw->target_pid, abs_path, "signature", reason, &ident);
    goto out;
  }

  /* No signature match - ask the userspace daemon (avd) for a second
   * opinion (YARA/heuristics, once those land in v0.3.0+). Fail-open:
   * if there's no daemon connected or it doesn't answer in time, we
   * fall through and log clean rather than blocking exec indefinitely
   * or killing on inconclusive information. See docs/netlink-protocol.md. */
  {
    int verdict = AV_VERDICT_CLEAN;
    char rule_name[AV_RULE_NAME_MAXLEN + 1] = "";
    int nl_ret;

    nl_ret = av_netlink_scan_request(
        abs_path, digest.sha256, pid_nr(aw->target_pid), &verdict, rule_name,
        sizeof(rule_name), DAEMON_TIMEOUT_MS);
    if (nl_ret == 0 && verdict == AV_VERDICT_MALICIOUS) {
      snprintf(reason, sizeof(reason), "daemon:%s", rule_name);
      av_kill(aw->target_pid, abs_path, "daemon", reason, &ident);
    } else if (nl_ret == 0) {
      /* pr_info_ratelimited, not plain pr_info: this fires for
       * every exec that reaches the daemon path (i.e. every
       * clean, non-signature-matched exec on the system), which
       * used to mean an unconditional dmesg line per exec.
       * Deliberately NOT pr_debug_ratelimited - that would make
       * it a silent no-op by default (needs CONFIG_DYNAMIC_DEBUG
       * enabled per call site, which this project doesn't set
       * up anywhere, and would also break test_detection.sh's
       * dmesg grep for this exact line below). _ratelimited()
       * keeps it visible at its current pr_info level while
       * capping it to the kernel's default rate limit
       * (10 msgs/5s) instead of one line per exec. */
      pr_info_ratelimited("kernel-av: event=clean type=daemon path=\"%s\" "
                          "pid=%d md5=%s sha1=%s sha256=%s dev=%u:%u ino=%lu\n",
                          abs_path, pid_nr(aw->target_pid), digest.md5,
                          digest.sha1, digest.sha256, MAJOR(ident.dev),
                          MINOR(ident.dev), ident.ino);
    } else if (aw->fail_closed) {
      /* Operator had opted into fail-closed via
       * /proc/kernel_av_daemon_policy as of THIS exec's kprobe time
       * (see the policy comment above av_daemon_fail_closed's
       * declaration for why that's aw->fail_closed and not a fresh
       * atomic_read() here) - -ENOTCONN/-ETIMEDOUT/other error is
       * treated as "no verdict, don't trust it" rather than "clean".
       * Goes through the same av_kill() as every other kill path, so
       * it still respects the PID-1 guard and the operator-managed
       * protected-path allow-list - fail-closed mode changes what
       * "inconclusive" means, not those existing safety rails. */
      snprintf(reason, sizeof(reason), "no-verdict:err=%d", nl_ret);
      av_kill(aw->target_pid, abs_path, "fail-closed", reason, &ident);
    } else {
      /* -ENOTCONN (no daemon), -ETIMEDOUT, or another error -
       * fail open (the default - see the policy comment above this
       * function), but log distinctly so this is visible/greppable
       * separately from a genuine daemon-confirmed clean verdict.
       * Same pr_info_ratelimited reasoning as above. */
      pr_info_ratelimited("kernel-av: event=clean type=fail-open path=\"%s\" "
                          "pid=%d md5=%s sha1=%s sha256=%s err=%d\n",
                          abs_path, pid_nr(aw->target_pid), digest.md5,
                          digest.sha1, digest.sha256, nl_ret);
    }
  }

out:
  kfree(abs_path);
  path_put(&aw->pwd);
  put_pid(aw->target_pid);
  kfree(aw);
  av_work_release();
}

/* Atomic context - the ONLY things allowed here: copying small amounts
 * of data with GFP_ATOMIC, reading regs, and scheduling work.
 *
 * KNOWN GAP - COLD-PATHNAME BYPASS (found via tests/qemu-boot/,
 * tracked by tests/qemu-boot/cold_launcher.c's dedicated regression
 * case, not previously documented): strncpy_from_user() below runs in
 * this atomic/kprobe context, so it can't sleep to fault in a
 * userspace page that isn't resident yet - it fails fast with -EFAULT
 * instead, and this handler then returns 0 without hashing/killing
 * (silent skip, same as any other early-bail path here). The real
 * execve() syscall's own later, in-process getname_flags() call on
 * the exact same pointer runs in normal sleepable context and CAN
 * fault the page in, which is why the syscall itself still proceeds
 * normally either way - only this kprobe's earlier copy can lose that
 * race.
 *
 * Unlike this file's other risk-reduction-not-elimination notes (e.g.
 * Has_RWX_Segment's scope note, or the quarantine TOCTOU note in
 * avd.c), this one is NOT a narrow timing race that needs a
 * well-positioned attacker to exploit - it's deterministically
 * reproducible by any process whose exec's pathname argument has
 * simply never been touched before, e.g. a freshly execve()'d static
 * binary whose entire body is "exec this literal path, nothing else
 * first" (exactly what cold_launcher.c is, and 100% reliable in
 * testing). A real shell essentially never hits this by accident -
 * too much prior memory activity for anything to still be a cold page
 * by the time it calls execve() - but a deliberately minimal launcher
 * doesn't need to work hard to trigger it on purpose.
 *
 * Considered and NOT done here:
 *   - Deferring the copy entirely to av_work_fn() (sleepable
 *     workqueue context) doesn't work: by the time that runs, a
 *     successful exec has already replaced this process's address
 *     space, so there's nothing left to copy from.
 *   - Failing closed (kill on -EFAULT) trades this for a new,
 *     meaningful false-positive class: -EFAULT alone can't
 *     distinguish "genuinely cold but valid page" from "actually bad
 *     pointer" (the latter would fail the real exec too, so killing
 *     there is harmless; the former would have execve()'d
 *     successfully and harmlessly, so killing it is a real false
 *     positive) - and "cold pathname page" is not exotic for
 *     legitimate minimal/embedded/statically-linked launchers, not
 *     just malicious ones.
 *   - A different hook mechanism entirely (e.g. an LSM
 *     security_bprm_check hook, which runs in normal sleepable
 *     context) would close this properly, but is a much larger
 *     architectural change than fits alongside adding a CI job.
 * Closing this for real needs one of those (or something better),
 * with more thought than fits here - tracked, not silently left
 * unverified: see the regression case's comment for how it stays
 * visible in every CI run instead. */
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
  const struct pt_regs *real_regs = (struct pt_regs *)regs->di;
  const char __user *user_filename;
  struct av_work *aw;

  if (!real_regs)
    return 0;

  user_filename = (const char __user *)real_regs->di;
  if (!user_filename)
    return 0;

  if (!av_work_admit())
    return 0;

  aw = kmalloc(sizeof(*aw), GFP_ATOMIC);
  if (!aw) {
    av_work_release();
    return 0;
  }

  /* strncpy_from_user() returns the copied length (excluding NUL) on
   * success, a negative errno on fault - but if the source string is
   * >= PATH_MAX bytes, it returns exactly PATH_MAX with NO guarantee
   * the destination is NUL-terminated. Checking only "<= 0" lets that
   * truncation case through as "success", leaving aw->path as a
   * non-NUL-terminated buffer that filp_open()/strcmp()/strstr()
   * further down would read past. Reject anything that fills the
   * whole buffer, not just outright failures. */
  {
    ssize_t path_len = strncpy_from_user(aw->path, user_filename, PATH_MAX);

    if (path_len <= 0 || path_len >= PATH_MAX) {
      kfree(aw);
      av_work_release();
      return 0;
    }
  }

  aw->target_pid = get_task_pid(current, PIDTYPE_PID);
  aw->tgid = task_tgid_nr(current);
  aw->start_time = current->start_time;
  aw->fail_closed = atomic_read(&av_daemon_fail_closed);
  /* get_fs_pwd() takes fs->lock and bumps refcounts under it - no
   * sleeping, so this is fine in this atomic kprobe context. This is
   * the fix for the relative-path evasion: capture the calling
   * process's cwd HERE, while we're still running in its context,
   * so a relative aw->path can be resolved correctly later even
   * though av_work_fn() runs on a workqueue thread with an unrelated
   * cwd of its own. Released via path_put() in av_work_fn(). */
  get_fs_pwd(current->fs, &aw->pwd);
  INIT_WORK(&aw->work, av_work_fn);
  queue_work(av_wq, &aw->work);

  return 0;
}
/* execveat(2): int execveat(int dirfd, const char *pathname,
 * char *const argv[], char *const envp[], int flags). x86_64 syscall
 * argument order puts dirfd in the first slot (real_regs->di) and
 * pathname in the second (real_regs->si) - same slot pattern as
 * openat's dfd/filename below, NOT the same as execve's filename-only
 * first slot. Reuses struct av_work / av_work_fn unchanged: the only
 * difference from handler_pre() is that the base directory for a
 * relative pathname comes from resolving `dirfd` (AT_FDCWD or a real
 * fd, via resolve_dfd_path() - see openat/unlink for the identical
 * pattern) instead of unconditionally being the calling process's cwd.
 *
 * Without this hook, execveat() was a complete bypass of every
 * exec-based check: no hash/signature match, no daemon scan, and no
 * av_behavior_record_exec() call - so the self-delete heuristic lost
 * its exec_path key for anything launched this way too. This is the
 * syscall containers, some language runtimes, and memfd_create()+
 * execveat() fileless-exec loaders actually use, so it's not a
 * theoretical gap.
 *
 * AT_EMPTY_PATH (flags argument, real_regs->r8) IS special-cased, but
 * only when the pathname is ALSO actually empty: per execveat(2), an
 * empty pathname with AT_EMPTY_PATH set means dfd names the target
 * file directly (typically an anonymous memfd) - exactly the
 * fileless-exec shape this hook exists to close. `dfd` has already
 * been resolved to the target's own struct path by resolve_dfd_path()
 * above (there is no separate "directory" to look a name up under -
 * dfd already names the whole target), so aw->path is set to the
 * empty-string sentinel in that case (see resolve_absolute_path()'s
 * and open_exec_target()'s matching comments in this file).
 *
 * AT_EMPTY_PATH set together with a NON-empty pathname is NOT that
 * case, though, and must not be treated as one: per execveat(2), the
 * flag only changes anything when the pathname is empty - a non-empty
 * pathname is resolved exactly as it would be without the flag
 * (relative to dfd, or absolute), and that resolution succeeds
 * normally. Bailing out here on that combination (as an earlier
 * version of this hook did, prompted by a review comment that assumed
 * the syscall fails in that case) would have made AT_EMPTY_PATH a
 * free detection bypass: set the flag on an otherwise-ordinary
 * dfd-relative execveat() and this hook skips scanning entirely while
 * the kernel executes the file anyway. So the only combination that's
 * actually invalid - and skipped below - is an empty pathname WITHOUT
 * AT_EMPTY_PATH (generic path resolution rejects a zero-length name
 * unless LOOKUP_EMPTY is set, so that syscall fails with ENOENT and
 * there is nothing to scan). Every other combination copies the real
 * pathname into aw->path and proceeds - empty+flag through the
 * sentinel branch above, non-empty (flag or not) through the normal
 * relative/absolute resolution every other pathname-taking hook in
 * this file already uses.
 *
 * Shares handler_pre()'s cold-pathname bypass (see that function's
 * comment): the strncpy_from_user() call(s) below run in this same
 * atomic/kprobe context and can silently skip a pathname argument
 * whose page isn't resident yet, for the same reasons and with the
 * same considered-and-rejected fix directions. Not independently
 * tracked by a separate cold_launcher.c case - it's the same
 * underlying mechanism, one write-up covers both call sites. */
static int handler_pre_execveat(struct kprobe *p, struct pt_regs *regs) {
  const struct pt_regs *real_regs = (struct pt_regs *)regs->di;
  const char __user *user_filename;
  struct av_work *aw;
  struct path base;
  int dfd;
  bool empty_path;

  if (!real_regs)
    return 0;

  user_filename = (const char __user *)real_regs->si;
  if (!user_filename)
    return 0;

  dfd = (int)real_regs->di;
  empty_path = ((unsigned int)real_regs->r8 & AT_EMPTY_PATH) != 0;

  /* Resolve dfd BEFORE allocating/copying anything else - same
   * ordering as handler_pre_openat() and for the same reason: a
   * bogus/already-closed fd racing the syscall leaves nothing
   * useful to queue work for. */
  if (!resolve_dfd_path(dfd, &base))
    return 0;

  if (!av_work_admit()) {
    path_put(&base);
    return 0;
  }

  aw = kmalloc(sizeof(*aw), GFP_ATOMIC);
  if (!aw) {
    path_put(&base);
    av_work_release();
    return 0;
  }
  aw->pwd = base;

  {
    /* Copy unconditionally - a non-empty pathname is scanned via the
     * normal relative/absolute branch below regardless of empty_path
     * (see the doc comment above: AT_EMPTY_PATH only changes anything
     * when the pathname is actually empty). The only combination
     * that's genuinely invalid is an empty pathname WITHOUT
     * AT_EMPTY_PATH - that syscall fails with ENOENT before doing
     * anything, so dfd must not be scanned/killed over it. */
    ssize_t path_len = strncpy_from_user(aw->path, user_filename, PATH_MAX);

    if (path_len < 0 || path_len >= PATH_MAX ||
        (path_len == 0 && !empty_path)) {
      path_put(&aw->pwd);
      kfree(aw);
      av_work_release();
      return 0;
    }
  }

  aw->target_pid = get_task_pid(current, PIDTYPE_PID);
  aw->tgid = task_tgid_nr(current);
  aw->start_time = current->start_time;
  aw->fail_closed = atomic_read(&av_daemon_fail_closed);
  INIT_WORK(&aw->work, av_work_fn);
  queue_work(av_wq, &aw->work);

  return 0;
}

/* ---- openat: write-intent open tracking (rapid modification +
 * sensitive-path-write heuristics) ---- */

struct av_openat_work {
  struct work_struct work;
  struct pid *target_pid;
  pid_t pid; /* actually the tgid (thread-group/process ID), not the
              * calling thread's individual pid - see task_tgid_nr()
              * below. behavior.c's tracking table is keyed by this
              * value, and current->pid is the kernel's per-THREAD
              * id: keying by it let a multi-threaded process evade
              * the rapid-write-open threshold by simply spreading
              * writes across threads, since each thread got its own
              * independent counter. */
  int flags;
  struct path base; /* dfd resolved to a struct path at kprobe time -
                     * see resolve_dfd_path(). `path` below is
                     * resolved against THIS in av_openat_work_fn(),
                     * not against whatever cwd the workqueue thread
                     * happens to have - same reasoning as av_work's
                     * pwd field. Released via path_put() in
                     * av_openat_work_fn()'s cleanup. */
  char path[PATH_MAX];
};

static void av_openat_work_fn(struct work_struct *w) {
  struct av_openat_work *ow = container_of(w, struct av_openat_work, work);
  char *abs_path = kmalloc(PATH_MAX, GFP_KERNEL);

  if (!abs_path) {
    path_put(&ow->base);
    put_pid(ow->target_pid);
    kfree(ow);
    av_work_release();
    return;
  }

  resolve_absolute_path(ow->path, &ow->base, abs_path, PATH_MAX);
  av_behavior_check_openat(ow->pid, abs_path, ow->flags, ow->target_pid);

  kfree(abs_path);
  path_put(&ow->base);
  put_pid(ow->target_pid);
  kfree(ow);
  av_work_release();
}

/* openat(int dfd, const char *filename, int flags, umode_t mode) - on
 * the x86_64 syscall ABI, dfd is the FIRST argument (regs->di) and
 * filename is the SECOND (regs->si), unlike execve where the filename
 * is the first (regs->di). Getting this register mapping wrong is a
 * silent, hard-to-notice bug (you'd just never see openat events, no
 * crash) - verify with a kprobe_log-style dmesg print if this hook
 * seems to never fire.
 *
 * dfd is now captured and resolved (resolve_dfd_path()) rather than
 * ignored: a bare filename is only ever cwd-relative when dfd ==
 * AT_FDCWD - openat(fd_for_some_other_dir, "shadow", ...) is relative
 * to THAT fd's directory, and treating it as cwd-relative (or, as
 * before this fix, not resolving it at all) let a caller reach
 * /etc/shadow while behavior.c only ever saw the bare string
 * "shadow". */
static int handler_pre_openat(struct kprobe *p, struct pt_regs *regs) {
  const struct pt_regs *real_regs = (struct pt_regs *)regs->di;
  const char __user *user_filename;
  int dfd;
  int flags;
  struct av_openat_work *ow;
  struct path base;

  if (!real_regs)
    return 0;

  user_filename = (const char __user *)real_regs->si;
  if (!user_filename)
    return 0;

  dfd = (int)real_regs->di;
  flags = (int)real_regs->dx;
  /* Skip the allocation/copy entirely for read-only opens - this is
   * the overwhelming majority of opens on a normal system, and
   * filtering here (still atomic-safe - just an integer test) avoids
   * scheduling work for events behavior.c would discard anyway. */
  if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
    return 0;

  /* Resolve dfd BEFORE allocating/copying anything else - if the fd
   * doesn't resolve (bogus/racing close) there's nothing useful to
   * queue work for. */
  if (!resolve_dfd_path(dfd, &base))
    return 0;

  if (!av_work_admit_nonexec()) {
    path_put(&base);
    return 0;
  }

  ow = kmalloc(sizeof(*ow), GFP_ATOMIC);
  if (!ow) {
    path_put(&base);
    av_work_release();
    return 0;
  }
  ow->base = base;

  {
    ssize_t path_len = strncpy_from_user(ow->path, user_filename, PATH_MAX);

    if (path_len <= 0 || path_len >= PATH_MAX) {
      path_put(&ow->base);
      kfree(ow);
      av_work_release();
      return 0;
    }
  }

  ow->flags = flags;
  ow->pid = task_tgid_nr(current);
  ow->target_pid = get_task_pid(current, PIDTYPE_PID);
  INIT_WORK(&ow->work, av_openat_work_fn);
  queue_work(av_wq, &ow->work);

  return 0;
}

/* ---- unlink/unlinkat: self-delete + sensitive-path-deletion ---- */

struct av_unlink_work {
  struct work_struct work;
  struct pid *target_pid;
  pid_t pid;        /* tgid, not thread pid - see the note on av_openat_work
                     * above; self-delete correlation against exec_path
                     * needs to match the same key av_behavior_record_exec()
                     * used. */
  struct path base; /* dfd resolved at kprobe time - see
                     * resolve_dfd_path(). For plain unlink() (no
                     * dfd arg) this is always the cwd capture, same
                     * as AT_FDCWD would give unlinkat(). Released
                     * via path_put() in av_unlink_work_fn(). */
  char path[PATH_MAX];
};

static void av_unlink_work_fn(struct work_struct *w) {
  struct av_unlink_work *uw = container_of(w, struct av_unlink_work, work);
  char *abs_path = kmalloc(PATH_MAX, GFP_KERNEL);

  if (!abs_path) {
    path_put(&uw->base);
    put_pid(uw->target_pid);
    kfree(uw);
    av_work_release();
    return;
  }

  resolve_absolute_path(uw->path, &uw->base, abs_path, PATH_MAX);
  av_behavior_check_unlink(uw->pid, abs_path, uw->target_pid);

  kfree(abs_path);
  path_put(&uw->base);
  put_pid(uw->target_pid);
  kfree(uw);
  av_work_release();
}

/* `dfd` should be AT_FDCWD for plain unlink() (no base fd of its own -
 * always cwd-relative) or the real dfd argument for unlinkat(). Same
 * dfd-ignored evasion fix as openat: unlinkat(fd_for_/etc, "shadow", 0)
 * previously reached behavior.c as bare "shadow", so it could never
 * match /etc/shadow's sensitive-path check, and could never correlate
 * against an exec_path recorded as an absolute path either. */
static int schedule_unlink_work(const char __user *user_path, int dfd) {
  struct av_unlink_work *uw;
  struct path base;

  if (!user_path)
    return 0;

  if (!resolve_dfd_path(dfd, &base))
    return 0;

  if (!av_work_admit_nonexec()) {
    path_put(&base);
    return 0;
  }

  uw = kmalloc(sizeof(*uw), GFP_ATOMIC);
  if (!uw) {
    path_put(&base);
    av_work_release();
    return 0;
  }
  uw->base = base;

  {
    ssize_t path_len = strncpy_from_user(uw->path, user_path, PATH_MAX);

    if (path_len <= 0 || path_len >= PATH_MAX) {
      path_put(&uw->base);
      kfree(uw);
      av_work_release();
      return 0;
    }
  }

  uw->pid = task_tgid_nr(current);
  uw->target_pid = get_task_pid(current, PIDTYPE_PID);
  INIT_WORK(&uw->work, av_unlink_work_fn);
  queue_work(av_wq, &uw->work);

  return 0;
}

/* unlink(const char *pathname) - pathname is the first (and only)
 * argument, same register position as execve's filename. No dfd of
 * its own, so always resolves relative to cwd (AT_FDCWD). */
static int handler_pre_unlink(struct kprobe *p, struct pt_regs *regs) {
  const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

  if (!real_regs)
    return 0;
  return schedule_unlink_work((const char __user *)real_regs->di, AT_FDCWD);
}

/* unlinkat(int dfd, const char *pathname, int flag) - dfd is the FIRST
 * argument (regs->di), pathname is the SECOND (regs->si), same
 * position as openat's filename. */
static int handler_pre_unlinkat(struct kprobe *p, struct pt_regs *regs) {
  const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

  if (!real_regs)
    return 0;
  return schedule_unlink_work((const char __user *)real_regs->si,
                              (int)real_regs->di);
}

/* ---- rename/renameat/renameat2: extension-append burst + sensitive-
 * path rename tracking. Same atomic-context discipline as every other
 * hook here: pre-handlers only copy TWO path strings (GFP_ATOMIC) and
 * schedule work; all logic lives in av_behavior_check_rename(). ---- */

struct av_rename_work {
  struct work_struct work;
  struct pid *target_pid;
  pid_t pid;            /* tgid, not thread pid - see the note on av_openat_work
                         * above; keeps the rename counter keyed the same way
                         * as every other per-process heuristic here. */
  struct path old_base; /* olddfd resolved at kprobe time (AT_FDCWD
                         * for rename(), which has no dfd args of
                         * its own). old_base/new_base are
                         * deliberately independent - renameat()
                         * allows olddfd and newdfd to name
                         * different directories entirely, so
                         * oldpath and newpath cannot share a single
                         * resolved base the way openat/unlink can.
                         * Released via path_put() in
                         * av_rename_work_fn(). */
  struct path new_base; /* newdfd resolved at kprobe time - see
                         * old_base above. */
  char oldpath[PATH_MAX];
  char newpath[PATH_MAX];
};

static void av_rename_work_fn(struct work_struct *w) {
  struct av_rename_work *rw = container_of(w, struct av_rename_work, work);
  char *abs_old = kmalloc(PATH_MAX, GFP_KERNEL);
  char *abs_new;

  if (!abs_old) {
    path_put(&rw->old_base);
    path_put(&rw->new_base);
    put_pid(rw->target_pid);
    kfree(rw);
    av_work_release();
    return;
  }
  abs_new = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!abs_new) {
    kfree(abs_old);
    path_put(&rw->old_base);
    path_put(&rw->new_base);
    put_pid(rw->target_pid);
    kfree(rw);
    av_work_release();
    return;
  }

  resolve_absolute_path(rw->oldpath, &rw->old_base, abs_old, PATH_MAX);
  resolve_absolute_path(rw->newpath, &rw->new_base, abs_new, PATH_MAX);
  av_behavior_check_rename(rw->pid, abs_old, abs_new, rw->target_pid);

  kfree(abs_new);
  kfree(abs_old);
  path_put(&rw->old_base);
  path_put(&rw->new_base);
  put_pid(rw->target_pid);
  kfree(rw);
  av_work_release();
}

/* `olddfd`/`newdfd` should each be AT_FDCWD for rename() (no dfd args
 * of its own - both ends are always cwd-relative) or the real dfd
 * arguments for renameat()/renameat2(). Same dfd-ignored evasion fix
 * as openat/unlink: renameat(fd_for_/etc, "shadow", fd_for_/tmp,
 * "leaked") previously reached behavior.c as bare "shadow"/"leaked",
 * bypassing the sensitive-path check on the oldpath end entirely. */
static int schedule_rename_work(const char __user *user_oldpath, int olddfd,
                                const char __user *user_newpath, int newdfd) {
  struct av_rename_work *rw;
  struct path old_base, new_base;

  if (!user_oldpath || !user_newpath)
    return 0;

  if (!resolve_dfd_path(olddfd, &old_base))
    return 0;
  if (!resolve_dfd_path(newdfd, &new_base)) {
    path_put(&old_base);
    return 0;
  }

  if (!av_work_admit_nonexec()) {
    path_put(&old_base);
    path_put(&new_base);
    return 0;
  }

  rw = kmalloc(sizeof(*rw), GFP_ATOMIC);
  if (!rw) {
    path_put(&old_base);
    path_put(&new_base);
    av_work_release();
    return 0;
  }
  rw->old_base = old_base;
  rw->new_base = new_base;

  {
    ssize_t path_len;

    path_len = strncpy_from_user(rw->oldpath, user_oldpath, PATH_MAX);
    if (path_len <= 0 || path_len >= PATH_MAX) {
      path_put(&rw->old_base);
      path_put(&rw->new_base);
      kfree(rw);
      av_work_release();
      return 0;
    }
    path_len = strncpy_from_user(rw->newpath, user_newpath, PATH_MAX);
    if (path_len <= 0 || path_len >= PATH_MAX) {
      path_put(&rw->old_base);
      path_put(&rw->new_base);
      kfree(rw);
      av_work_release();
      return 0;
    }
  }

  rw->pid = task_tgid_nr(current);
  rw->target_pid = get_task_pid(current, PIDTYPE_PID);
  INIT_WORK(&rw->work, av_rename_work_fn);
  queue_work(av_wq, &rw->work);

  return 0;
}

/* rename(const char *oldname, const char *newname) - same register
 * shape as unlink's single-arg case, just two of them: oldname is the
 * first arg (di), newname is the second (si). No dfd args of its own,
 * so both resolve relative to cwd (AT_FDCWD). */
static int handler_pre_rename(struct kprobe *p, struct pt_regs *regs) {
  const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

  if (!real_regs)
    return 0;
  return schedule_rename_work((const char __user *)real_regs->di, AT_FDCWD,
                              (const char __user *)real_regs->si, AT_FDCWD);
}

/* renameat(int olddfd, const char *oldname, int newdfd, const char *newname)
 * - olddfd is the FIRST arg (di), oldname the SECOND (si), newdfd the
 * THIRD (dx), newname the FOURTH (r10, not r8 - standard x86_64
 * syscall arg order is di/si/dx/r10/r8/r9, since r10 substitutes for
 * rcx which the SYSCALL instruction itself clobbers). */
static int handler_pre_renameat(struct kprobe *p, struct pt_regs *regs) {
  const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

  if (!real_regs)
    return 0;
  return schedule_rename_work(
      (const char __user *)real_regs->si, (int)real_regs->di,
      (const char __user *)real_regs->r10, (int)real_regs->dx);
}

/* renameat2(int olddfd, const char *oldname, int newdfd, const char *newname,
 * unsigned int flags) - same first four args as renameat (flags, the
 * fifth/r8, isn't currently used - RENAME_EXCHANGE/RENAME_NOREPLACE/
 * RENAME_WHITEOUT aren't distinguished by this heuristic today). */
static int handler_pre_renameat2(struct kprobe *p, struct pt_regs *regs) {
  const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

  if (!real_regs)
    return 0;
  return schedule_rename_work(
      (const char __user *)real_regs->si, (int)real_regs->di,
      (const char __user *)real_regs->r10, (int)real_regs->dx);
}

/* ---- pre-existing kernel taint check ----
 *
 * Checked once, as the very first thing av_init() does, before this
 * module sets up anything else - the point is visibility into what
 * state the kernel was ALREADY in before av.ko loaded, not a
 * decision this module makes on its own. A kernel that's already
 * tainted by something else (a prior OOPS, a forced/crash-driven
 * module unload, a machine check, RANDSTRUCT disabled, etc.) means
 * this module's own detection guarantees may not hold - something
 * else may have already had the opportunity to compromise kernel
 * state before av.ko ever got a chance to hook anything, and results
 * from a module running on top of that should be trusted less, not
 * silently trusted the same as on a clean boot.
 *
 * This does NOT refuse to load on a tainted kernel: same reasoning
 * as the daemon fail-open default elsewhere in this file - a
 * security module that won't even start on an already-imperfect
 * system is a worse outcome than one that starts and says so loudly
 * via dmesg, where an operator or analyst can actually see and
 * act on it.
 *
 * Deliberately does NOT check TAINT_OOT_MODULE or
 * TAINT_UNSIGNED_MODULE: av.ko itself is out-of-tree and (in every
 * documented workflow in this repo) unsigned, so both of those flags
 * get set by THIS module's own load, unconditionally, on every
 * single insmod, on every system - checking for them would just mean
 * this warning fires 100% of the time regardless of system history,
 * carrying zero information about whether anything ELSE tainted the
 * kernel first. Every flag below is one this module's own load
 * cannot cause by itself, so seeing any of them set means something
 * else is responsible. Only test_taint() is used, not get_taint():
 * the latter isn't EXPORT_SYMBOL'd (confirmed against this project's
 * own build - absent from Module.symvers), so it's not callable from
 * an out-of-tree module at all; test_taint() (one flag at a time) is
 * the only externally-usable primitive here. */
struct av_taint_flag {
  unsigned int flag;
  char letter;
  const char *name;
};

static const struct av_taint_flag av_taint_flags_of_interest[] = {
    {TAINT_PROPRIETARY_MODULE, 'P', "PROPRIETARY_MODULE"},
    {TAINT_FORCED_MODULE, 'F', "FORCED_MODULE"},
    {TAINT_CPU_OUT_OF_SPEC, 'S', "CPU_OUT_OF_SPEC"},
    {TAINT_FORCED_RMMOD, 'R', "FORCED_RMMOD"},
    {TAINT_MACHINE_CHECK, 'M', "MACHINE_CHECK"},
    {TAINT_BAD_PAGE, 'B', "BAD_PAGE"},
    {TAINT_USER, 'U', "USER"},
    {TAINT_DIE, 'D', "DIE"},
    {TAINT_OVERRIDDEN_ACPI_TABLE, 'A', "OVERRIDDEN_ACPI_TABLE"},
    {TAINT_WARN, 'W', "WARN"},
    {TAINT_CRAP, 'C', "CRAP"},
    {TAINT_FIRMWARE_WORKAROUND, 'I', "FIRMWARE_WORKAROUND"},
    {TAINT_SOFTLOCKUP, 'L', "SOFTLOCKUP"},
    {TAINT_LIVEPATCH, 'K', "LIVEPATCH"},
    {TAINT_AUX, 'X', "AUX"},
#ifdef TAINT_RANDSTRUCT
    {TAINT_RANDSTRUCT, 'T', "RANDSTRUCT"},
#endif
};

/* Letters follow the same convention as the kernel's own "Tainted:"
 * dmesg/print_tainted() line, so this is directly cross-referenceable
 * against Documentation/admin-guide/tainted-kernels.rst without
 * needing a separate lookup table. */
static void av_check_preexisting_taint(void) {
  char letters[ARRAY_SIZE(av_taint_flags_of_interest) + 1];
  char names[512];
  size_t n_letters = 0;
  size_t names_len = 0;
  size_t i;

  names[0] = '\0';
  for (i = 0; i < ARRAY_SIZE(av_taint_flags_of_interest); i++) {
    if (!test_taint(av_taint_flags_of_interest[i].flag))
      continue;
    letters[n_letters++] = av_taint_flags_of_interest[i].letter;
    names_len += scnprintf(names + names_len, sizeof(names) - names_len,
                           "%s%s", names_len ? "," : "",
                           av_taint_flags_of_interest[i].name);
  }
  letters[n_letters] = '\0';

  if (n_letters == 0)
    return;

  pr_alert("kernel-av: event=kernel_tainted flags=\"%s\" reasons=\"%s\" "
           "note=\"kernel was already tainted before av.ko loaded - "
           "detection is running on a kernel whose own integrity "
           "isn't guaranteed, treat results with reduced confidence\"\n",
           letters, names);
}

static int __init av_init(void) {
  int ret;

  av_check_preexisting_taint();

  ret = av_sigtable_init();
  if (ret)
    return ret;

  ret = av_sigtable_proc_init();
  if (ret) {
    pr_err("kernel-av: failed to create /proc/kernel_av_signatures: %d\n", ret);
    goto err_sigtable;
  }

  daemon_policy_proc_entry = proc_create(
      "kernel_av_daemon_policy", 0644, NULL, &daemon_policy_proc_ops);
  if (!daemon_policy_proc_entry) {
    pr_err("kernel-av: failed to create /proc/kernel_av_daemon_policy\n");
    ret = -ENOMEM;
    goto err_proc;
  }

  /* Seed a default signature so testing works out of the box without
   * needing a separate `avctl add` step first. Not fatal to av_init()
   * if this fails - detection still works via avctl/the daemon path,
   * just without the EICAR convenience entry - but silently ignoring
   * the return value would leave "why doesn't EICAR trigger a kill on
   * a fresh module load" with no dmesg trail to explain it, so log it
   * loudly enough to notice. */
  ret = av_sigtable_add(
      AV_ALGO_SHA256,
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "EICAR-Test-File");
  if (ret)
    pr_warn("kernel-av: failed to seed default EICAR signature: %d\n", ret);

  ret = av_behavior_init();
  if (ret) {
    pr_err("kernel-av: failed to init behavior tracking: %d\n", ret);
    goto err_daemon_policy_proc;
  }

  /* max_active bounded to av_wq_max_active rather than 0 (per-CPU
   * default, effectively unbounded for WQ_UNBOUND at this queue's
   * volume) - bounds how many *_work_fn instances run concurrently, so
   * a burst (build, checkout, rm -rf) can't spin up hundreds of worker
   * threads all doing PATH_MAX kmallocs and path resolution at once.
   * NOT a strict, single-counter global ceiling: current kernels
   * enforce WQ_UNBOUND's max_active per NUMA node (proportional to
   * each node's online CPUs, with an 8-per-node floor), so the true
   * aggregate across all nodes can exceed this value by a small,
   * kernel-version-dependent amount on multi-node hardware - see
   * WQ_UNBOUND_MAX_ACTIVE's own kernel documentation. Still the right
   * knob for this module's actual goal (avoid an unbounded pile of
   * concurrent worker threads under a burst), just not an exact one.
   * Pending items beyond that still queue (bounded separately by
   * av_inflight_work / AV_MAX_INFLIGHT_WORK above) and drain as
   * workers free up, rather than being dropped. */
  if (av_wq_max_active < AV_WQ_MAX_ACTIVE_MIN ||
      av_wq_max_active > AV_WQ_MAX_ACTIVE_MAX) {
    pr_warn("kernel-av: av_wq_max_active=%d out of range [%d,%d], "
            "using default %d\n",
            av_wq_max_active, AV_WQ_MAX_ACTIVE_MIN, AV_WQ_MAX_ACTIVE_MAX,
            AV_WQ_MAX_ACTIVE_DEFAULT);
    av_wq_max_active = AV_WQ_MAX_ACTIVE_DEFAULT;
  }
  av_wq = alloc_workqueue("kernel_av_wq", WQ_UNBOUND, av_wq_max_active);
  if (!av_wq) {
    pr_err("kernel-av: failed to allocate workqueue\n");
    ret = -ENOMEM;
    goto err_behavior;
  }

  ret = av_netlink_init();
  if (ret) {
    pr_err("kernel-av: failed to register netlink family: %d\n", ret);
    goto err_wq;
  }

  kp_execve.pre_handler = handler_pre;
  ret = register_kprobe(&kp_execve);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(execve) failed: %d\n", ret);
    goto err_netlink;
  }

  kp_execveat.pre_handler = handler_pre_execveat;
  ret = register_kprobe(&kp_execveat);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(execveat) failed: %d\n", ret);
    goto err_kp_execve;
  }

  kp_openat.pre_handler = handler_pre_openat;
  ret = register_kprobe(&kp_openat);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(openat) failed: %d\n", ret);
    goto err_kp_execveat;
  }

  kp_unlink.pre_handler = handler_pre_unlink;
  ret = register_kprobe(&kp_unlink);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(unlink) failed: %d\n", ret);
    goto err_kp_openat;
  }

  kp_unlinkat.pre_handler = handler_pre_unlinkat;
  ret = register_kprobe(&kp_unlinkat);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(unlinkat) failed: %d\n", ret);
    goto err_kp_unlink;
  }

  kp_rename.pre_handler = handler_pre_rename;
  ret = register_kprobe(&kp_rename);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(rename) failed: %d\n", ret);
    goto err_kp_unlinkat;
  }

  kp_renameat.pre_handler = handler_pre_renameat;
  ret = register_kprobe(&kp_renameat);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(renameat) failed: %d\n", ret);
    goto err_kp_rename;
  }

  kp_renameat2.pre_handler = handler_pre_renameat2;
  ret = register_kprobe(&kp_renameat2);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(renameat2) failed: %d\n", ret);
    goto err_kp_renameat;
  }

  pr_info("kernel-av: loaded, %zu signature(s) active\n", av_sigtable_count());
  return 0;

err_kp_renameat:
  unregister_kprobe(&kp_renameat);
err_kp_rename:
  unregister_kprobe(&kp_rename);
err_kp_unlinkat:
  unregister_kprobe(&kp_unlinkat);
err_kp_unlink:
  unregister_kprobe(&kp_unlink);
err_kp_openat:
  unregister_kprobe(&kp_openat);
err_kp_execveat:
  unregister_kprobe(&kp_execveat);
err_kp_execve:
  unregister_kprobe(&kp_execve);
err_netlink:
  av_netlink_exit();
err_wq:
  destroy_workqueue(av_wq);
err_behavior:
  av_behavior_exit();
err_daemon_policy_proc:
  remove_proc_entry("kernel_av_daemon_policy", NULL);
err_proc:
  av_sigtable_proc_exit();
err_sigtable:
  av_sigtable_exit();
  return ret;
}

static void __exit av_exit(void) {
  unregister_kprobe(&kp_renameat2);
  unregister_kprobe(&kp_renameat);
  unregister_kprobe(&kp_rename);
  unregister_kprobe(&kp_unlinkat);
  unregister_kprobe(&kp_unlink);
  unregister_kprobe(&kp_openat);
  unregister_kprobe(&kp_execveat);
  unregister_kprobe(&kp_execve);
  /* destroy_workqueue() flushes all pending work first, so no work
   * item can run against unloaded module .text after this returns. */
  destroy_workqueue(av_wq);
  av_netlink_exit();
  av_behavior_exit();
  remove_proc_entry("kernel_av_daemon_policy", NULL);
  av_sigtable_proc_exit();
  av_sigtable_exit();
  pr_info("kernel-av: unloaded\n");
}

module_init(av_init);
module_exit(av_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Keane");
MODULE_DESCRIPTION("Signature-based execve detection with runtime-managed "
                   "signature DB and behavioral heuristics");
MODULE_VERSION("1.0.0");
