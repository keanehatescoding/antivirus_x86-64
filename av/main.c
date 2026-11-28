/*
 * main.c - av module entry point: kprobe on security_bprm_check (exec),
 * workqueue-deferred multi-algorithm hashing (MD5/SHA-1/SHA-256),
 * lookup against the runtime-managed signature table (sigtable.c),
 * kill on match.
 *
 * ARCHITECTURE NOTE: kprobe pre-handlers run in an ATOMIC context - no
 * sleeping, no file I/O, no GFP_KERNEL. handler_pre_bprm_check() only
 * pins the exec's struct file and schedules a work item; all file I/O,
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
#include <linux/binfmts.h>
#include <linux/crypto.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include "behavior.h"
#include "logfmt.h"
#include "netlink_chan.h"
#include "netlink_proto.h"
#include "sigtable.h"

/* x86_64 only, for now (see CONTRIBUTING.md) - every behavioral hook
 * below (openat/unlink/rename) is registered by hardcoded __x64_sys_*
 * symbol name. The exec hook is not: it probes security_bprm_check,
 * which is arch-independent. On an arch using a
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

/* The exec hook probes security_bprm_check() (#87, #102), not the
 * execve/execveat syscall entry points. By the time the kernel calls
 * it, the pathname has already been copied in by getname() and the
 * target is open as bprm->file, so the pre-handler never has to read
 * user memory from atomic context. The old syscall-entry hook did, via
 * strncpy_from_user(), and a pathname on a not-yet-resident page made
 * that copy fail with -EFAULT and the exec go unscanned every time.
 * Hashing bprm->file itself also means the file hashed is the file
 * being executed, not whatever a later re-open of the path finds.
 *
 * Without CONFIG_SECURITY, security_bprm_check() is a static inline
 * stub in <linux/security.h> with no symbol to probe, so
 * register_kprobe() would fail at load with a bare -ENOENT/-EINVAL.
 * Fail at build time instead. Every mainstream distro kernel sets it;
 * CI's tinyconfig kernels enable it explicitly. */
#ifndef CONFIG_SECURITY
#error "av.ko needs CONFIG_SECURITY=y: the exec hook probes security_bprm_check(), which is an inline stub without it"
#endif
#define AV_EXEC_HOOK_SYMBOL "security_bprm_check"
#define READ_CHUNK_SIZE 4096
#define MAX_HASH_FILE_SIZE                                                     \
  (256 * 1024 * 1024) /* 256 MB cap on what                                    \
                       * hash_file_multi() will read - without                 \
                       * it, execve of a multi-GB binary hashes                \
                       * the whole thing inline in the worker,                 \
                       * tying up a workqueue thread for as                    \
                       * long as that takes; see the i_size                    \
                       * and read-loop checks below. */
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

static struct kprobe kp_bprm_check = {
    .symbol_name = AV_EXEC_HOOK_SYMBOL,
};
/* Self-delete detection on exec identity (#230): the commit point of an
 * exec, and the two places a name is removed. All three are
 * CONFIG_SECURITY entry points with signatures unchanged across every
 * supported kernel, like security_bprm_check(). Probed rather than
 * registered as LSM hooks because modules cannot register LSM hooks. */
static struct kprobe kp_bprm_committing = {
    .symbol_name = "security_bprm_committing_creds",
};
static struct kprobe kp_inode_unlink = {
    .symbol_name = "security_inode_unlink",
};
static struct kprobe kp_inode_rename = {
    .symbol_name = "security_inode_rename",
};
static struct kprobe kp_openat = {
    .symbol_name = "__x64_sys_openat",
};
/* Write-intent open tracking at the VFS layer (#105, #94): the kernel
 * calls security_file_open() with the file it actually resolved, for
 * every open (open/creat/openat/openat2, io_uring, kernel-internal),
 * so there is no user string to copy and no syscall ABI to name.
 * kp_openat above is kept only behind av_legacy_openat_hook.
 *
 * A kretprobe, not a plain kprobe: security_file_open() itself runs the
 * LSM and fanotify permission checks in its body, so the event may only
 * be queued once the function returns 0. The entry handler retains the
 * state; the exit handler either queues it or drops it on denial. */
struct av_fileopen_work; /* defined with the deferred work item below */
static struct kretprobe kr_file_open = {
    .kp.symbol_name = "security_file_open",
    .data_size = sizeof(struct av_fileopen_work *),
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
/* Slots reserved exclusively for the exec hook: openat/unlink/
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
/* A separate budget for matched self-delete reports (see
 * schedule_selfdel_work()), not a slice of av_inflight_work. A process
 * whose image is already staged can have exec work filling
 * AV_MAX_INFLIGHT_WORK around it, and admitting its report from that
 * budget would drop the unlink or rename it was matched on, letting it
 * remove its own image with no report and no kill. A match is rare (each
 * one ends the process), so this stays small; what it bounds is the
 * PATH_MAX buffer every item carries. It still has to be a bound: a
 * process the kill is suppressed for (a protected exe) can repeat the
 * attempt, and so can one that keeps going until the kill lands. */
#define AV_MAX_INFLIGHT_SELFDEL 256
static atomic_t av_inflight_selfdel = ATOMIC_INIT(0);

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

/* TEST-ONLY: parks every deferred exec work item for this many ms
 * before it looks at the file at all (d_path() and the hash), so
 * tests/test_netlink.sh can rename or unlink the exec'd pathname while
 * the request is still in flight and prove that avd scans the file the
 * kernel hashed, not whatever the path names by then (issue #227), and
 * the QEMU boot test can unlink an image before d_path() runs and
 * prove the self-delete kill does not wait for this work item. The
 * hash itself reads the pinned
 * bprm->file, so the delay cannot change what is hashed - only how
 * late avd gets to open the path. Ported from the arm64 tree, where
 * the same knob drives the QEMU boot test's exec-time TOCTOU cases.
 *
 * Default 0 = disabled, so every production configuration is byte-for-byte
 * unaffected (the sleep is not even entered). Writable (0644) so the test
 * can enable it around its cases and clear it again via
 * /sys/module/av/parameters/av_toctou_test_delay_ms; read once per work
 * item and clamped, so a concurrent out-of-range write can never turn it
 * into an unbounded sleep. The _test_ infix marks it as never an
 * operational knob. */
#define AV_TOCTOU_TEST_DELAY_MAX_MS 2000
static int av_toctou_test_delay_ms; /* = 0: disabled unless a test sets it */
module_param(av_toctou_test_delay_ms, int, 0644);
MODULE_PARM_DESC(av_toctou_test_delay_ms,
                 "TEST ONLY: ms to sleep before the deferred exec work looks at the file, so a regression test can swap or unlink the pathname mid-flight and prove avd scans the hashed file (default 0 = disabled; clamped to [0, 2000]); never set in production");

/* Escape hatch while the security_file_open hook is new: load with
 * av_legacy_openat_hook=1 to track write-intent opens through the old
 * __x64_sys_openat kprobe instead. Exactly one of the two is ever
 * registered (never both: that would double-count every open toward
 * the rapid-write threshold). Read-only at runtime (0444). */
static bool av_legacy_openat_hook;
module_param(av_legacy_openat_hook, bool, 0444);
MODULE_PARM_DESC(av_legacy_openat_hook,
                 "Track write-intent opens via the legacy __x64_sys_openat kprobe instead of security_file_open (default 0 = security_file_open); escape hatch, remove once the new hook has soaked");

/* Read-only observability for the security_file_open kretprobe. nmissed
 * counts probe hits for which no return-probe instance was available: in
 * that case even entry_file_open() is skipped, so the work-admission
 * budget never gets a chance to decide. It counts ALL opens, including
 * read-only ones the entry handler would have filtered out, so a nonzero
 * value signals that write-intent coverage MAY have been lost, not that
 * a qualifying write was definitely missed. With maxactive sized to the
 * work budget (see av_register_open_probe()) this should stay at zero. */
static int av_file_open_nmissed_get(char *buffer,
                                    const struct kernel_param *kp) {
  return sprintf(buffer, "%d\n", kr_file_open.nmissed);
}
static const struct kernel_param_ops av_file_open_nmissed_ops = {
    .get = av_file_open_nmissed_get,
};
module_param_cb(av_file_open_nmissed, &av_file_open_nmissed_ops, NULL, 0444);
MODULE_PARM_DESC(av_file_open_nmissed,
                 "security_file_open kretprobe instances missed since load (read-only; nonzero means write-intent open coverage may have been lost)");

static inline bool av_work_admit_capped(unsigned int cap) {
  if (atomic_inc_return(&av_inflight_work) > cap) {
    atomic_dec(&av_inflight_work);
    return false;
  }
  return true;
}

/* Call before allocating a struct av_work in the exec (bprm_check)
 * pre-handler. Returns true if under the cap (caller may proceed to
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

/* Same contract as av_work_admit(), against the self-delete budget only:
 * paired with exactly one av_selfdel_release() on every path after a true
 * return. */
static inline bool av_selfdel_admit(void) {
  if (atomic_inc_return(&av_inflight_selfdel) > AV_MAX_INFLIGHT_SELFDEL) {
    atomic_dec(&av_inflight_selfdel);
    return false;
  }
  return true;
}

static inline void av_selfdel_release(void) {
  atomic_dec(&av_inflight_selfdel);
}

/* Resolves a syscall's `dfd` argument into a struct path suitable as
 * the base for a later relative-path lookup. Callable from ATOMIC
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
 * lifetime discipline for every hook that uses it. Returns false
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
 * prefix/substring matching referenced in resolve_absolute_path()'s
 * comment below,
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
       * downstream path checks (sensitive-path, rename/write-open
       * dedup) compare by string. Bail out instead of producing a
       * lossy, potentially colliding result - leave `path` untouched
       * (still the original, un-normalized string) so callers compare
       * the real path rather than a truncated stand-in. */
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
 * rename's newpath and an O_CREAT openat target may not exist yet, and
 * unlink's target may be a symlink we must NOT follow. (The exec hook
 * doesn't come through here at all - it has the kernel's own resolved
 * struct file and d_path()s that directly, see av_work_fn().) Instead this resolves only the base directory (dfd)
 * to its absolute path via d_path() and string-concatenates the
 * (still possibly containing "." / ".." components) relative
 * remainder onto it. That's sufficient for behavior.c's prefix/
 * substring matching once normalize_abs_path() (below) collapses
 * those components - lexical
 * normalization only, not a canonical realpath() (no symlink
 * resolution, no filesystem access to confirm anything exists). On any
 * failure this falls back to copying `path` through unresolved rather
 * than dropping the event - a degraded (pre-fix) check on this one
 * call is better than silently skipping it. */
static void resolve_absolute_path(const char *path, const struct path *base,
                                  char *out, size_t out_len) {
  char *tmp;
  char *dirpath;

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
     * identical string, which any strcmp() on this output would
     * then treat as the same file -
     * same lossy-result-is-dangerous reasoning as normalize_abs_path()'s
     * own >128-component bail-out above. Falling back to the
     * unresolved relative path (not absolute, but not truncated
     * either) matches this function's existing degraded-not-dropped
     * fallback stance for the d_path() failure case just above - it
     * doesn't fully rule out a collision between two different
     * fallback results. (Self-delete correlation, the one caller that
     * used to compare two of these with strcmp(), now matches on the
     * resolved dentry instead - see struct av_exec_ident in
     * behavior.c.)
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
  struct file *file; /* bprm->file - the file the kernel itself opened
                      * for this exec - pinned with get_file() in
                      * handler_pre_bprm_check() (a refcount bump,
                      * atomic-safe) and fput() in av_work_fn()'s
                      * cleanup. Hashing and path logging both go
                      * through THIS, never a re-open of a pathname. */
  bool fail_closed; /* av_daemon_fail_closed, snapshotted here (kprobe
                     * time) rather than re-read in av_work_fn() at
                     * verdict time - see the policy-flip race note on
                     * av_daemon_fail_closed's own declaration below.
                     * Locks in "policy as of launch" semantics instead
                     * of "policy as of verdict", so an operator toggling
                     * fail-closed mid-flight can no longer retroactively
                     * kill an exec that was already committed under
                     * fail-open. */
};

struct algo_ctx {
  bool active;
  /* Borrowed from the matching av_tfm_* below (allocated once in
   * av_crypto_init(), freed in av_crypto_exit()) - never allocated or
   * freed per-exec here. Every crypto_shash_* call on it runs under
   * av_tfm_lock. */
  struct crypto_shash *tfm;
  struct shash_desc *desc;
  u8 *digest_bin;
  size_t digest_bin_len;
  char *digest_hex; /* points into the matching field of av_digest */
};
/* Cached crypto_shash transforms, one per hash algorithm (issue #118).
 * hash_file_multi() used to crypto_alloc_shash() a fresh transform on
 * every exec, so an allocation failure under memory pressure skipped
 * the signature match AND the daemon scan with no verdict and no log
 * line at all - a silent, complete fail-open. Allocating once at load
 * moves that failure to module-load time, where it is loud (pr_err,
 * and fatal for SHA-256: the trusted-hash lookup and the daemon scan
 * key on it unconditionally, so loading without it would silently
 * degrade every exec to "no hash at all").
 *
 * SHA-256 is mandatory; MD5/SHA-1 only matter when the sigtable holds
 * entries of that algo, so a missing MD5/SHA-1 transform (e.g. on a
 * kernel with the algo unavailable) warns and skips that algo instead
 * of refusing to load. A sigtable entry added later for an unavailable
 * algo then never matches - no worse than a sigtable holding no such
 * entries in the first place.
 *
 * av_tfm_lock is taken around each individual crypto_shash_* call
 * (init/update/final), never across file IO: the workqueue runs
 * av_work_fn() on multiple threads at once, and sharing one transform
 * across them must not interleave on it. Locking per call (rather
 * than once for the whole file) keeps concurrent execs hashing in
 * parallel - a slow or huge file being read by one worker must not
 * stall every other exec's verdict behind a single lock-holder.
 * Sleepable context only (workqueue, never the kprobe pre-handler),
 * so a plain mutex is fine. */
static struct crypto_shash *av_tfm_md5;
static struct crypto_shash *av_tfm_sha1;
static struct crypto_shash *av_tfm_sha256;
static DEFINE_MUTEX(av_tfm_lock);

static int __init av_crypto_init(void) {
  /* Mandatory first: on failure nothing else is allocated yet, so the
   * caller can just return err with no cleanup. */
  av_tfm_sha256 = crypto_alloc_shash("sha256", 0, 0);
  if (IS_ERR(av_tfm_sha256)) {
    int err = PTR_ERR(av_tfm_sha256);

    av_tfm_sha256 = NULL;
    pr_err("kernel-av: crypto_alloc_shash(sha256) failed: %d - refusing to "
           "load without it\n",
           err);
    return err;
  }
  av_tfm_md5 = crypto_alloc_shash("md5", 0, 0);
  if (IS_ERR(av_tfm_md5)) {
    pr_warn("kernel-av: crypto_alloc_shash(md5) failed: %d - MD5 sigtable "
            "entries will never match\n",
            (int)PTR_ERR(av_tfm_md5));
    av_tfm_md5 = NULL;
  }
  av_tfm_sha1 = crypto_alloc_shash("sha1", 0, 0);
  if (IS_ERR(av_tfm_sha1)) {
    pr_warn("kernel-av: crypto_alloc_shash(sha1) failed: %d - SHA-1 sigtable "
            "entries will never match\n",
            (int)PTR_ERR(av_tfm_sha1));
    av_tfm_sha1 = NULL;
  }
  return 0;
}

static void av_crypto_exit(void) {
  /* No lifetime worry: both callers run after every hash_file_multi()
   * has finished - av_exit() calls this after destroy_workqueue()
   * flushes all pending work, and av_init()'s error path only reaches
   * it when init failed before any work could be queued. */
  crypto_free_shash(av_tfm_md5);
  crypto_free_shash(av_tfm_sha1);
  crypto_free_shash(av_tfm_sha256);
  av_tfm_md5 = NULL;
  av_tfm_sha1 = NULL;
  av_tfm_sha256 = NULL;
}

/* Captures the identity of the file hash_file_multi() hashed, so a
 * signature/daemon verdict can be logged against something more
 * forensically specific than a path string alone. Since the exec hook
 * moved to security_bprm_check, that file is the exec's own
 * bprm->file, so dev/ino here identify the image that actually ran. */
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

/* Computes MD5, SHA-1, and SHA-256 of `f` in a single read pass. MUST
 * be called from a sleepable (process) context only. `f` is the exec's
 * own bprm->file (see struct av_work) - borrowed, not opened or closed
 * here. The kernel opened it for exec with O_RDONLY, so FMODE_READ is
 * set even for an execute-only (--x) binary, and kernel_read() with a
 * local `pos` never touches f->f_pos, which the binfmt loader may be
 * using concurrently. `ident_out` (optional, may be NULL) is filled in
 * with `f`'s identity - see struct av_file_identity above. */
static int hash_file_multi(struct file *f, struct av_digest *out,
                           struct av_file_identity *ident_out) {
  u8 md5_bin[16], sha1_bin[20], sha256_bin[32];
  /* SHA-256 is always computed - av_behavior_record_exec()'s
   * trusted-hash lookup and the netlink scan request to avd
   * both key on it unconditionally, regardless of what the sigtable
   * holds. MD5/SHA-1 exist purely to match against sigtable entries
   * of that algo, so skip computing them when the sigtable holds
   * none - wasted crypto work in the common case (SHA-256-only
   * signature DBs). */
  bool need_md5 = av_sigtable_algo_count(AV_ALGO_MD5) > 0;
  bool need_sha1 = av_sigtable_algo_count(AV_ALGO_SHA1) > 0;
  struct algo_ctx ctx[3] = {
      {need_md5 && av_tfm_md5, av_tfm_md5, NULL, md5_bin, sizeof(md5_bin),
       out->md5},
      {need_sha1 && av_tfm_sha1, av_tfm_sha1, NULL, sha1_bin,
       sizeof(sha1_bin), out->sha1},
      /* SHA-256 is always usable here: av_crypto_init() refuses to load
       * without it (see above), so no NULL check needed. */
      {true, av_tfm_sha256, NULL, sha256_bin, sizeof(sha256_bin), out->sha256},
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

  /* Only hash regular files, and only up to MAX_HASH_FILE_SIZE - see
   * the macro comment. The exec path's own open already refuses a
   * non-regular file (-EACCES) before security_bprm_check() runs, so
   * the S_ISREG check is defense in depth rather than a live case. */
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
    /* Per-exec shash_desc on the shared cached transform (see
     * av_tfm_*): only the desc and read buffer can still fail here
     * with -ENOMEM, and av_work_fn() already logs those distinctly. */
    ctx[i].desc = kmalloc(
        sizeof(*ctx[i].desc) + crypto_shash_descsize(ctx[i].tfm), GFP_KERNEL);
    if (!ctx[i].desc) {
      ret = -ENOMEM;
      goto out;
    }
    ctx[i].desc->tfm = ctx[i].tfm;
    /* Per-op av_tfm_lock (see its comment): serialize on the shared
     * transform for exactly this call, never across file IO. */
    mutex_lock(&av_tfm_lock);
    ret = crypto_shash_init(ctx[i].desc);
    mutex_unlock(&av_tfm_lock);
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
      /* Same per-op locking as the init loop above - the read itself
       * stays outside the lock so workers hash in parallel. */
      mutex_lock(&av_tfm_lock);
      ret = crypto_shash_update(ctx[i].desc, buf, n);
      mutex_unlock(&av_tfm_lock);
      if (ret)
        goto out;
    }
    /* Sleepable kworker: yield each chunk so a large cached file can't
     * monopolize the CPU on CONFIG_PREEMPT_NONE. */
    cond_resched();
  }
  if (n < 0) {
    ret = n;
    goto out;
  }

  for (i = 0; i < 3; i++) {
    if (!ctx[i].active)
      continue;
    mutex_lock(&av_tfm_lock);
    ret = crypto_shash_final(ctx[i].desc, ctx[i].digest_bin);
    mutex_unlock(&av_tfm_lock);
    if (ret)
      goto out;
    bin_to_hex(ctx[i].digest_bin, ctx[i].digest_bin_len, ctx[i].digest_hex);
  }

out:
  kfree(buf);
  for (i = 0; i < 3; i++)
    kfree(ctx[i].desc);
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
 * with workqueue backlog. handler_pre_bprm_check() now snapshots
 * this into struct av_work's fail_closed field at kprobe time
 * instead, so av_work_fn() enforces the policy that was in
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
  char *protected_path;
  char *esc_path;
  /* path/protected_exe go through av_log_escape() (logfmt.c), not a
   * bare %s or %*pE, in every log line here (#166): a filename can
   * contain quotes or newlines, which would otherwise forge extra
   * fields or whole log lines in these quoted key=value records -
   * and %*pE leaves '"' unescaped, see logfmt.c. Ordinary paths
   * render identically, so nothing greppable changes for them. Same
   * idiom as the hash-error/clean lines in av_work_fn(). A kmalloc
   * failure logs "?" for the field, never skips the check or kill. */
  esc_path = av_log_escape(path, GFP_KERNEL);
  /* PID 1 checked before the PATH_MAX allocation below: killing init
   * can panic the kernel, so bail before spending it. */
  if (pid_nr(target_pid) == 1) {
    pr_alert("kernel-av: event=suppressed action=none type=%s "
             "path=\"%s\" reason=\"%s\" pid=1\n",
             type, av_log_str(esc_path), reason);
    kfree(esc_path);
    return;
  }
  /* PATH_MAX (4096) is far too large for the kernel stack - heap-
   * allocate rather than declare a PATH_MAX array here, same reasoning
   * as kill_with_reason()'s identical pattern in behavior.c. Sleepable
   * context (workqueue), GFP_KERNEL is fine. A kmalloc failure just
   * drops the protected-exe path from the log line, not the check
   * itself - av_behavior_target_is_protected() tolerates NULL path_out. */
  protected_path = kmalloc(PATH_MAX, GFP_KERNEL);

  /* See behavior.h's comment on av_behavior_target_is_protected() -
   * an operator-managed allow-list, same suppressed-not-skipped
   * treatment as the PID-1 guard above. */
  if (av_behavior_target_is_protected(target_pid, protected_path, PATH_MAX)) {
    char *esc_exe =
        protected_path ? av_log_escape(protected_path, GFP_KERNEL) : NULL;

    pr_alert("kernel-av: event=suppressed action=none type=%s "
             "path=\"%s\" reason=\"%s\" pid=%d protected_exe=\"%s\"\n",
             type, av_log_str(esc_path), reason, pid_nr(target_pid),
             av_log_str(esc_exe));
    kfree(esc_exe);
    kfree(protected_path);
    kfree(esc_path);
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
          type, av_log_str(esc_path), reason, pid_nr(target_pid),
          MAJOR(ident->dev), MINOR(ident->dev), ident->ino,
          (long long)ident->size);
    } else {
      pr_alert("kernel-av: event=detected action=kill type=%s "
               "path=\"%s\" reason=\"%s\" pid=%d\n",
               type, av_log_str(esc_path), reason, pid_nr(target_pid));
    }
    send_sig(SIGKILL, task, 0);
  }
  rcu_read_unlock();
  kfree(esc_path);
}

/* Releases everything an av_work holds. */
static void av_work_free(struct av_work *aw) {
  fput(aw->file);
  put_pid(aw->target_pid);
  kfree(aw);
  av_work_release();
}

/* Identity of the pinned exec file in the form userspace fstat() reports
 * it, for the daemon's "is this still the file the kernel hashed" check
 * (issue #227). Deliberately vfs_getattr() rather than inode->i_sb->s_dev/
 * i_ino (what av_file_identity carries for logging): btrfs subvolumes and
 * overlayfs report a different st_dev/st_ino through ->getattr than the
 * raw inode fields, and a mismatch there would make avd refuse every
 * legitimate exec on those filesystems. Returns false when getattr
 * fails. The daemon is then not asked at all: an identity-free request
 * is avd's compatibility mode for pre-#227 modules, which scans
 * whatever the path names now, so av_work_fn() treats the exec as
 * unverified instead (fail-closed kills, fail-open logs it). */
static bool av_scan_ident_of(struct file *file, struct av_scan_ident *out) {
  struct kstat st;

  if (vfs_getattr(&file->f_path, &st, STATX_INO, AT_STATX_SYNC_AS_STAT))
    return false;
  out->dev_major = MAJOR(st.dev);
  out->dev_minor = MINOR(st.dev);
  out->ino = st.ino;
  return true;
}

/* Runs in a kernel worker thread - safe to sleep, do file I/O, use
 * GFP_KERNEL. This is where all "heavy" work happens.
 *
 * What's hashed is aw->file, the exec's own bprm->file pinned in
 * handler_pre_bprm_check(), so the digest is of the exact image the
 * kernel is executing. An earlier design hashed a SEPARATE, LATER
 * open of the pathname and could be raced by swapping the file or a
 * symlink in between; with no second open, there's nothing to swap.
 *
 * STILL KILL-AFTER-EXEC: this runs asynchronously, so the exec has
 * usually already committed and the new image may run briefly before
 * a verdict kills it. Holding the exec until a verdict exists is the
 * fanotify FAN_OPEN_EXEC_PERM work in avd (#176), not something a
 * kprobe can do. */
static void av_work_fn(struct work_struct *w) {
  struct av_work *aw = container_of(w, struct av_work, work);
  struct av_digest digest;
  struct av_file_identity ident;
  char sig_name[AV_SIG_NAME_LEN];
  char reason[AV_SIG_NAME_LEN + 32];
  char *abs_path;
  char *esc_path;
  int ret;

  /* TEST-ONLY delay (see av_toctou_test_delay_ms): a no-op whenever the
   * knob is at its default 0, i.e. in every production configuration.
   * Placed before this work item looks at the file at all - the
   * d_path() below and the hash - so a test can rename or unlink the
   * pathname while it is parked. The request then carries the
   * " (deleted)" form d_path() gives an unlinked image, which avd
   * cannot open either, so #227's UNAVAILABLE answer is unchanged.
   * The self-delete check does not depend on this record at all (it
   * matches on the dentry, from the exec-time kprobe). Read once and
   * clamped so a
   * racing sysfs write of a bogus value cannot stall a worker
   * indefinitely. */
  {
    int delay_ms = READ_ONCE(av_toctou_test_delay_ms);

    if (delay_ms > 0) {
      if (delay_ms > AV_TOCTOU_TEST_DELAY_MAX_MS)
        delay_ms = AV_TOCTOU_TEST_DELAY_MAX_MS;
      msleep(delay_ms);
    }
  }

  /* d_path() of the kernel's own resolved f_path, used in every log
   * line below and recorded as this process's exec_path, which the
   * self-delete report prefers for its log line. Absolute, with
   * symlinks already followed (a /usr/bin/python symlink exec records
   * the real target's path), and " (deleted)"-suffixed if the file was
   * unlinked after the exec opened it. A d_path() failure leaves an
   * empty string rather than a misleading partial path. */
  abs_path = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!abs_path) {
    av_work_free(aw);
    return;
  }
  {
    char *p = d_path(&aw->file->f_path, abs_path, PATH_MAX);

    if (IS_ERR(p))
      abs_path[0] = '\0';
    else
      memmove(abs_path, p, strlen(p) + 1);
  }
  ret = hash_file_multi(aw->file, &digest, &ident);
  if (ret) {
    /* A hash failure skips both the signature match and the daemon
     * scan below, i.e. the exec is allowed without any verdict -
     * fail-open. Log it distinctly (with the errno) instead of
     * silently folding it into a clean skip: the errno tells a
     * benign race (-ENOENT, target already gone) apart from a
     * resource failure (-ENOMEM from the per-exec shash_desc/read-buffer
     * kmallocs - the transforms themselves are allocated once at load
     * now, so their allocation failure fails the load instead of an
     * exec - or a crypto_shash_init/update/final error) that left real
     * executables unscanned. pr_warn_ratelimited, not pr_info: an
     * unscanned exec is worth a warning, and _ratelimited caps the
     * flood if this ever fires per-exec under memory pressure.
     * Path goes through av_log_escape(), not %s or %*pE: a filename
     * can contain quotes or newlines, which would otherwise forge
     * extra fields or whole log lines in this quoted key=value
     * record (see logfmt.c for why %*pE isn't enough). Ordinary
     * paths render identically, so nothing greppable changes for
     * them. No behavior change - still skips to out. */
    esc_path = av_log_escape(abs_path, GFP_KERNEL);
    pr_warn_ratelimited("kernel-av: event=skip reason=hash-error path=\"%s\" "
                        "pid=%d err=%d\n",
                        av_log_str(esc_path), pid_nr(aw->target_pid), ret);
    kfree(esc_path);
    goto out;
  }

  /* Record regardless of verdict below - if this process gets killed
   * immediately it'll never reach the unlink hook anyway, and this
   * keeps the recording logic in one place rather than duplicated
   * across the signature-match/daemon-match/clean branches. */
  av_behavior_record_exec(aw->tgid, abs_path, aw->file->f_path.dentry,
                          digest.sha256, aw->start_time);

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
    struct av_scan_ident sid;
    bool have_sid = av_scan_ident_of(aw->file, &sid);
    int nl_ret;

    if (have_sid) {
      nl_ret = av_netlink_scan_request(
          abs_path, digest.sha256, pid_nr(aw->target_pid), &sid, &verdict,
          rule_name, sizeof(rule_name), DAEMON_TIMEOUT_MS);
    } else {
      /* We hashed the pinned file but can't name it to avd, which
       * could then only scan whatever the path names now - or answer
       * CLEAN if it names nothing. Don't ask: take the same "no
       * verdict for the hashed file" branch as an UNAVAILABLE reply,
       * so aw->fail_closed decides, never a by-path scan. */
      nl_ret = 0;
      verdict = AV_VERDICT_UNAVAILABLE;
    }
    if (nl_ret == 0 && verdict == AV_VERDICT_MALICIOUS) {
      snprintf(reason, sizeof(reason), "daemon:%s", rule_name);
      av_kill(aw->target_pid, abs_path, "daemon", reason, &ident);
    } else if (nl_ret == 0 && verdict == AV_VERDICT_UNAVAILABLE) {
      /* No verdict for the inode we hashed. Either avd answered
       * UNAVAILABLE - the path names a different file now
       * (rename-swap) or nothing (unlink), and /proc/<pid>/exe didn't
       * lead back to it either (issue #227) - or vfs_getattr() failed
       * and avd was never asked (have_sid above). That is "no
       * verdict", not "clean" - same policy as a timeout
       * (aw->fail_closed, captured at kprobe time), but logged
       * distinctly at warn because a swap in this window is exactly
       * what an evasion attempt looks like. */
      if (aw->fail_closed) {
        av_kill(aw->target_pid, abs_path, "fail-closed",
                have_sid ? "daemon-unavailable" : "identity-unavailable",
                &ident);
      } else {
        esc_path = av_log_escape(abs_path, GFP_KERNEL);
        pr_warn_ratelimited("kernel-av: event=unverified type=daemon "
                            "path=\"%s\" pid=%d sha256=%s dev=%u:%u ino=%lu "
                            "(%s)\n",
                            av_log_str(esc_path), pid_nr(aw->target_pid),
                            digest.sha256, MAJOR(ident.dev), MINOR(ident.dev),
                            ident.ino,
                            have_sid ? "daemon could not open the hashed file"
                                     : "could not read the hashed file's "
                                       "identity; daemon not asked");
        kfree(esc_path);
      }
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
      esc_path = av_log_escape(abs_path, GFP_KERNEL);
      pr_info_ratelimited("kernel-av: event=clean type=daemon path=\"%s\" "
                          "pid=%d md5=%s sha1=%s sha256=%s dev=%u:%u ino=%lu\n",
                          av_log_str(esc_path), pid_nr(aw->target_pid),
                          digest.md5, digest.sha1, digest.sha256,
                          MAJOR(ident.dev), MINOR(ident.dev), ident.ino);
      kfree(esc_path);
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
      esc_path = av_log_escape(abs_path, GFP_KERNEL);
      pr_info_ratelimited("kernel-av: event=clean type=fail-open path=\"%s\" "
                          "pid=%d md5=%s sha1=%s sha256=%s err=%d\n",
                          av_log_str(esc_path), pid_nr(aw->target_pid),
                          digest.md5, digest.sha1, digest.sha256, nl_ret);
      kfree(esc_path);
    }
  }

out:
  kfree(abs_path);
  av_work_free(aw);
}

/* Atomic context - the ONLY things allowed here: taking references,
 * GFP_ATOMIC allocation, reading regs, and scheduling work.
 *
 * Probes security_bprm_check(struct linux_binprm *bprm), which the
 * exec path calls from search_binary_handler() after opening the
 * target and before trying any binfmt loader. That one call site
 * covers execve, execveat (including AT_EMPTY_PATH and memfd fileless
 * exec, where bprm->file is the fd's own file), fexecve, and
 * kernel-initiated execs (kernel_execve(), usermode helpers), with no
 * syscall-specific argument decoding.
 *
 * This replaces kprobes on __x64_sys_execve/__x64_sys_execveat, which
 * had to strncpy_from_user() the pathname from atomic context. That
 * copy can't fault in a non-resident page, so a pathname on a cold
 * page made it fail with -EFAULT and the exec went unscanned
 * deterministically (#87, reproduced every CI run by
 * tests/qemu-boot/cold_launcher.c). Here the pathname is already in
 * kernel memory and nothing reads user memory at all.
 *
 * search_binary_handler() runs again for each interpreter level: a
 * "#!/bin/sh" script calls this once for the script, then again with
 * bprm->file = /bin/sh. Only the first level is scanned, matching the
 * old syscall-entry hook, which saw only the path passed to execve().
 * Scanning the interpreter too would hash /bin/sh on every script
 * exec, and the self-delete identity would become the interpreter's
 * instead of the script's. alloc_bprm() sets bprm->interp = bprm->filename, and
 * only bprm_change_interp() (binfmt_script, binfmt_misc) repoints
 * interp, so pointer equality identifies the first level. */
static int handler_pre_bprm_check(struct kprobe *p, struct pt_regs *regs) {
  struct linux_binprm *bprm =
      (struct linux_binprm *)regs_get_kernel_argument(regs, 0);
  struct av_work *aw;

  if (!bprm || !bprm->file)
    return 0;
  if (bprm->interp != bprm->filename)
    return 0;

  /* Before the work budget check: the identity is a cheap, bounded
   * record of its own, and an exec flood that exhausts the budget must
   * not also blind the self-delete check for that exec. */
  av_behavior_exec_ident_stage(bprm->file);

  if (!av_work_admit())
    return 0;

  aw = kmalloc(sizeof(*aw), GFP_ATOMIC);
  if (!aw) {
    av_work_release();
    return 0;
  }

  aw->file = get_file(bprm->file);
  aw->target_pid = get_task_pid(current, PIDTYPE_PID);
  aw->tgid = task_tgid_nr(current);
  aw->start_time = current->start_time;
  aw->fail_closed = atomic_read(&av_daemon_fail_closed);
  INIT_WORK(&aw->work, av_work_fn);
  queue_work(av_wq, &aw->work);

  return 0;
}

/* Probes security_bprm_committing_creds(), which begin_new_exec()
 * calls once per exec, after the point of no return. It promotes
 * whatever handler_pre_bprm_check() staged for this thread group to the
 * identity of the image now running (see struct av_exec_ident in
 * behavior.c for why staging and committing are separate). No argument
 * is needed: it promotes whatever handler_pre_bprm_check() staged. Atomic
 * context, like every pre-handler here. */
/* cppcheck-suppress constParameterCallback */
static int handler_pre_bprm_committing(struct kprobe *p, struct pt_regs *regs) {
  av_behavior_exec_ident_commit();
  return 0;
}

/* ---- self-delete: security_inode_unlink / security_inode_rename ---- */

struct av_selfdel_work {
  struct work_struct work;
  struct pid *target_pid;
  pid_t tgid;
  const struct dentry *cookie; /* compared, never dereferenced */
  bool overwrite;              /* rename over the image, not unlink */
  char *path;                  /* PATH_MAX, dentry_path_raw() fallback */
};

static void av_selfdel_work_fn(struct work_struct *w) {
  struct av_selfdel_work *sw = container_of(w, struct av_selfdel_work, work);

  av_behavior_report_self_delete(sw->tgid, sw->cookie, sw->path, PATH_MAX,
                                 sw->overwrite, sw->target_pid);
  kfree(sw->path);
  put_pid(sw->target_pid);
  kfree(sw);
  av_selfdel_release();
}

/* A matched self-delete whose report could not be queued: the process
 * removes its image unobserved, so say so. Atomic context. */
static void selfdel_missed(const char *why) {
  pr_warn_ratelimited("kernel-av: event=skip reason=%s pid=%d\n", why,
                      task_tgid_nr(current));
}

/* Called from the two inode-level probes below with the dentry about to
 * be removed (unlink) or replaced (rename's target). Atomic context.
 * The decision is made here, on the dentry the kernel resolved, so no
 * spelling of the name - symlinked directories, "..", bind mounts,
 * another mount namespace, /proc/self/cwd/... - changes the answer; see
 * struct av_exec_ident in behavior.c.
 *
 * Only a match costs anything beyond an RCU hash lookup. It then
 * renders a log name here, because the work item may not hold a
 * reference to the dentry (a dentry pinned past umount is a "busy
 * inodes" bug at superblock shutdown): dentry_path_raw() is RCU-walk
 * and seqlock based, safe in atomic context, and gives the path within
 * the dentry's filesystem. The report replaces it with the exec-time
 * d_path() when that was recorded.
 *
 * Admitted from av_selfdel_admit()'s own budget, not av_work_admit()
 * (shared with exec work) or the _nonexec one: a self-delete is a kill
 * path and the process is already matched, so neither a burst of exec
 * work nor a flood of unrelated unlinks may crowd its report out. A
 * report that is still dropped (budget or memory) is logged by
 * selfdel_missed().
 *
 * The report targets the thread GROUP (task_tgid()), not the calling
 * thread: the thread that unlinks can exit before the work runs, and a
 * thread pid that no longer names a task would skip the kill while the
 * rest of the process carried on. kill_with_reason() then kills the
 * group through that pid, which also works when the leader is already a
 * zombie. */
static void schedule_selfdel_work(const struct inode *dir,
                                  struct dentry *dentry, bool overwrite) {
  struct av_selfdel_work *sw;
  char *p;

  if (!av_behavior_exec_ident_match(dir, dentry))
    return;
  if (!av_selfdel_admit()) {
    selfdel_missed("selfdel-budget-full");
    return;
  }

  sw = kmalloc(sizeof(*sw), GFP_ATOMIC);
  if (!sw) {
    av_selfdel_release();
    selfdel_missed("selfdel-alloc-failed");
    return;
  }
  sw->path = kmalloc(PATH_MAX, GFP_ATOMIC);
  if (!sw->path) {
    kfree(sw);
    av_selfdel_release();
    selfdel_missed("selfdel-alloc-failed");
    return;
  }
  p = dentry_path_raw(dentry, sw->path, PATH_MAX);
  if (IS_ERR(p))
    strscpy(sw->path, "?", PATH_MAX);
  else
    memmove(sw->path, p, strlen(p) + 1);

  sw->cookie = dentry;
  sw->overwrite = overwrite;
  sw->tgid = task_tgid_nr(current);
  sw->target_pid = get_pid(task_tgid(current));
  INIT_WORK(&sw->work, av_selfdel_work_fn);
  queue_work(av_wq, &sw->work);
}

/* security_inode_unlink(struct inode *dir, struct dentry *dentry):
 * vfs_unlink() calls it with the target's inode locked, after
 * may_delete() and before the filesystem's ->unlink(). Every unlink
 * and unlinkat(fd, name, 0) reaches it whatever the spelling, and so
 * do kernel-internal callers (overlayfs's own upper-layer unlinks, in
 * the same task, pass the upper dentry, which never matches an exec'd
 * overlay dentry; nfsd and other kthreads never have an exec identity).
 * The unlink can still fail after this (a mountpoint's -EBUSY, the
 * filesystem refusing); the attempt is what is flagged, as with the
 * syscall-level hook before. */
static int handler_pre_inode_unlink(struct kprobe *p, struct pt_regs *regs) {
  const struct inode *dir =
      (const struct inode *)regs_get_kernel_argument(regs, 0);
  struct dentry *dentry = (struct dentry *)regs_get_kernel_argument(regs, 1);

  if (dentry)
    schedule_selfdel_work(dir, dentry, false);
  return 0;
}

/* security_inode_rename(old_dir, old_dentry, new_dir, new_dentry,
 * flags): a rename onto the exec'd name removes it just as an unlink
 * does (rename(decoy, own_exe)). vfs_rename() has already returned for
 * a rename of a name onto itself or another link of the same inode
 * (source == target), so this only sees real replacements. Skipped:
 * a negative new_dentry (nothing is replaced) and RENAME_EXCHANGE
 * (both names survive, swapped). Renaming the executed file itself
 * away is not a delete; its dentry moves with it, so an unlink of the
 * new name later still matches.
 *
 * This also catches an updater that renames a new build over its own
 * running binary. That is the atomic-update idiom, and it is also how
 * a dropper replaces itself with a decoy; the protected-exe list is the
 * per-binary escape hatch, as for every behavioral kill. */
static int handler_pre_inode_rename(struct kprobe *p, struct pt_regs *regs) {
  const struct inode *new_dir =
      (const struct inode *)regs_get_kernel_argument(regs, 2);
  struct dentry *new_dentry = (struct dentry *)regs_get_kernel_argument(regs, 3);
  unsigned int flags = (unsigned int)regs_get_kernel_argument(regs, 4);

  if (!new_dentry || (flags & RENAME_EXCHANGE) || !d_is_positive(new_dentry))
    return 0;
  schedule_selfdel_work(new_dir, new_dentry, true);
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

/* ---- security_file_open: write-intent open tracking at the VFS layer ----
 *
 * Replaces the __x64_sys_openat probe as the source for the rapid-write
 * and sensitive-path-write heuristics. What changes, and why:
 *   - No user-memory copy. The syscall-entry hook copied the filename
 *     with strncpy_from_user() in atomic context, which fails (the event
 *     is silently dropped) when the string sits on a page that is not
 *     resident, and reads the string before the kernel does, so another
 *     thread can rewrite it in between. Here the kernel has already
 *     resolved the file; we pin its struct path and freeze the sensitive
 *     path verdict at hook entry, before an ancestor can be renamed.
 *     The full pathname is re-rendered in the worker only for logging
 *     and the rapid-write hash - never for the sensitive-path decision.
 *   - Every spelling of open is seen: open(), creat(), openat2(),
 *     io_uring, not just openat().
 *   - The path is canonical (symlinks followed, no "..", no dfd/cwd
 *     resolution to get wrong), unlike resolve_absolute_path()'s purely
 *     lexical result.
 *   - Only opens that passed the permission checks are seen: a denied
 *     write to a sensitive path is no longer counted. That is deliberate:
 *     a write the kernel refused did no harm, and counting it only adds
 *     false-positive kill risk.
 *
 * Skipped: kernel threads, O_PATH, and FMODE_BACKING files (overlayfs
 * opens a backing file for every overlay open; the overlay file itself
 * is the one the user sees, and counting both would double every open in
 * a container toward the rapid-write threshold).
 *
 * security_file_open() runs before O_CREAT/O_EXCL/O_TRUNC are cleared
 * from f_flags (do_dentry_open()), so the existing write-intent flag test
 * in behavior.c still sees them. */
struct av_fileopen_work {
  struct work_struct work;
  struct pid *target_pid;
  pid_t pid; /* tgid, not thread id - same keying as av_openat_work */
  int flags;
  bool sensitive; /* verdict from the entry-rendered path */
  /* Entry rendering can fail (GFP_ATOMIC kmalloc or d_path() error). In
   * that case sensitive is not a real "no" verdict but "unknown", and the
   * worker must not treat it as non-sensitive - see av_fileopen_work_fn().
   * pseudo/noise have a safe default (false = "not excluded") and need no
   * such flag. */
  bool sensitive_known;
  bool pseudo;
  bool noise;
  u32 path_hash; /* rapid-write sliding-window key from the entry path */
  struct path path; /* pinned with path_get() in the entry handler, released
                     * in av_fileopen_work_fn(); d_path()'d there only for
                     * the log line and the rapid-write hash */
};

static void av_fileopen_work_fn(struct work_struct *w) {
  struct av_fileopen_work *fw = container_of(w, struct av_fileopen_work, work);
  char *buf = kmalloc(PATH_MAX, GFP_KERNEL);
  const char *abs_path = NULL;
  bool render_ok = false;
  bool sensitive;
  char fallback[128];

  if (buf) {
    char *rendered = d_path(&fw->path, buf, PATH_MAX);

    if (!IS_ERR(rendered)) {
      abs_path = rendered;
      render_ok = true;
    }
  }
  if (!abs_path) {
    /* Late rendering can fail (kmalloc, or ENAMETOOLONG after an
     * ancestor is renamed deeper). The frozen verdicts are still valid,
     * so the check must still run. A constant placeholder here would
     * merge every unresolved write into one rapid-write counter; the
     * (tgid, dentry) pair keeps unrelated files apart. */
    snprintf(fallback, sizeof(fallback), "<unresolved:%d:%p>", fw->pid,
             fw->path.dentry);
    abs_path = fallback;
  }

  if (fw->sensitive_known) {
    sensitive = fw->sensitive;
  } else {
    /* The entry handler could not render the path, so it has no policy
     * verdict to freeze. "unknown" must not silently become "not
     * sensitive": a write to /etc/passwd whose GFP_ATOMIC allocation
     * failed would otherwise escape the sensitive-path check. Classify
     * from the late render when it worked (best available information),
     * and fail closed otherwise so the check still runs. */
    sensitive = render_ok ? av_behavior_path_is_sensitive(abs_path) : true;
  }
  /* 'pseudo' and 'noise' are the entry-time decisions: reapplying either
   * exclusion to a worker-rendered path would drop a chrooted
   * /etc/passwd (rendered under /dev/) or turn /documents/fN into a
   * fake cache path under /.cache/rootfs/. */
  av_behavior_check_openat_preclassified(fw->pid, abs_path, fw->flags,
                                         fw->target_pid, sensitive,
                                         fw->pseudo, fw->noise,
                                         fw->path_hash);
  kfree(buf);
  path_put(&fw->path);
  put_pid(fw->target_pid);
  kfree(fw);
  av_work_release();
}

/* security_file_open(struct file *file) - entry half. Nothing is queued
 * here: the LSM/fanotify checks live inside the probed function and may
 * still reject the open. */
static int entry_file_open(struct kretprobe_instance *ri,
                           struct pt_regs *regs) {
  const struct file *file =
      (const struct file *)regs_get_kernel_argument(regs, 0);
  struct av_fileopen_work **slot = (struct av_fileopen_work **)ri->data;
  struct av_fileopen_work *fw;
  unsigned int flags;

  *slot = NULL;
  if (!file || (current->flags & PF_KTHREAD))
    return 0;
  if (file->f_mode & FMODE_BACKING)
    return 0;
  flags = file->f_flags;
  if (flags & O_PATH)
    return 0;
  /* Same cheap integer pre-filter as the syscall hook: read-only opens
   * are the overwhelming majority and behavior.c would discard them. */
  if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
    return 0;

  if (!av_work_admit_nonexec())
    return 0;

  fw = kmalloc(sizeof(*fw), GFP_ATOMIC);
  if (!fw) {
    av_work_release();
    return 0;
  }

  /* Freeze the policy input while the pathname is still the one the
   * kernel observed. A concurrent rename of an ancestor keeps fw->path
   * valid (path_get pins the object) but changes what d_path() would
   * return in the worker; the legacy openat hook copied the string and
   * kept the original classification. d_path() here is atomic-safe
   * (RCU/seqcount only) and uses the opening task's root, unlike the
   * workqueue thread's root. */
  {
    char *buf = kmalloc(PATH_MAX, GFP_ATOMIC);
    const char *entry_path = NULL;
    bool sensitive = false;
    bool pseudo = false;
    bool noise = false;
    u32 path_hash;

    if (buf) {
      entry_path = d_path(&file->f_path, buf, PATH_MAX);
      if (IS_ERR(entry_path))
        entry_path = NULL;
    }
    if (entry_path) {
      sensitive = av_behavior_path_is_sensitive(entry_path);
      pseudo = av_behavior_path_is_pseudo_fs(entry_path);
      noise = av_behavior_path_is_rapid_write_noise(entry_path);
      /* The counting key must be the observed pathname: a worker that
       * renders after a batch of renames can collapse /documents/f1..f51
       * onto /documents/sink and defeat the sliding-window threshold. */
      path_hash = av_behavior_path_hash(entry_path);
    } else {
      /* Entry rendering failed. Keep the key distinct per (tgid, dentry)
       * so unresolved opens do not merge into one bucket; a constant
       * placeholder here would have the same collapsing effect as a
       * late-rendered renamed path. */
      char fallback[128];

      snprintf(fallback, sizeof(fallback), "<unresolved:%d:%p>",
               task_tgid_nr(current), file->f_path.dentry);
      path_hash = av_behavior_path_hash(fallback);
    }
    fw->sensitive_known = (entry_path != NULL);
    kfree(buf);
    /* On a successful render all verdicts are frozen here. On failure,
     * pseudo/noise keep their safe "not excluded" defaults (so a genuine
     * cache/journal open is counted rather than dropped), path_hash is the
     * per-(tgid,dentry) placeholder, and 'sensitive' is flagged unknown:
     * the worker must not read the default false as a real "not sensitive"
     * verdict - it reclassifies from its own render or fails closed. */
    fw->sensitive = sensitive;
    fw->pseudo = pseudo;
    fw->noise = noise;
    fw->path_hash = path_hash;
  }

  fw->path = file->f_path;
  path_get(&fw->path);
  fw->flags = (int)flags;
  fw->pid = task_tgid_nr(current);
  fw->target_pid = get_task_pid(current, PIDTYPE_PID);
  *slot = fw;
  /* Per the kretprobe contract, 0 (not 1) means the return handler runs
   * on function return. Returning 1 would recycle the instance, skip
   * exit_file_open(), and leak the pinned path/pid/budget slot. */
  return 0;
}

/* Exit half: only a granted open is allowed to become a behavioral
 * event. security_file_open() calls call_int_hook(file_open, ...) and
 * fsnotify_open_perm() in its body, either of which can deny; counting
 * a rejected attempt would risk killing a process for a write the
 * kernel never permitted. */
static int exit_file_open(struct kretprobe_instance *ri,
                          struct pt_regs *regs) {
  struct av_fileopen_work **slot = (struct av_fileopen_work **)ri->data;
  struct av_fileopen_work *fw = *slot;

  if (!fw)
    return 0;

  if (regs_return_value(regs) != 0) {
    path_put(&fw->path);
    put_pid(fw->target_pid);
    kfree(fw);
    av_work_release();
    return 0;
  }

  INIT_WORK(&fw->work, av_fileopen_work_fn);
  queue_work(av_wq, &fw->work);
  return 0;
}

/* Register whichever open probe this load uses. Defined after the
 * handlers so the kretprobe callbacks are in scope. */
static int av_register_open_probe(void) {
  if (av_legacy_openat_hook) {
    kp_openat.pre_handler = handler_pre_openat;
    pr_info("kernel-av: av_legacy_openat_hook=1, write-intent opens tracked "
            "via __x64_sys_openat\n");
    return register_kprobe(&kp_openat);
  }
  /* The kernel default when maxactive == 0 is only max(10, 2*CPUs).
   * A fanotify/LSM permission check can hold an instance for a long
   * time; once that many opens are in flight, further opens skip the
   * entry handler entirely and the work budget never sees them. Size
   * the pool to the non-exec work-admission cap instead, so admission
   * (and its fail-open policy under overload) stays in control. */
  kr_file_open.maxactive = AV_MAX_INFLIGHT_WORK - AV_EXEC_RESERVED_WORK;
  kr_file_open.entry_handler = entry_file_open;
  kr_file_open.handler = exit_file_open;
  return register_kretprobe(&kr_file_open);
}

static void av_unregister_open_probe(void) {
  if (av_legacy_openat_hook)
    unregister_kprobe(&kp_openat);
  else
    unregister_kretprobe(&kr_file_open);
}

/* ---- unlink/unlinkat: sensitive-path deletion (self-delete is the
 * inode-level probe above) ---- */

struct av_unlink_work {
  struct work_struct work;
  struct pid *target_pid;
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
  av_behavior_check_unlink(abs_path, uw->target_pid);

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
 * match /etc/shadow's sensitive-path check. */
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

  ret = av_crypto_init();
  if (ret)
    return ret;

  ret = av_sigtable_init();
  if (ret)
    return ret;

  ret = av_sigtable_proc_init();
  if (ret) {
    pr_err("kernel-av: failed to create /proc/kernel_av_signatures: %d\n", ret);
    goto err_sigtable;
  }

  /* Deliberately left 0644 while the three IOC entries went 0640
   * root:hyprav (#143, "include or leave" - leave): this is a single
   * fail-open/fail-closed flag, not fingerprintable IOC content, and
   * the GUI policy display plus `avctl policy get` read it
   * unprivileged. Restricting reads would break those with no
   * hardening gain - writes stay root-only via DAC, same as before. */
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

  kp_bprm_check.pre_handler = handler_pre_bprm_check;
  ret = register_kprobe(&kp_bprm_check);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(" AV_EXEC_HOOK_SYMBOL ") failed: %d\n",
           ret);
    goto err_netlink;
  }

  ret = av_register_open_probe();
  if (ret < 0) {
    pr_err("kernel-av: register open probe (%s) failed: %d\n",
           av_legacy_openat_hook ? kp_openat.symbol_name
                                 : kr_file_open.kp.symbol_name, ret);
    goto err_kp_bprm_check;
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

  kp_bprm_committing.pre_handler = handler_pre_bprm_committing;
  ret = register_kprobe(&kp_bprm_committing);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(security_bprm_committing_creds) "
           "failed: %d\n",
           ret);
    goto err_kp_renameat2;
  }

  kp_inode_unlink.pre_handler = handler_pre_inode_unlink;
  ret = register_kprobe(&kp_inode_unlink);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(security_inode_unlink) failed: %d\n",
           ret);
    goto err_kp_bprm_committing;
  }

  kp_inode_rename.pre_handler = handler_pre_inode_rename;
  ret = register_kprobe(&kp_inode_rename);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe(security_inode_rename) failed: %d\n",
           ret);
    goto err_kp_inode_unlink;
  }

  pr_info("kernel-av: loaded, %zu signature(s) active\n", av_sigtable_count());
  return 0;

err_kp_inode_unlink:
  unregister_kprobe(&kp_inode_unlink);
err_kp_bprm_committing:
  unregister_kprobe(&kp_bprm_committing);
err_kp_renameat2:
  unregister_kprobe(&kp_renameat2);
err_kp_renameat:
  unregister_kprobe(&kp_renameat);
err_kp_rename:
  unregister_kprobe(&kp_rename);
err_kp_unlinkat:
  unregister_kprobe(&kp_unlinkat);
err_kp_unlink:
  unregister_kprobe(&kp_unlink);
err_kp_openat:
  av_unregister_open_probe();
err_kp_bprm_check:
  unregister_kprobe(&kp_bprm_check);
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
  /* Funnels every av_init() failure path, so one call here covers
   * them all (av_crypto_init() runs before anything else above). */
  av_crypto_exit();
  return ret;
}

static void __exit av_exit(void) {
  unregister_kprobe(&kp_inode_rename);
  unregister_kprobe(&kp_inode_unlink);
  unregister_kprobe(&kp_bprm_committing);
  unregister_kprobe(&kp_renameat2);
  unregister_kprobe(&kp_renameat);
  unregister_kprobe(&kp_rename);
  unregister_kprobe(&kp_unlinkat);
  unregister_kprobe(&kp_unlink);
  av_unregister_open_probe();
  unregister_kprobe(&kp_bprm_check);
  /* destroy_workqueue() flushes all pending work first, so no work
   * item can run against unloaded module .text after this returns. */
  destroy_workqueue(av_wq);
  av_netlink_exit();
  av_behavior_exit();
  remove_proc_entry("kernel_av_daemon_policy", NULL);
  av_sigtable_proc_exit();
  av_sigtable_exit();
  av_crypto_exit();
  pr_info("kernel-av: unloaded\n");
}

module_init(av_init);
module_exit(av_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Keane");
MODULE_DESCRIPTION("Signature-based execve detection with runtime-managed "
                   "signature DB and behavioral heuristics");
MODULE_VERSION("1.0.0");
