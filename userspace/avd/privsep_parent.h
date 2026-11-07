/*
 * privsep_parent.h - the main avd process shrinks itself once the spawner
 * exists (#103, Stage 2 step 2; see docs/privilege-separation.md, "Stage 2:
 * shrink the parent").
 *
 * Until now the main process stayed root with every capability. It does not
 * need them: it never changes credentials, signals a worker (the spawner does
 * that) or executes anything. What it does need, and what this header keeps:
 *
 *   CAP_NET_ADMIN        the genl ops are GENL_ADMIN_PERM (verdicts, policy)
 *   CAP_SYS_ADMIN        fanotify permission events, and the module's trust-
 *                        list writes
 *   CAP_DAC_READ_SEARCH  linkat(AT_EMPTY_PATH) into quarantine
 *   CAP_DAC_OVERRIDE     reading a mode-0000 quarantined file back
 *   CAP_FOWNER           chmod/unlink of a file owned by someone else
 *   CAP_CHOWN            restoring a quarantined file's original owner
 *
 * Dropped: everything else, in particular CAP_SETUID, CAP_SETGID, CAP_SETPCAP,
 * CAP_KILL, CAP_SYS_PTRACE, CAP_SYS_MODULE, CAP_SYS_RAWIO and CAP_MKNOD.
 * The audit behind this list is in the design doc; it was made by reading
 * every path-, owner- and credential-affecting call in avd.c, not by tracing a
 * run, so the list is conservative on purpose (nothing was removed that a
 * reading could not clear) and the first real run is what confirms it.
 *
 * Steps, same fail-closed shape as the spawner's lockdown: the first failing
 * step is returned with errno as that step left it, and avd refuses to start.
 *
 *   1. bounding set   cut to PS_PARENT_CAPS and read back
 *   2. capabilities   effective and permitted = PS_PARENT_CAPS, inheritable
 *                     (and so ambient) empty, read back
 *   3. NO_NEW_PRIVS   set and read back
 *
 * MUST be called after the spawner was forked: the spawner inherits its
 * capabilities from the process that forks it, and the bounding set only ever
 * shrinks. It MUST also be called before the process creates any other
 * thread: capabilities, the bounding set and NO_NEW_PRIVS belong to a THREAD
 * (capset() and the prctl()s act on the caller only), so a thread that already
 * exists keeps whatever it had, and one created afterwards inherits the
 * caller's reduced set. avd calls it in privsep_start(), between forking the
 * spawner and starting the client's reader thread; the test checks both
 * orderings. Needs CAP_SETPCAP effective for step 1, so it also must run
 * before anything drops that. A bounding set that lacks one of PS_PARENT_CAPS (a
 * systemd unit with a too-small CapabilityBoundingSet=) fails step 1.
 *
 * Header-only and dependency-free like the others; compiled standalone by
 * tests/test_privsep_parent.sh. x86-64 only.
 */

#ifndef AV_PRIVSEP_PARENT_H
#define AV_PRIVSEP_PARENT_H

#include "privsep_lockdown.h"

#define PS_PARENT_CAPS                                                         \
  ((1ULL << CAP_NET_ADMIN) | (1ULL << CAP_SYS_ADMIN) |                         \
   (1ULL << CAP_DAC_READ_SEARCH) | (1ULL << CAP_DAC_OVERRIDE) |                \
   (1ULL << CAP_FOWNER) | (1ULL << CAP_CHOWN))

enum ps_parent_step {
  PS_P_BOUNDING_SET = 1,
  PS_P_CAPABILITIES,
  PS_P_NO_NEW_PRIVS,
  PS_P_STEP_COUNT /* not a step */
};

#ifdef PS_WORKER_TEST_HOOKS
/* Test builds only, like ps_test_lock_fail_step. */
static int ps_test_parent_fail_step;
#define PS_PARENT_HOOK(step)                                                   \
  do {                                                                         \
    if (ps_test_parent_fail_step == (step)) {                                  \
      errno = EIO;                                                             \
      return (step);                                                           \
    }                                                                          \
  } while (0)
#else
#define PS_PARENT_HOOK(step) ((void)0)
#endif

/* Returns 0, or the number of the step that failed (errno as it left it). */
static inline int ps_parent_lockdown(void) {
  PS_PARENT_HOOK(PS_P_BOUNDING_SET);
  if (ps_bounding_set_to(PS_PARENT_CAPS) < 0)
    return PS_P_BOUNDING_SET;

  PS_PARENT_HOOK(PS_P_CAPABILITIES);
  if (ps_set_capabilities_to(PS_PARENT_CAPS) < 0)
    return PS_P_CAPABILITIES;

  PS_PARENT_HOOK(PS_P_NO_NEW_PRIVS);
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
    return PS_P_NO_NEW_PRIVS;

  return 0;
}

/* ------------------------------------------------------------------------
 * The main process's seccomp filter (#103, Stage 2 step 3)
 * ------------------------------------------------------------------------
 *
 * Installed once avd has finished starting up: rules and corpora loaded, the
 * spawner forked, the netlink socket bound, fanotify set up, the control
 * socket listening and every long-lived thread created. From then on avd's job
 * is to read files, answer the kernel and its clients, and move files into
 * and out of quarantine, so the filter allows that and nothing that only
 * startup needed: no socket(), bind(), listen(), fanotify_init(), capset(),
 * prctl(), execve*(), fork, ptrace(), mount(), bpf(), io_uring, module
 * loading, setuid() and friends, and so on.
 *
 * Installed with SECCOMP_FILTER_FLAG_TSYNC, so it applies to every thread at
 * once, including the ones that already exist (a filter set with prctl() would
 * cover the caller only). TSYNC needs NO_NEW_PRIVS, which ps_parent_lockdown()
 * set before any of those threads was created, so they all have it.
 *
 * The list comes from tracing avd with privilege separation on (strace -f over
 * tests/test_avd_socket.sh --privsep and tests/test_fanotify_exec.sh
 * --privsep, cut at the point where the filter is installed), then reading
 * avd.c for the paths those runs do not reach: the quarantine copy fallback
 * (fsync), the spawner kill in ps_client_stop() and glibc's abort() (tgkill).
 * The libc-level equivalents of a traced call are allowed alongside it
 * (openat and open, rename and renameat2, statx and newfstatat, ...), because
 * which one glibc picks differs between versions and a miss kills avd.
 *
 * The filter cannot narrow what the remaining file calls do: avd keeps
 * CAP_DAC_OVERRIDE and CAP_FOWNER to quarantine anyone's file, and openat,
 * write, rename and unlink take paths the filter cannot see. What it removes
 * is everything else a compromised main process could do as root.
 *
 * Argument checks (an int argument is compared on its low 32 bits, as in the
 * spawner's filter; an unsigned long is checked whole):
 *
 *   clone          only exactly pthread_create()'s flags (no fork, no
 *                  namespaces)
 *   clone3         fails with ENOSYS: its flags are in memory, where a filter
 *                  cannot look, and glibc falls back to clone() on ENOSYS
 *   mmap/mprotect  PROT_EXEC fails with EPERM: nothing after startup loads
 *                  code, so no new executable mapping can appear
 *   connect        only on the wake-up socket avd created before the filter,
 *                  used once to unblock the control thread's accept() at
 *                  shutdown
 *   kill           only SIGKILL to the spawner (ps_client_stop())
 *   tgkill         only on this process's own threads (abort(), raise())
 *   fanotify_mark  only FAN_MARK_ADD | FAN_MARK_FILESYSTEM (re-marking after
 *                  a mount) and only on the fanotify group; another
 *                  descriptor fails with EBADF, which is what the kernel
 *                  answers once the group has been closed
 *
 * Anything else is SECCOMP_RET_KILL_PROCESS, or SECCOMP_RET_LOG with
 * `log_only` (AVD_PRIVSEP_SECCOMP=log): the call then goes through and the
 * kernel logs it (audit type 1326, "SECCOMP"), for finding what another
 * distribution's libc calls before enforcing there. The architecture and x32
 * checks kill in both modes. */

/* pthread_create()'s clone flags in glibc: CLONE_VM | CLONE_FS | CLONE_FILES |
 * CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
 * CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID, no exit signal. Stable kernel
 * ABI, spelled out because <sched.h> needs _GNU_SOURCE. */
#define PS_CLONE_THREAD_FLAGS 0x003d0f00u

/* <sys/fanotify.h> values, stable ABI. */
#define PS_FAN_MARK_ADD 0x00000001u
#define PS_FAN_MARK_FILESYSTEM 0x00000100u

#define PS_PROT_EXEC 0x4u

/* The main process's unconditional list. */
static const int ps_allow_parent[] = {
    /* descriptors and files */
    SYS_read, SYS_write, SYS_readv, SYS_writev, SYS_pread64, SYS_lseek,
    SYS_close, SYS_dup, SYS_fcntl, SYS_fstat, SYS_newfstatat, SYS_statx,
    SYS_getdents64, SYS_readlink, SYS_readlinkat, SYS_open, SYS_openat,
    SYS_mkdir, SYS_mkdirat, SYS_chmod, SYS_fchmod, SYS_fchmodat, SYS_fchown,
    SYS_linkat, SYS_rename, SYS_renameat, SYS_renameat2, SYS_unlink,
    SYS_unlinkat, SYS_fsync, SYS_fdatasync,
    /* sockets that already exist: netlink, the spawner channel, workers, the
     * control socket and its connections */
    SYS_poll, SYS_ppoll, SYS_accept, SYS_accept4, SYS_recvmsg, SYS_sendmsg,
    SYS_getsockopt, SYS_setsockopt, SYS_shutdown,
    /* memory, threads, time, signals */
    SYS_munmap, SYS_mremap, SYS_brk, SYS_madvise, SYS_futex, SYS_sched_yield,
    SYS_set_robust_list, SYS_rseq, SYS_clock_gettime, SYS_clock_getres,
    SYS_gettimeofday, SYS_time, SYS_nanosleep, SYS_clock_nanosleep,
    SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigreturn,
    SYS_restart_syscall, SYS_getpid, SYS_gettid, SYS_getuid, SYS_geteuid,
    SYS_getgid, SYS_getegid, SYS_getrandom, SYS_wait4, SYS_exit,
    SYS_exit_group,
};
#define PS_ALLOW_PARENT_N (sizeof(ps_allow_parent) / sizeof(ps_allow_parent[0]))

struct ps_parent_filter {
  pid_t self_pid;    /* tgkill() target; this process */
  pid_t spawner_pid; /* kill() target; <= 0 allows no kill() */
  int wake_fd;       /* connect() descriptor; < 0 allows no connect() */
  int fan_fd;        /* fanotify_mark() descriptor; < 0 allows none */
  bool log_only;     /* SECCOMP_RET_LOG instead of KILL_PROCESS */
};

/* Build the main process's filter into `a`. Returns its length, or 0. */
static inline size_t ps_seccomp_build_parent(struct ps_asm *a,
                                             const struct ps_parent_filter *f) {
  ps_asm_init(a);
  if (f->self_pid <= 0) {
    a->err = true;
    return 0;
  }

  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARCH);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, PSL_NONE, PSL_KILL);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_NR);
  ps_asm_jump(a, BPF_JMP | BPF_JSET | BPF_K, PS_X32_BIT, PSL_KILL, PSL_NONE);

  for (size_t i = 0; i < PS_ALLOW_PARENT_N; i++)
    ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)ps_allow_parent[i],
                PSL_ALLOW, PSL_NONE);

  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_mmap, PSL_P_PROT,
              PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_mprotect, PSL_P_PROT,
              PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_clone, PSL_P_CLONE,
              PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_clone3, PSL_ENOSYS,
              PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_connect,
              f->wake_fd >= 0 ? PSL_P_CONNECT : PSL_DENY, PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_kill,
              f->spawner_pid > 0 ? PSL_P_KILL : PSL_DENY, PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_tgkill, PSL_P_TGKILL,
              PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_fanotify_mark,
              f->fan_fd >= 0 ? PSL_P_FANMARK : PSL_DENY, PSL_DENY);

  /* mmap(addr, len, prot, ...) and mprotect(addr, len, prot): prot is arg 2
   * of both. */
  ps_asm_bind(a, PSL_P_PROT);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(2));
  ps_asm_jump(a, BPF_JMP | BPF_JSET | BPF_K, PS_PROT_EXEC, PSL_EPERM, PSL_ALLOW);

  ps_asm_bind(a, PSL_P_CLONE);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_HI(0));
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, 0, PSL_NONE, PSL_DENY);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(0));
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, PS_CLONE_THREAD_FLAGS, PSL_ALLOW,
              PSL_DENY);

  if (f->wake_fd >= 0) {
    ps_asm_bind(a, PSL_P_CONNECT);
    ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(0));
    ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)f->wake_fd, PSL_ALLOW,
                PSL_DENY);
  }

  if (f->spawner_pid > 0) {
    ps_asm_bind(a, PSL_P_KILL);
    ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(0));
    ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)f->spawner_pid,
                PSL_NONE, PSL_DENY);
    ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(1));
    ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, PSL_ALLOW, PSL_DENY);
  }

  ps_asm_bind(a, PSL_P_TGKILL);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(0));
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)f->self_pid, PSL_ALLOW,
              PSL_DENY);

  /* The flags first, so a forbidden mark kind is denied on any descriptor. */
  if (f->fan_fd >= 0) {
    ps_asm_bind(a, PSL_P_FANMARK);
    ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(1));
    ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K,
                PS_FAN_MARK_ADD | PS_FAN_MARK_FILESYSTEM, PSL_NONE, PSL_DENY);
    ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(0));
    ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)f->fan_fd, PSL_ALLOW,
                PSL_EBADF);
  }

  ps_asm_bind(a, PSL_ALLOW);
  ps_asm_stmt(a, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  ps_asm_bind(a, PSL_EPERM);
  ps_asm_stmt(a, BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  ps_asm_bind(a, PSL_EBADF);
  ps_asm_stmt(a, BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EBADF & SECCOMP_RET_DATA));
  ps_asm_bind(a, PSL_ENOSYS);
  ps_asm_stmt(a, BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA));
  ps_asm_bind(a, PSL_DENY);
  ps_asm_stmt(a, BPF_RET | BPF_K,
              f->log_only ? SECCOMP_RET_LOG : SECCOMP_RET_KILL_PROCESS);
  ps_asm_bind(a, PSL_KILL);
  ps_asm_stmt(a, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

  return ps_asm_finish(a);
}

/* Install it on every thread of the process. Returns 0, or -1 with errno set:
 * EPERM without NO_NEW_PRIVS, E2BIG if the program did not build, ESRCH if a
 * thread could not be synchronised (the kernel then installed nothing), or
 * whatever seccomp() itself reported. */
static inline int ps_seccomp_install_parent(const struct ps_parent_filter *f) {
  struct ps_asm a;
  struct sock_fprog fprog;
  size_t n;
  long r;

  if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
    errno = EPERM;
    return -1;
  }
  n = ps_seccomp_build_parent(&a, f);
  if (n == 0) {
    errno = E2BIG;
    return -1;
  }
  fprog.len = (unsigned short)n;
  fprog.filter = a.prog;
  r = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
              &fprog);
  if (r > 0) { /* the id of a thread that could not be synchronised */
    errno = ESRCH;
    return -1;
  }
  return r == 0 ? 0 : -1;
}

#endif /* AV_PRIVSEP_PARENT_H */
