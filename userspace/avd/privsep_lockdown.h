/*
 * privsep_lockdown.h - the spawner's own lockdown (#103, Stage 1f; see
 * docs/privilege-separation.md, "The spawner" and "Seccomp filters stack").
 *
 * The spawner is the only process that keeps root's power after avd starts
 * (it has to change a worker's uid and signal it). It never reads a scanned
 * file, so it is not part of the attack surface, but nothing about its job
 * needs the rest of root's capabilities or syscalls either. This header
 * removes them:
 *
 *   1. bounding set    cut to CAP_SETUID, CAP_SETGID, CAP_SETPCAP, CAP_KILL
 *   2. capabilities    effective and permitted the same four, inheritable
 *                      (and so ambient) empty, read back
 *   3. NO_NEW_PRIVS    set and read back
 *   4. parent death    PR_SET_PDEATHSIG again, read back, and getppid() must
 *                      still be avd (see "Why again" below)
 *   5. seccomp         a filter that is a SUPERSET of the worker allowlist
 *                      plus what only the spawner needs, installed last
 *
 * Same fail-closed shape as ps_worker_harden(): the first failing step is
 * returned (errno left as that step set it) and the spawner exits instead of
 * serving, so avd sees the control channel close and refuses to run.
 *
 * Why the filter must be a superset. A seccomp filter is inherited across
 * fork() and can only ever be added to: every attached filter is evaluated and
 * the strictest verdict wins. Each worker is forked by the spawner and then
 * hardens itself, so it runs its whole hardening sequence (close_range,
 * prlimit64, prctl, setgroups, setresuid, capset, ...) and reports ready under
 * THIS filter before its own tight one is installed, and afterwards the
 * worker's filter and this one both apply. A narrow spawner filter would
 * therefore kill the workers it creates. The test suite checks that every
 * syscall the worker filter allows is also allowed here.
 *
 * Why again (step 4). The kernel clears the parent-death signal when the
 * process's credentials change in a way that can widen access. Dropping
 * capabilities should not do that, but the spawner's contract with avd is
 * "if avd dies, so do I", so it is set again after the drop and read back,
 * which makes a future reordering or a kernel that behaves differently fail
 * closed instead of leaving an orphaned process holding CAP_SETUID.
 *
 * This guards against mistakes, not against a compromised spawner: it keeps
 * CAP_SETUID and CAP_SETGID, the filter has to allow the credential calls
 * (workers make them under it), and changing the effective uid or gid clears
 * the signal. See docs/privilege-separation.md, "Residual risk: a compromised
 * spawner can outlive avd".
 *
 * Same arrangement as privsep_worker.h: header-only, dependency-free, compiled
 * standalone by tests/test_privsep_lockdown.sh. x86-64 only (the worker header
 * already refuses anything else).
 */

#ifndef AV_PRIVSEP_LOCKDOWN_H
#define AV_PRIVSEP_LOCKDOWN_H

#include "privsep_worker.h"

/* ------------------------------------------------------------------------
 * Capabilities the spawner keeps
 * ------------------------------------------------------------------------ */

/* CAP_SETUID and CAP_SETGID change a worker's credentials, CAP_SETPCAP lets a
 * worker empty its bounding set (PR_CAPBSET_DROP needs it in the EFFECTIVE set
 * of the forked child, which inherits it from here), CAP_KILL signals a worker
 * that runs as a different uid. Nothing else. */
#define PS_SPAWNER_CAPS                                                        \
  ((1ULL << CAP_SETUID) | (1ULL << CAP_SETGID) | (1ULL << CAP_SETPCAP) |       \
   (1ULL << CAP_KILL))

/* The steps of ps_spawner_lockdown(), in the order they run. */
enum ps_lock_step {
  PS_L_BOUNDING_SET = 1,
  PS_L_CAPABILITIES,
  PS_L_NO_NEW_PRIVS,
  PS_L_PDEATHSIG,
  PS_L_SECCOMP,
  PS_L_STEP_COUNT /* not a step */
};

#ifdef PS_WORKER_TEST_HOOKS
/* Test builds only: makes that lockdown step fail with EIO before it does
 * anything. Absent from a production build, so there is no switch to flip. */
static int ps_test_lock_fail_step;
#define PS_LOCK_HOOK(step)                                                     \
  do {                                                                         \
    if (ps_test_lock_fail_step == (step)) {                                    \
      errno = EIO;                                                             \
      return (step);                                                           \
    }                                                                          \
  } while (0)
#else
#define PS_LOCK_HOOK(step) ((void)0)
#endif

/* Reduce the bounding set to exactly `keep` (bit n = capability n) and read it
 * back. A capability in `keep` that the bounding set did not hold is an error:
 * the later capset() could not raise it anyway, and it means the spawner was
 * not started with the power it needs. Needs CAP_SETPCAP. */
static inline int ps_bounding_set_to(uint64_t keep) {
  for (int pass = 0; pass < 2; pass++) {
    for (int cap = 0;; cap++) {
      int r = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
      bool want;

      if (r < 0) {
        if (errno == EINVAL)
          break; /* past the last capability */
        return -1;
      }
      want = cap < 64 && ((keep >> cap) & 1u);
      if (pass == 0) {
        if (r == 1 && !want && prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0)
          return -1;
      } else if ((r == 1) != want) { /* the read-back */
        errno = EPERM;
        return -1;
      }
    }
  }
  return 0;
}

/* Effective and permitted = `keep`, inheritable empty, then read all three
 * back. Clearing inheritable also empties the ambient set, which the kernel
 * only allows to hold what is both permitted and inheritable. */
static inline int ps_set_capabilities_to(uint64_t keep) {
  struct __user_cap_header_struct hdr = {.version = _LINUX_CAPABILITY_VERSION_3,
                                         .pid = 0};
  struct __user_cap_data_struct data[2];

  memset(data, 0, sizeof(data));
  data[0].effective = data[0].permitted = (uint32_t)keep;
  data[1].effective = data[1].permitted = (uint32_t)(keep >> 32);
  if (syscall(SYS_capset, &hdr, data) < 0)
    return -1;

  hdr.version = _LINUX_CAPABILITY_VERSION_3;
  hdr.pid = 0;
  memset(data, 0xff, sizeof(data));
  if (syscall(SYS_capget, &hdr, data) < 0)
    return -1;
  if (data[0].effective != (uint32_t)keep ||
      data[0].permitted != (uint32_t)keep || data[0].inheritable != 0 ||
      data[1].effective != (uint32_t)(keep >> 32) ||
      data[1].permitted != (uint32_t)(keep >> 32) || data[1].inheritable != 0) {
    errno = EPERM;
    return -1;
  }
  return 0;
}

/* ------------------------------------------------------------------------
 * The spawner's seccomp filter
 * ------------------------------------------------------------------------ */

/* Syscalls the spawner needs on top of the worker's list, found by tracing a
 * real spawner and the hardening of a real worker (strace -f over spawn, scan,
 * KILL, EXITED and shutdown) rather than by reading the code:
 *
 *  - its own loop: poll, wait4, getpid (the pid it records before fork),
 *    getppid, and recvmsg/sendmsg on the control channel and the worker
 *    sockets (their descriptor numbers vary, so no fd check is possible here;
 *    the worker's own filter pins its single descriptor)
 *  - the forked child before its own filter exists: set_robust_list (glibc
 *    runs it in every fork child), close_range, the credential calls
 *    setgroups/setresgid/setresuid and their read-backs getresuid/getresgid/
 *    getgroups, setuid/setgid (hardening probes that setuid(0) now FAILS, and
 *    a killed probe would be a worker that can never start), capget/capset.
 *    Also prlimit64, prctl, clone and kill, which are argument-checked below.
 *
 * Deliberately absent, so a compromised spawner cannot use them: open*,
 * socket, connect, bind, execve*, ptrace, write, every filesystem call,
 * mount, unshare, setns, bpf, io_uring, clone3 and signalfd4 (the spawner
 * calls it before this filter exists). rt_sigaction is allowed, through the
 * worker list. */
static const int ps_allow_spawner_extra[] = {
    SYS_poll,       SYS_wait4,     SYS_getpid,    SYS_getppid,
    SYS_recvmsg,    SYS_sendmsg,   SYS_set_robust_list,
    SYS_close_range,
    SYS_setgroups,  SYS_setresgid, SYS_setresuid, SYS_setuid,
    SYS_setgid,     SYS_getresuid, SYS_getresgid, SYS_getgroups,
    SYS_capget,     SYS_capset,
};
#define PS_ALLOW_SPAWNER_EXTRA_N                                               \
  (sizeof(ps_allow_spawner_extra) / sizeof(ps_allow_spawner_extra[0]))

/* prctl options the spawner and the hardening of its children use. Everything
 * else (PR_SET_DUMPABLE, PR_SET_MM, PR_SET_NAME, ...) is killed. */
static const int ps_allow_prctl_opts[] = {
    PR_SET_PDEATHSIG, PR_GET_PDEATHSIG, PR_SET_SECCOMP,
    PR_CAPBSET_READ,  PR_CAPBSET_DROP,  PR_SET_NO_NEW_PRIVS,
    PR_GET_NO_NEW_PRIVS,
};
#define PS_ALLOW_PRCTL_OPTS_N                                                  \
  (sizeof(ps_allow_prctl_opts) / sizeof(ps_allow_prctl_opts[0]))

/* fork() in glibc is clone(CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID |
 * SIGCHLD). Anything else (CLONE_VM, CLONE_THREAD, any CLONE_NEW*, a different
 * exit signal) is not a fork and is killed. These values are stable kernel ABI;
 * <sched.h> only defines them under _GNU_SOURCE, which a header cannot set. */
#define PS_CLONE_CHILD_CLEARTID 0x00200000u
#define PS_CLONE_CHILD_SETTID 0x01000000u

/* A tiny assembler: forward jumps to labels, resolved at the end. The worker's
 * filter computes its offsets by hand, which is fine for 40 instructions and
 * error-prone for twice that. A jump to a label that was bound earlier, or that
 * is more than 255 instructions away (the BPF limit), makes the whole build
 * fail, and the caller then refuses to install anything. */
#define PS_ASM_MAX 160

enum ps_lbl {
  PSL_NONE = -1, /* fall through to the next instruction */
  PSL_ALLOW = 0,
  PSL_KILL,
  PSL_STAT,
  PSL_PRCTL,
  PSL_PDEATH,
  PSL_KILLSIG,
  PSL_CLONE,
  PSL_SOCKPAIR,
  PSL_PRLIMIT,
  /* used only by the main process's filter (privsep_parent.h) */
  PSL_DENY,
  PSL_EPERM,
  PSL_EBADF,
  PSL_ENOSYS,
  PSL_P_PROT,
  PSL_P_CLONE,
  PSL_P_CONNECT,
  PSL_P_KILL,
  PSL_P_TGKILL,
  PSL_P_FANMARK,
  PSL_COUNT
};

struct ps_asm {
  struct sock_filter prog[PS_ASM_MAX];
  int jt[PS_ASM_MAX]; /* label for the true branch, or PSL_NONE */
  int jf[PS_ASM_MAX];
  size_t pos[PSL_COUNT];
  bool bound[PSL_COUNT];
  size_t n;
  bool err;
};

static inline void ps_asm_init(struct ps_asm *a) {
  memset(a, 0, sizeof(*a));
  for (size_t i = 0; i < PS_ASM_MAX; i++)
    a->jt[i] = a->jf[i] = PSL_NONE;
}

static inline void ps_asm_stmt(struct ps_asm *a, uint16_t code, uint32_t k) {
  if (a->n >= PS_ASM_MAX) {
    a->err = true;
    return;
  }
  a->prog[a->n++] = PS_BPF_STMT(code, k);
}

static inline void ps_asm_jump(struct ps_asm *a, uint16_t code, uint32_t k,
                               int jt, int jf) {
  if (a->n >= PS_ASM_MAX) {
    a->err = true;
    return;
  }
  a->jt[a->n] = jt;
  a->jf[a->n] = jf;
  a->prog[a->n++] = PS_BPF_JUMP(code, k, 0, 0);
}

static inline void ps_asm_bind(struct ps_asm *a, int label) {
  if (label < 0 || label >= PSL_COUNT || a->bound[label]) {
    a->err = true;
    return;
  }
  a->pos[label] = a->n;
  a->bound[label] = true;
}

/* Resolve every label into a jump offset. Returns the program length, or 0. */
static inline size_t ps_asm_finish(struct ps_asm *a) {
  if (a->err)
    return 0;
  for (size_t i = 0; i < a->n; i++) {
    int *lab[2] = {&a->jt[i], &a->jf[i]};
    uint8_t *off[2] = {&a->prog[i].jt, &a->prog[i].jf};

    for (int b = 0; b < 2; b++) {
      size_t target;

      if (*lab[b] == PSL_NONE)
        continue;
      if (*lab[b] < 0 || *lab[b] >= PSL_COUNT || !a->bound[*lab[b]])
        return 0;
      target = a->pos[*lab[b]];
      if (target <= i || target - (i + 1) > 255)
        return 0; /* backwards, or out of range */
      *off[b] = (uint8_t)(target - (i + 1));
    }
  }
  return a->n;
}

/* The int-typed arguments below (prctl's option, kill's signal, socketpair's
 * domain, prlimit64's pid) are compared by their low 32 bits only, because
 * that is all the kernel looks at: the upper half of a register holding an int
 * is not defined, and a filter that insisted on zero there could reject a
 * legitimate call. clone's flags are an unsigned long and are checked whole. */

/* Build the spawner filter into `a`. Returns its length, or 0.
 *
 *   arch must be x86-64 and the x32 bit clear
 *   worker list + spawner list                    -> allow
 *   newfstatat   only with AT_EMPTY_PATH          (as the worker's filter)
 *   prctl        only the options listed above; PR_SET_PDEATHSIG only with
 *                SIGKILL
 *   kill         only with SIGKILL (any target, see below)
 *   clone        only exactly fork()'s flags
 *   socketpair   only AF_UNIX
 *   prlimit64    only on itself (pid 0)
 *   anything else                                 -> SECCOMP_RET_KILL_PROCESS */
static inline size_t ps_seccomp_build_spawner(struct ps_asm *a) {
  ps_asm_init(a);

  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARCH);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, PSL_NONE, PSL_KILL);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_NR);
  ps_asm_jump(a, BPF_JMP | BPF_JSET | BPF_K, PS_X32_BIT, PSL_KILL, PSL_NONE);

  for (size_t i = 0; i < PS_ALLOW_PLAIN_N; i++)
    ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)ps_allow_plain[i],
                PSL_ALLOW, PSL_NONE);
  for (size_t i = 0; i < PS_ALLOW_SPAWNER_EXTRA_N; i++)
    ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)ps_allow_spawner_extra[i],
                PSL_ALLOW, PSL_NONE);

  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_newfstatat, PSL_STAT,
              PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_prctl, PSL_PRCTL,
              PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_kill, PSL_KILLSIG,
              PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_clone, PSL_CLONE,
              PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_socketpair,
              PSL_SOCKPAIR, PSL_NONE);
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_prlimit64, PSL_PRLIMIT,
              PSL_NONE);
  ps_asm_stmt(a, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS); /* nothing matched */

  ps_asm_bind(a, PSL_STAT);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(3));
  ps_asm_jump(a, BPF_JMP | BPF_JSET | BPF_K, AT_EMPTY_PATH, PSL_ALLOW, PSL_KILL);

  ps_asm_bind(a, PSL_PRCTL);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(0));
  for (size_t i = 0; i < PS_ALLOW_PRCTL_OPTS_N; i++)
    ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)ps_allow_prctl_opts[i],
                ps_allow_prctl_opts[i] == PR_SET_PDEATHSIG ? PSL_PDEATH
                                                           : PSL_ALLOW,
                i + 1 == PS_ALLOW_PRCTL_OPTS_N ? PSL_KILL : PSL_NONE);

  /* PR_SET_PDEATHSIG only with SIGKILL. The option is on the list so that
   * hardening can set it, and with any other signal (0 clears it) it would
   * be the easiest way for a compromised spawner to outlive avd. This closes
   * that route only: setresgid() and friends are allowed (workers need them
   * under this filter) and clear the signal too, so it is not a guarantee.
   * The argument is an unsigned long, so the upper half must be zero too. */
  ps_asm_bind(a, PSL_PDEATH);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_HI(1));
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, 0, PSL_NONE, PSL_KILL);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(1));
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, PSL_ALLOW, PSL_KILL);

  /* Only the SIGNAL is pinned, not the target: the spawner holds CAP_KILL and
   * the filter cannot know which pids are its workers. Pinning avd's pid would
   * not close this either, since kill() on any of avd's thread ids signals the
   * whole process. See docs/privilege-separation.md, "Residual risk: the
   * spawner can signal any process". */
  ps_asm_bind(a, PSL_KILLSIG);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(1));
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, PSL_ALLOW, PSL_KILL);

  /* The exit signal is the low byte of the flags, so mask the two optional
   * flags out and require what is left to be exactly SIGCHLD. The upper half
   * must be zero: a fork never sets it, and how much of it the kernel looks at
   * has differed between versions, so nothing is left to depend on. */
  ps_asm_bind(a, PSL_CLONE);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_HI(0));
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, 0, PSL_NONE, PSL_KILL);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(0));
  ps_asm_stmt(a, BPF_ALU | BPF_AND | BPF_K,
              ~(PS_CLONE_CHILD_CLEARTID | PS_CLONE_CHILD_SETTID));
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, SIGCHLD, PSL_ALLOW, PSL_KILL);

  ps_asm_bind(a, PSL_SOCKPAIR);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(0));
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, PSL_ALLOW, PSL_KILL);

  ps_asm_bind(a, PSL_PRLIMIT);
  ps_asm_stmt(a, BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(0));
  ps_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, 0, PSL_ALLOW, PSL_KILL);

  ps_asm_bind(a, PSL_ALLOW);
  ps_asm_stmt(a, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  ps_asm_bind(a, PSL_KILL);
  ps_asm_stmt(a, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

  return ps_asm_finish(a);
}

/* Install it. NO_NEW_PRIVS must already be set. */
static inline int ps_seccomp_install_spawner(void) {
  struct ps_asm a;
  struct sock_fprog fprog;
  size_t n = ps_seccomp_build_spawner(&a);

  if (n == 0) {
    errno = E2BIG;
    return -1;
  }
  fprog.len = (unsigned short)n;
  fprog.filter = a.prog;
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0);
}

/* ------------------------------------------------------------------------
 * The ordered, fail-closed sequence
 * ------------------------------------------------------------------------ */

/* Run every step in order; stop at the first failure and return its step
 * number, or 0 once the spawner is locked down. `expect_ppid` is the pid of
 * the process that forked the spawner (avd). Call it once the spawner has
 * finished its own setup (the signalfd), because the filter does not allow
 * signalfd4. */
static inline int ps_spawner_lockdown(pid_t expect_ppid) {
  PS_LOCK_HOOK(PS_L_BOUNDING_SET);
  if (ps_bounding_set_to(PS_SPAWNER_CAPS) < 0)
    return PS_L_BOUNDING_SET;

  PS_LOCK_HOOK(PS_L_CAPABILITIES);
  if (ps_set_capabilities_to(PS_SPAWNER_CAPS) < 0)
    return PS_L_CAPABILITIES;

  PS_LOCK_HOOK(PS_L_NO_NEW_PRIVS);
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
    return PS_L_NO_NEW_PRIVS;

  PS_LOCK_HOOK(PS_L_PDEATHSIG);
  {
    int sig = -1;

    errno = 0;
    if (expect_ppid <= 0 || prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0 ||
        prctl(PR_GET_PDEATHSIG, &sig, 0, 0, 0) < 0 || sig != SIGKILL ||
        getppid() != expect_ppid) {
      if (errno == 0)
        errno = ESRCH;
      return PS_L_PDEATHSIG;
    }
  }

  PS_LOCK_HOOK(PS_L_SECCOMP);
  if (ps_seccomp_install_spawner() < 0)
    return PS_L_SECCOMP;

  return 0;
}

#endif /* AV_PRIVSEP_LOCKDOWN_H */
