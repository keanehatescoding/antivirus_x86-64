/*
 * privsep_worker.h - worker side of avd's privilege separation (#103,
 * Stage 1b; see docs/privilege-separation.md, "Worker hardening fails
 * closed", "IPC" and "Seccomp allowlist (worker)").
 *
 * Three independent pieces, all header-only and dependency-free (standard
 * and Linux UAPI headers only) so tests/test_privsep_worker.sh compiles this
 * exact file standalone, same arrangement as privsep_proto.h:
 *
 *   ps_worker_harden()  the ordered, fail-closed hardening sequence a freshly
 *                       forked worker runs before it may report ready
 *   ps_seccomp_install()  the hand-emitted BPF allowlist (last hardening step)
 *   ps_worker_run()     the request/reply loop: one SCM_RIGHTS fd in, one
 *                       fixed-size struct ps_reply out
 *
 * Nothing here is wired into avd yet. The spawner that forks workers, the
 * readiness report and the parent-side dispatch arrive in the next slices;
 * the scan itself plugs in as a callback so this header never needs YARA,
 * ssdeep or TLSH.
 *
 * x86-64 only: the seccomp filter checks AUDIT_ARCH_X86_64 and kills anything
 * else (including x32 syscall numbers). A port (#105) must add its own table.
 */

#ifndef AV_PRIVSEP_WORKER_H
#define AV_PRIVSEP_WORKER_H

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "privsep_proto.h"

/* Not every libc exposes these without _GNU_SOURCE, and a header that other
 * files include after <fcntl.h> cannot turn it on. */
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#if !defined(__x86_64__)
#error "privsep_worker.h: the seccomp allowlist is x86-64 only (see #105)"
#endif

/* ------------------------------------------------------------------------
 * Hardening
 * ------------------------------------------------------------------------ */

/* The steps of ps_worker_harden(), in the order they run. A failure returns
 * the number of the step that failed (errno is left as that step set it), so
 * the spawner can log which one and the tests can inject a failure at each.
 *
 * This is the order in docs/privilege-separation.md with two deliberate
 * differences:
 *  - the bounding set is emptied BEFORE the credential change.
 *    PR_CAPBSET_DROP needs CAP_SETPCAP in the effective set, and changing
 *    the real, effective and saved uid away from 0 clears the effective and
 *    permitted sets, so dropping afterwards fails with EPERM;
 *  - descriptors are closed BEFORE the rlimits are lowered, so the
 *    close_range()-less fallback can still see every descriptor number. */
enum ps_harden_step {
  PS_H_CLOSE_FDS = 1,
  PS_H_RLIMITS,
  PS_H_BOUNDING_SET,
  PS_H_CREDENTIALS,
  PS_H_CAPABILITIES,
  PS_H_NO_NEW_PRIVS,
  PS_H_PDEATHSIG,
  PS_H_SECCOMP,
  PS_H_STEP_COUNT /* not a step */
};

struct ps_harden_cfg {
  uid_t uid;       /* dedicated worker user; 0 is rejected */
  gid_t gid;       /* dedicated worker group; 0 is rejected */
  int ipc_fd;      /* the worker's end of its socketpair; kept open */
  int log_fd;      /* kept open too, or -1 for none (the worker logs nothing) */
  pid_t expect_ppid; /* the spawner's pid, recorded before it forks */
  rlim_t as_bytes;   /* RLIMIT_AS */
  rlim_t cpu_seconds; /* RLIMIT_CPU */
  rlim_t nofile;      /* RLIMIT_NOFILE: small, a leak must fail fast */
};

#ifdef PS_WORKER_TEST_HOOKS
/* Test builds only. `ps_test_fail_step` makes that step fail with EIO before
 * it does anything; `ps_test_ran` records every step that started. Neither
 * exists in a production build, so there is no switch for an attacker or a
 * misconfiguration to flip. */
static int ps_test_fail_step;
static unsigned ps_test_ran;
#define PS_HOOK(step)                                                          \
  do {                                                                         \
    ps_test_ran |= 1u << (step);                                               \
    if (ps_test_fail_step == (step)) {                                         \
      errno = EIO;                                                             \
      return (step);                                                           \
    }                                                                          \
  } while (0)
#else
#define PS_HOOK(step) ((void)0)
#endif

static inline int ps_set_rlimit(int res, rlim_t v) {
  struct rlimit rl = {.rlim_cur = v, .rlim_max = v};
  return setrlimit(res, &rl);
}

/* Close every descriptor except the (up to two) we were told to keep.
 * close_range() when the kernel has it, a bounded loop otherwise. */
static inline int ps_close_all_but(int keep_a, int keep_b) {
  int lo = keep_a < keep_b ? keep_a : keep_b;
  int hi = keep_a < keep_b ? keep_b : keep_a;
  unsigned int ranges[3][2];
  int n = 0;

  if (keep_a < 0 && keep_b < 0) {
    ranges[n][0] = 0;
    ranges[n][1] = ~0u;
    n++;
  } else if (keep_a < 0 || keep_b < 0) {
    int k = keep_a < 0 ? keep_b : keep_a;
    if (k > 0) {
      ranges[n][0] = 0;
      ranges[n][1] = (unsigned)k - 1;
      n++;
    }
    ranges[n][0] = (unsigned)k + 1;
    ranges[n][1] = ~0u;
    n++;
  } else {
    if (lo > 0) {
      ranges[n][0] = 0;
      ranges[n][1] = (unsigned)lo - 1;
      n++;
    }
    if (hi > lo + 1) {
      ranges[n][0] = (unsigned)lo + 1;
      ranges[n][1] = (unsigned)hi - 1;
      n++;
    }
    ranges[n][0] = (unsigned)hi + 1;
    ranges[n][1] = ~0u;
    n++;
  }

  for (int i = 0; i < n; i++) {
    if (syscall(SYS_close_range, ranges[i][0], ranges[i][1], 0) == 0)
      continue;
    if (errno != ENOSYS)
      return -1;
    /* Old kernel: walk the range up to the descriptor limit. Callers close
     * descriptors before lowering RLIMIT_NOFILE, so the current limit is
     * an upper bound on any open descriptor number. */
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0)
      return -1;
    for (long fd = ranges[i][0]; fd <= (long)ranges[i][1] && fd < maxfd; fd++)
      if (close((int)fd) < 0 && errno != EBADF)
        return -1;
  }
  return 0;
}

/* Empty the bounding set. Walks capabilities until the kernel says one does
 * not exist, so it needs no knowledge of how many there are and no /proc.
 * Needs CAP_SETPCAP; failure means we are not running as intended. */
static inline int ps_drop_bounding_set(void) {
  for (int cap = 0;; cap++) {
    int r = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
    if (r < 0) {
      if (errno == EINVAL)
        break; /* past the last capability */
      return -1;
    }
    if (r == 1 && prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0)
      return -1;
  }
  /* Read it back: every capability must now be absent. */
  for (int cap = 0;; cap++) {
    int r = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
    if (r < 0)
      return errno == EINVAL ? 0 : -1;
    if (r != 0) {
      errno = EPERM;
      return -1;
    }
  }
}

/* setgroups(0), then gid, then uid, then prove the change cannot be undone. */
/* The worker is single-threaded, so the raw syscalls are exactly what the
 * libc wrappers would do (minus their all-threads broadcast) and need no
 * _GNU_SOURCE. */
static inline int ps_setresuid(uid_t r, uid_t e, uid_t s) {
  return (int)syscall(SYS_setresuid, r, e, s);
}
static inline int ps_setresgid(gid_t r, gid_t e, gid_t s) {
  return (int)syscall(SYS_setresgid, r, e, s);
}
static inline int ps_getresuid(uid_t *r, uid_t *e, uid_t *s) {
  return (int)syscall(SYS_getresuid, r, e, s);
}
static inline int ps_getresgid(gid_t *r, gid_t *e, gid_t *s) {
  return (int)syscall(SYS_getresgid, r, e, s);
}

static inline int ps_drop_credentials(uid_t uid, gid_t gid) {
  uid_t r, e, s;
  gid_t rg, eg, sg;

  if (uid == 0 || gid == 0) {
    errno = EINVAL;
    return -1;
  }
  if (setgroups(0, NULL) < 0)
    return -1;
  if (ps_setresgid(gid, gid, gid) < 0)
    return -1;
  if (ps_setresuid(uid, uid, uid) < 0)
    return -1;

  if (ps_getresuid(&r, &e, &s) < 0 || r != uid || e != uid || s != uid) {
    errno = EPERM;
    return -1;
  }
  if (ps_getresgid(&rg, &eg, &sg) < 0 || rg != gid || eg != gid || sg != gid) {
    errno = EPERM;
    return -1;
  }
  if (getgroups(0, NULL) != 0) {
    errno = EPERM;
    return -1;
  }
  /* The point of no return must really be one. */
  if (setuid(0) == 0 || setgid(0) == 0 || ps_setresuid(0, 0, 0) == 0) {
    errno = EPERM;
    return -1;
  }
  return 0;
}

/* Clear the permitted, effective and inheritable sets and read them back.
 * Credential change already empties permitted and effective; inheritable is
 * not touched by it, so this is not redundant. */
static inline int ps_clear_capabilities(void) {
  struct __user_cap_header_struct hdr = {.version = _LINUX_CAPABILITY_VERSION_3,
                                         .pid = 0};
  struct __user_cap_data_struct data[2];

  memset(data, 0, sizeof(data));
  if (syscall(SYS_capset, &hdr, data) < 0)
    return -1;

  hdr.version = _LINUX_CAPABILITY_VERSION_3;
  hdr.pid = 0;
  memset(data, 0xff, sizeof(data));
  if (syscall(SYS_capget, &hdr, data) < 0)
    return -1;
  for (int i = 0; i < 2; i++)
    if (data[i].effective || data[i].permitted || data[i].inheritable) {
      errno = EPERM;
      return -1;
    }
  return 0;
}

/* ------------------------------------------------------------------------
 * Seccomp allowlist
 * ------------------------------------------------------------------------ */

#define PS_BPF_MAX 96

/* Syscalls allowed unconditionally. The list is the one in the design doc;
 * it is a starting point, and docs/privilege-separation.md says the real
 * list must come from tracing a YARA scan with the shipped rules once the
 * scan runs in a worker. Explicitly absent: open*, socket, connect, execve*,
 * clone/fork, ptrace, kill, write, and anything that changes the filesystem.
 *
 * `fstat` and `newfstatat` are only reachable on an open descriptor: the
 * latter is further restricted to AT_EMPTY_PATH below. */
static const int ps_allow_plain[] = {
    SYS_read,          SYS_pread64,        SYS_lseek,        SYS_fstat,
    SYS_mmap,          SYS_munmap,         SYS_mprotect,     SYS_mremap,
    SYS_brk,           SYS_madvise,        SYS_futex,        SYS_dup,
    SYS_close,         SYS_clock_gettime,  SYS_clock_nanosleep,
    SYS_rt_sigaction,  SYS_rt_sigprocmask, SYS_rt_sigreturn, SYS_getrandom,
    SYS_exit_group,
};
#define PS_ALLOW_PLAIN_N (sizeof(ps_allow_plain) / sizeof(ps_allow_plain[0]))

#define PS_BPF_STMT(code, k) ((struct sock_filter)BPF_STMT((code), (k)))
#define PS_BPF_JUMP(code, k, jt, jf)                                           \
  ((struct sock_filter)BPF_JUMP((code), (k), (jt), (jf)))

/* Offsets into struct seccomp_data. */
#define PS_SD_NR offsetof(struct seccomp_data, nr)
#define PS_SD_ARCH offsetof(struct seccomp_data, arch)
#define PS_SD_ARG_LO(n) (offsetof(struct seccomp_data, args) + 8 * (n))
#define PS_SD_ARG_HI(n) (PS_SD_ARG_LO(n) + 4)

#define PS_X32_BIT 0x40000000u

/* Build the filter into `prog` (room for PS_BPF_MAX entries) and return its
 * length, or 0 if it does not fit.
 *
 *   arch must be x86-64, and the x32 syscall bit must be clear
 *   plain list                    -> allow
 *   recvmsg / sendmsg             -> allow only on exactly `ipc_fd`
 *   newfstatat                    -> allow only with AT_EMPTY_PATH set
 *   anything else                 -> SECCOMP_RET_KILL_PROCESS
 *
 * The fd comparison checks all 64 bits of the argument, so a caller cannot
 * hide a different descriptor in the upper half.
 *
 * Layout (P = number of plain entries):
 *    0  ld arch
 *    1  jeq x86-64 ? skip kill
 *    2  ret KILL
 *    3  ld nr
 *    4  jset x32 bit ? fall into kill : skip it
 *    5  ret KILL
 *  6..  P x (jeq nr -> allow)
 *   +P  jeq recvmsg -> fdchk
 *       jeq sendmsg -> fdchk
 *       jeq newfstatat -> statchk
 *       ret KILL                       (nothing matched)
 *   fdchk:   ld arg0.hi; jeq 0 (else kill); ld arg0.lo; jeq ipc_fd
 *   statchk: ld arg3.lo; jset AT_EMPTY_PATH
 *   allow:   ret ALLOW
 *   kill:    ret KILL
 * Every jump goes forward, as BPF requires. */
static inline size_t ps_seccomp_build(struct sock_filter *prog, int ipc_fd) {
  const size_t P = PS_ALLOW_PLAIN_N;
  const size_t first_plain = 6;
  const size_t fdchk = first_plain + P + 4;
  const size_t statchk = fdchk + 4;
  const size_t allow = statchk + 2;
  const size_t kill = allow + 1;
  const size_t total = kill + 1;
  size_t n = 0;
  size_t i;

#define PS_JT(target) ((uint8_t)((target) - (n) - 1))
  if (total > PS_BPF_MAX || kill - first_plain > 255 || ipc_fd < 0)
    return 0;

  prog[n++] = PS_BPF_STMT(BPF_LD | BPF_W | BPF_ABS, PS_SD_ARCH);
  prog[n++] = PS_BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
  prog[n++] = PS_BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
  prog[n++] = PS_BPF_STMT(BPF_LD | BPF_W | BPF_ABS, PS_SD_NR);
  prog[n++] = PS_BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PS_X32_BIT, 0, 1);
  prog[n++] = PS_BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

  for (i = 0; i < P; i++) {
    prog[n] = PS_BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)ps_allow_plain[i],
                          PS_JT(allow), 0);
    n++;
  }
  prog[n] = PS_BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_recvmsg,
                        PS_JT(fdchk), 0);
  n++;
  prog[n] = PS_BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_sendmsg,
                        PS_JT(fdchk), 0);
  n++;
  prog[n] = PS_BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_newfstatat,
                        PS_JT(statchk), 0);
  n++;
  prog[n++] = PS_BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

  /* fdchk */
  prog[n++] = PS_BPF_STMT(BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_HI(0));
  prog[n] = PS_BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, PS_JT(kill));
  n++;
  prog[n++] = PS_BPF_STMT(BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(0));
  prog[n] = PS_BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)ipc_fd,
                        PS_JT(allow), PS_JT(kill));
  n++;

  /* statchk */
  prog[n++] = PS_BPF_STMT(BPF_LD | BPF_W | BPF_ABS, PS_SD_ARG_LO(3));
  prog[n] = PS_BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, AT_EMPTY_PATH, PS_JT(allow),
                        PS_JT(kill));
  n++;

  prog[n++] = PS_BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  prog[n++] = PS_BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#undef PS_JT

  return n == total ? n : 0; /* wrong layout arithmetic: refuse to install */
}

/* Install the filter. Requires NO_NEW_PRIVS to be set already (so it works
 * without CAP_SYS_ADMIN, and so it cannot be shed by a later exec). */
static inline int ps_seccomp_install(int ipc_fd) {
  struct sock_filter prog[PS_BPF_MAX];
  struct sock_fprog fprog;
  size_t n = ps_seccomp_build(prog, ipc_fd);

  if (n == 0) {
    errno = E2BIG;
    return -1;
  }
  fprog.len = (unsigned short)n;
  fprog.filter = prog;
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0);
}

/* ------------------------------------------------------------------------
 * The ordered, fail-closed hardening sequence
 * ------------------------------------------------------------------------ */

/* Run every step in order; stop at the first failure and return its step
 * number, or 0 once the worker is fully hardened. The caller must `_exit(1)`
 * on a non-zero return without sending any readiness report (the spawner
 * then replies FAILED). Only a 0 return may lead to a ready report. */
static inline int ps_worker_harden(const struct ps_harden_cfg *c) {
  PS_HOOK(PS_H_CLOSE_FDS);
  if (c->ipc_fd < 0) {
    errno = EBADF;
    return PS_H_CLOSE_FDS;
  }
  if (ps_close_all_but(c->ipc_fd, c->log_fd) < 0)
    return PS_H_CLOSE_FDS;

  PS_HOOK(PS_H_RLIMITS);
  if (ps_set_rlimit(RLIMIT_AS, c->as_bytes) < 0 ||
      ps_set_rlimit(RLIMIT_CPU, c->cpu_seconds) < 0 ||
      ps_set_rlimit(RLIMIT_FSIZE, 0) < 0 ||
      ps_set_rlimit(RLIMIT_NOFILE, c->nofile) < 0)
    return PS_H_RLIMITS;

  PS_HOOK(PS_H_BOUNDING_SET);
  if (ps_drop_bounding_set() < 0)
    return PS_H_BOUNDING_SET;

  PS_HOOK(PS_H_CREDENTIALS);
  if (ps_drop_credentials(c->uid, c->gid) < 0)
    return PS_H_CREDENTIALS;

  PS_HOOK(PS_H_CAPABILITIES);
  if (ps_clear_capabilities() < 0)
    return PS_H_CAPABILITIES;

  PS_HOOK(PS_H_NO_NEW_PRIVS);
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
    return PS_H_NO_NEW_PRIVS;

  /* The parent-death signal is cleared by any uid/gid change, so it is set
   * after the credential step and read back, so that a later reordering
   * fails closed. It does nothing if the spawner already died, hence the
   * getppid() handshake. */
  PS_HOOK(PS_H_PDEATHSIG);
  {
    int sig = -1;

    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0 ||
        prctl(PR_GET_PDEATHSIG, &sig, 0, 0, 0) < 0 || sig != SIGKILL ||
        getppid() != c->expect_ppid) {
      if (errno == 0)
        errno = ESRCH;
      return PS_H_PDEATHSIG;
    }
  }

  PS_HOOK(PS_H_SECCOMP);
  if (ps_seccomp_install(c->ipc_fd) < 0)
    return PS_H_SECCOMP;

  return 0;
}

/* ------------------------------------------------------------------------
 * Request / reply loop
 * ------------------------------------------------------------------------ */

/* Descriptors the worker will look at in one message. One is correct; the
 * rest of the room exists so that a hostile peer sending several is seen,
 * counted and closed rather than silently truncated by the kernel. */
#define PS_MAX_RECV_FDS 8

enum ps_recv_result {
  PS_RECV_OK = 0,
  PS_RECV_EOF,      /* peer closed: orderly shutdown */
  PS_RECV_PROTOCOL, /* malformed request; every descriptor was closed */
  PS_RECV_ERROR     /* recvmsg failed for another reason */
};

/* Receive one request. On PS_RECV_OK, *request_id and *fd are set and the
 * caller owns *fd. On PS_RECV_PROTOCOL, *request_id is set only if the
 * header itself parsed (*have_id says so) and no descriptor is left open.
 *
 * Protocol errors: wrong length (short or oversized), bad magic/version,
 * zero or several descriptors, truncated ancillary data, or an ancillary
 * message of any other type. Every descriptor that arrived is closed on
 * every path. */
static inline enum ps_recv_result ps_worker_recv(int sock, uint64_t *request_id,
                                                 bool *have_id, int *fd) {
  /* One byte of slack so an oversized message is detected rather than
   * silently cut to the expected size. */
  unsigned char buf[sizeof(struct ps_request) + 1];
  union {
    char b[CMSG_SPACE(sizeof(int) * PS_MAX_RECV_FDS)];
    struct cmsghdr align;
  } ctl;
  struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
  struct msghdr msg;
  struct cmsghdr *cm;
  int fds[PS_MAX_RECV_FDS];
  int nfds = 0;
  ssize_t len;
  bool ok = true;

  *have_id = false;
  *fd = -1;
  memset(&msg, 0, sizeof(msg));
  memset(&ctl, 0, sizeof(ctl));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = ctl.b;
  msg.msg_controllen = sizeof(ctl.b);

  do {
    len = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
  } while (len < 0 && errno == EINTR);
  if (len < 0)
    return PS_RECV_ERROR;

  /* Collect every descriptor first, so each is closed whatever else is
   * wrong with the message. */
  for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
    if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
      size_t bytes = cm->cmsg_len - CMSG_LEN(0);
      size_t cnt = bytes / sizeof(int);
      int tmp[PS_MAX_RECV_FDS];

      if (cnt > PS_MAX_RECV_FDS - (size_t)nfds)
        cnt = PS_MAX_RECV_FDS - (size_t)nfds;
      memcpy(tmp, CMSG_DATA(cm), cnt * sizeof(int));
      for (size_t k = 0; k < cnt; k++)
        fds[nfds++] = tmp[k];
    } else {
      ok = false; /* an ancillary type we never asked for */
    }
  }

  if (len == 0 && nfds == 0 && !(msg.msg_flags & MSG_CTRUNC))
    return PS_RECV_EOF;

  if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
    ok = false;
  if (nfds != 1)
    ok = false;

  if (len == (ssize_t)sizeof(struct ps_request)) {
    uint64_t id;
    if (ps_request_parse(buf, (size_t)len, &id)) {
      *request_id = id;
      *have_id = true;
    } else {
      ok = false;
    }
  } else {
    ok = false;
  }

  if (!ok) {
    for (int k = 0; k < nfds; k++)
      close(fds[k]);
    return PS_RECV_PROTOCOL;
  }
  *fd = fds[0];
  return PS_RECV_OK;
}

/* Send a complete reply with sendmsg() (the only send call the filter
 * allows). Returns 0 only if the whole struct went out. */
static inline int ps_worker_send(int sock, const struct ps_reply *rep) {
  struct iovec iov = {.iov_base = (void *)rep, .iov_len = sizeof(*rep)};
  struct msghdr msg;
  ssize_t n;

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  do {
    n = sendmsg(sock, &msg, MSG_NOSIGNAL);
  } while (n < 0 && errno == EINTR);
  return n == (ssize_t)sizeof(*rep) ? 0 : -1;
}

/* Prefill a reply with the header and the canonical failure result, so a
 * scan callback that does nothing - or a path that never reaches it - is
 * reported as CLEAN + inconclusive, never as a half-filled verdict. */
static inline void ps_reply_init_failure(struct ps_reply *rep, uint64_t id) {
  memset(rep, 0, sizeof(*rep));
  rep->magic = PS_MAGIC;
  rep->version = PS_VERSION;
  rep->request_id = id;
  rep->verdict = PS_VERDICT_CLEAN;
  rep->inconclusive = 1;
}

/* The scan. Gets the descriptor and a reply prefilled by
 * ps_reply_init_failure(). To report a completed scan it sets
 * `inconclusive = 0` and whichever of verdict/score/rule_name/... apply. It
 * must not close `fd` (the loop does). */
typedef void (*ps_scan_fn)(int fd, void *ctx, struct ps_reply *rep);

/* Serve requests until the peer closes the socket (returns 0) or something
 * goes wrong (returns -1; the worker should then exit, and the parent, which
 * sees EOF or a bad reply, replaces it).
 *
 * After a protocol error on a request whose header did parse, a canonical
 * failure reply echoing its id is sent best-effort before returning, so the
 * parent can tell the difference between "worker rejected the request" and
 * "worker died". The descriptor is closed before the reply on every path, so
 * a worker never accumulates descriptors across requests. */
static inline int ps_worker_run(int sock, ps_scan_fn scan, void *ctx) {
  for (;;) {
    struct ps_reply rep;
    uint64_t id = 0;
    bool have_id = false;
    int fd = -1;
    enum ps_recv_result r = ps_worker_recv(sock, &id, &have_id, &fd);

    if (r == PS_RECV_EOF)
      return 0;
    if (r == PS_RECV_ERROR)
      return -1;
    if (r == PS_RECV_PROTOCOL) {
      if (have_id) {
        ps_reply_init_failure(&rep, id);
        (void)ps_worker_send(sock, &rep);
      }
      return -1;
    }

    ps_reply_init_failure(&rep, id);
    scan(fd, ctx, &rep);
    close(fd);

    /* The callback fills the header's neighbours; it must not be able to
     * change what identifies the reply, or leave the name unterminated. */
    rep.magic = PS_MAGIC;
    rep.version = PS_VERSION;
    rep.request_id = id;
    rep.reserved = 0;
    rep.rule_name[PS_RULE_NAME_SIZE - 1] = '\0';

    if (ps_worker_send(sock, &rep) < 0)
      return -1;
  }
}

#endif /* AV_PRIVSEP_WORKER_H */
