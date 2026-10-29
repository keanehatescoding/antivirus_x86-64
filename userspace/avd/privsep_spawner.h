/*
 * privsep_spawner.h - the spawner process and its control channel (#103,
 * Stage 1c; see docs/privilege-separation.md, "The spawner", "Correlating
 * replies" and "Reaping and lifecycle").
 *
 * avd forks one spawner, once, while it is still single-threaded. The spawner
 * stays single-threaded for its whole life, so it can always fork() safely,
 * and forks every scan worker from there (workers inherit the compiled rules
 * and corpora copy-on-write). The main process talks to it over one
 * socketpair(AF_UNIX, SOCK_SEQPACKET) with fixed-size messages:
 *
 *   main -> spawner   SPAWN(request_id)   KILL(worker_id)
 *   spawner -> main   READY(request_id, worker_id, pid) + the worker socket
 *                     FAILED(request_id, reason, detail)
 *                     EXITED(worker_id, wait status)       unprompted
 *
 * Both directions are treated as untrusted input (ps_ctl_recv() validates
 * everything and closes any descriptor it was not meant to receive).
 *
 * Same arrangement as privsep_proto.h and privsep_worker.h: header-only and
 * dependency-free (standard and Linux headers, no pthreads), so
 * tests/test_privsep_spawner.sh compiles this exact file standalone. The
 * reader thread, the request table and the lock that the main process needs
 * around this channel belong to the avd.c wiring, not here.
 *
 * Not wired into avd yet. Also not here yet: the spawner's own capability
 * drop and seccomp superset filter (doc, "Seccomp filters stack"), and the
 * parent-side /proc check of a READY worker.
 */

#ifndef AV_PRIVSEP_SPAWNER_H
#define AV_PRIVSEP_SPAWNER_H

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "privsep_worker.h"

/* ------------------------------------------------------------------------
 * Control channel wire format
 * ------------------------------------------------------------------------ */

#define PS_CTL_MAGIC 0x43535641u /* "AVSC" */
#define PS_CTL_VERSION 1u

enum ps_ctl_type {
  PS_MSG_SPAWN = 1,        /* main -> spawner */
  PS_MSG_KILL,             /* main -> spawner */
  PS_MSG_READY,            /* spawner -> main, carries the worker socket */
  PS_MSG_FAILED,           /* spawner -> main */
  PS_MSG_EXITED,           /* spawner -> main */
  PS_MSG_WORKER_READY,     /* worker -> spawner, on the worker's own socket */
  PS_MSG_TYPE_END          /* not a type */
};

/* Why a SPAWN failed. `detail` says more: the hardening step for
 * PS_FAIL_HARDEN, errno for PS_FAIL_FORK and PS_FAIL_RESOURCE, the wait
 * status for PS_FAIL_EXITED. */
enum ps_fail_reason {
  PS_FAIL_FORK = 1,   /* the fork call failed */
  PS_FAIL_HARDEN,     /* the worker failed a hardening step before ready */
  PS_FAIL_TIMEOUT,    /* no ready report within the startup timeout */
  PS_FAIL_EXITED,     /* the worker died before reporting ready */
  PS_FAIL_PROTOCOL,   /* the worker's ready report was malformed */
  PS_FAIL_RESOURCE,   /* socketpair() failed, or the spawner's tables are full */
  PS_FAIL_END         /* not a reason */
};

/* One struct for every message in both directions, fixed size, no padding.
 * Fields a message does not use are zero and are checked to be zero. */
struct ps_ctl_msg {
  uint32_t magic;
  uint32_t version;
  uint32_t type;
  uint32_t reason;     /* FAILED only */
  uint64_t request_id; /* SPAWN, READY, FAILED */
  uint64_t worker_id;  /* KILL, READY, EXITED */
  int32_t pid;         /* READY only; informational (never used to signal) */
  int32_t detail;      /* FAILED: see above. EXITED: raw wait status */
};

_Static_assert(sizeof(struct ps_ctl_msg) == 40, "ps_ctl_msg has padding");

static inline void ps_ctl_msg_init(struct ps_ctl_msg *m, enum ps_ctl_type type) {
  memset(m, 0, sizeof(*m));
  m->magic = PS_CTL_MAGIC;
  m->version = PS_CTL_VERSION;
  m->type = (uint32_t)type;
}

/* Which message types may carry a descriptor: exactly READY, exactly one. */
static inline bool ps_ctl_type_has_fd(uint32_t type) {
  return type == PS_MSG_READY;
}

/* Structural validation of one message. `from_main` selects which types are
 * acceptable (the spawner accepts SPAWN and KILL from main; main accepts
 * READY, FAILED and EXITED from the spawner; a worker may only send
 * WORKER_READY, validated with from_worker). */
enum ps_ctl_from { PS_FROM_MAIN, PS_FROM_SPAWNER, PS_FROM_WORKER };

static inline bool ps_ctl_msg_valid(const struct ps_ctl_msg *m,
                                    enum ps_ctl_from from) {
  if (m->magic != PS_CTL_MAGIC || m->version != PS_CTL_VERSION)
    return false;

  switch (from) {
  case PS_FROM_MAIN:
    if (m->type != PS_MSG_SPAWN && m->type != PS_MSG_KILL)
      return false;
    break;
  case PS_FROM_SPAWNER:
    if (m->type != PS_MSG_READY && m->type != PS_MSG_FAILED &&
        m->type != PS_MSG_EXITED)
      return false;
    break;
  case PS_FROM_WORKER:
    if (m->type != PS_MSG_WORKER_READY)
      return false;
    break;
  default:
    return false;
  }

  switch (m->type) {
  case PS_MSG_SPAWN:
    return m->reason == 0 && m->worker_id == 0 && m->pid == 0 && m->detail == 0;
  case PS_MSG_KILL:
    return m->reason == 0 && m->request_id == 0 && m->pid == 0 &&
           m->detail == 0 && m->worker_id != 0;
  case PS_MSG_READY:
    return m->reason == 0 && m->detail == 0 && m->worker_id != 0 && m->pid > 0;
  case PS_MSG_FAILED:
    return m->reason >= PS_FAIL_FORK && m->reason < PS_FAIL_END &&
           m->worker_id == 0 && m->pid == 0;
  case PS_MSG_EXITED:
    return m->reason == 0 && m->request_id == 0 && m->pid == 0 &&
           m->worker_id != 0;
  case PS_MSG_WORKER_READY:
    return m->reason == 0 && m->request_id == 0 && m->worker_id == 0 &&
           m->pid == 0 && m->detail == 0;
  default:
    return false;
  }
}

/* Send one message, with `fd` attached as SCM_RIGHTS when it is >= 0. Blocks
 * until the whole message is queued; returns 0 on success, -1 with errno set
 * otherwise (EPIPE: the peer is gone). MSG_NOSIGNAL so a dead peer is an
 * error, not a SIGPIPE. */
static inline int ps_ctl_send(int sock, const struct ps_ctl_msg *m, int fd) {
  struct iovec iov = {.iov_base = (void *)m, .iov_len = sizeof(*m)};
  union {
    char b[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align;
  } ctl;
  struct msghdr msg;
  ssize_t n;

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  if (fd >= 0) {
    struct cmsghdr *cm;

    memset(&ctl, 0, sizeof(ctl));
    msg.msg_control = ctl.b;
    msg.msg_controllen = sizeof(ctl.b);
    cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof(int));
  }
  do {
    n = sendmsg(sock, &msg, MSG_NOSIGNAL);
  } while (n < 0 && errno == EINTR);
  return n == (ssize_t)sizeof(*m) ? 0 : -1;
}

enum ps_ctl_recv_result {
  PS_CTL_OK = 0,
  PS_CTL_EOF,      /* peer closed: orderly shutdown or death */
  PS_CTL_BAD,      /* malformed message; every descriptor was closed */
  PS_CTL_ERROR,    /* recvmsg failed (errno set); EAGAIN with MSG_DONTWAIT */
};

/* Descriptors looked at in one message. At most one is correct (READY); the
 * rest of the room exists so a hostile peer sending several is seen, counted
 * and closed rather than silently truncated by the kernel. */
#define PS_CTL_MAX_FDS 8

/* Receive and validate one message. On PS_CTL_OK, *m is a valid message from
 * `from`; *fd is the attached descriptor (owned by the caller) for a READY and
 * -1 for everything else. A descriptor on a message that must not carry one,
 * a READY without exactly one, truncation of the data or the ancillary
 * data, or any other ancillary type is PS_CTL_BAD and every descriptor that
 * arrived is closed. `flags` is passed to recvmsg (MSG_DONTWAIT). */
static inline enum ps_ctl_recv_result
ps_ctl_recv(int sock, enum ps_ctl_from from, int flags, struct ps_ctl_msg *m,
            int *fd) {
  unsigned char buf[sizeof(struct ps_ctl_msg) + 1];
  union {
    char b[CMSG_SPACE(sizeof(int) * PS_CTL_MAX_FDS)];
    struct cmsghdr align;
  } ctl;
  struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
  struct msghdr msg;
  struct cmsghdr *cm;
  int fds[PS_CTL_MAX_FDS];
  int nfds = 0;
  ssize_t len;
  bool ok = true;

  *fd = -1;
  memset(m, 0, sizeof(*m));
  memset(&msg, 0, sizeof(msg));
  memset(&ctl, 0, sizeof(ctl));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = ctl.b;
  msg.msg_controllen = sizeof(ctl.b);

  do {
    len = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC | flags);
  } while (len < 0 && errno == EINTR);
  if (len < 0)
    return PS_CTL_ERROR;

  for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
    if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
      size_t cnt = (cm->cmsg_len - CMSG_LEN(0)) / sizeof(int);
      int tmp[PS_CTL_MAX_FDS];

      if (cnt > PS_CTL_MAX_FDS - (size_t)nfds)
        cnt = PS_CTL_MAX_FDS - (size_t)nfds;
      memcpy(tmp, CMSG_DATA(cm), cnt * sizeof(int));
      for (size_t k = 0; k < cnt; k++)
        fds[nfds++] = tmp[k];
    } else {
      ok = false;
    }
  }

  if (len == 0 && nfds == 0 && !(msg.msg_flags & MSG_CTRUNC))
    return PS_CTL_EOF;

  if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
    ok = false;
  if (len != (ssize_t)sizeof(*m)) {
    ok = false;
  } else {
    memcpy(m, buf, sizeof(*m));
    if (!ps_ctl_msg_valid(m, from))
      ok = false;
    else if (ps_ctl_type_has_fd(m->type) ? nfds != 1 : nfds != 0)
      ok = false;
  }

  if (!ok) {
    for (int k = 0; k < nfds; k++)
      close(fds[k]);
    memset(m, 0, sizeof(*m));
    return PS_CTL_BAD;
  }
  if (nfds == 1)
    *fd = fds[0];
  return PS_CTL_OK;
}

/* ------------------------------------------------------------------------
 * Worker readiness report
 * ------------------------------------------------------------------------ */

/* Exit codes a worker child uses before it reports ready. A hardening
 * failure exits with PS_EXIT_HARDEN_BASE + the step number from
 * ps_worker_harden(), so the spawner can say which step in FAILED. */
#define PS_EXIT_HARDEN_BASE 64
#define PS_EXIT_READY_SEND 120 /* hardened, but could not send the report */

/* Report ready. Called only after ps_worker_harden() returned 0, and uses
 * sendmsg() - the one send call the worker's seccomp filter allows, on
 * exactly the IPC descriptor. */
static inline int ps_worker_report_ready(int sock) {
  struct ps_ctl_msg m;

  ps_ctl_msg_init(&m, PS_MSG_WORKER_READY);
  return ps_ctl_send(sock, &m, -1);
}

/* ------------------------------------------------------------------------
 * The spawner
 * ------------------------------------------------------------------------ */

/* Fixed-size tables: the spawner allocates nothing after startup. Each scan
 * thread owns one worker, so PS_SPAWNER_MAX_WORKERS bounds the scan thread
 * count and PS_SPAWNER_MAX_PENDING bounds simultaneous replacements. A SPAWN
 * that finds either table full is answered FAILED(PS_FAIL_RESOURCE). */
#ifndef PS_SPAWNER_MAX_WORKERS /* overridable so tests can hit the limit */
#define PS_SPAWNER_MAX_WORKERS 256
#endif
#ifndef PS_SPAWNER_MAX_PENDING
#define PS_SPAWNER_MAX_PENDING 64
#endif
_Static_assert(PS_SPAWNER_MAX_PENDING <= PS_SPAWNER_MAX_WORKERS,
               "a pending worker must always fit in the live table");

struct ps_spawner_cfg {
  struct ps_harden_cfg harden; /* template: ipc_fd, log_fd and expect_ppid are
                                * filled in per worker */
  ps_scan_fn scan;             /* what a worker runs; inherited by fork */
  void *scan_ctx;
  int startup_timeout_ms;      /* bound on spawn -> ready report */
};

#ifdef PS_SPAWNER_TEST_HOOKS
/* Test builds only: replaces ps_worker_harden() in the forked child so the
 * spawner's own logic can be exercised without root. Absent from production
 * builds, so there is no switch to flip. */
static int (*ps_spawner_test_harden)(const struct ps_harden_cfg *);
/* Test builds only: makes the Nth fork (1-based) fail with EAGAIN. */
static unsigned ps_spawner_test_fail_fork;
static unsigned ps_spawner_test_forks;
#endif

struct ps_pending {
  uint64_t request_id;
  uint64_t worker_id;
  pid_t pid;
  int sock;        /* the spawner's end of the worker's socketpair */
  int64_t deadline_ms;
  bool eof;        /* the worker closed its end; waiting for the reap */
  bool used;
};

struct ps_live {
  uint64_t worker_id;
  pid_t pid;
  bool used;
};

struct ps_spawner {
  struct ps_pending pending[PS_SPAWNER_MAX_PENDING];
  struct ps_live live[PS_SPAWNER_MAX_WORKERS];
  uint64_t next_worker_id; /* starts at 1, only increases, never reused */
};

static inline int64_t ps_now_ms(void) {
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Replies. A send failure means main is gone (or hopelessly stuck), which the
 * run loop treats as the end of the spawner. */
static inline int ps_spawner_reply_failed(int ctl, uint64_t request_id,
                                          enum ps_fail_reason why, int detail) {
  struct ps_ctl_msg m;

  ps_ctl_msg_init(&m, PS_MSG_FAILED);
  m.request_id = request_id;
  m.reason = (uint32_t)why;
  m.detail = detail;
  return ps_ctl_send(ctl, &m, -1);
}

static inline struct ps_pending *ps_pending_free_slot(struct ps_spawner *s) {
  for (int i = 0; i < PS_SPAWNER_MAX_PENDING; i++)
    if (!s->pending[i].used)
      return &s->pending[i];
  return NULL;
}

static inline struct ps_live *ps_live_free_slot(struct ps_spawner *s) {
  for (int i = 0; i < PS_SPAWNER_MAX_WORKERS; i++)
    if (!s->live[i].used)
      return &s->live[i];
  return NULL;
}

/* Workers the spawner is responsible for: pending plus live. */
static inline int ps_in_use(const struct ps_spawner *s) {
  int n = 0;

  for (int i = 0; i < PS_SPAWNER_MAX_PENDING; i++)
    n += s->pending[i].used;
  for (int i = 0; i < PS_SPAWNER_MAX_WORKERS; i++)
    n += s->live[i].used;
  return n;
}

/* The forked child: never returns. `oldmask` is the signal mask from before
 * the spawner blocked SIGCHLD, restored so a worker is not left with it. */
static inline void ps_spawner_child(const struct ps_spawner_cfg *cfg, int sock,
                                    pid_t spawner_pid,
                                    const sigset_t *oldmask) {
  struct ps_harden_cfg h = cfg->harden;
  int rc;

  (void)sigprocmask(SIG_SETMASK, oldmask, NULL);
  h.ipc_fd = sock;
  h.log_fd = -1;
  h.expect_ppid = spawner_pid;

#ifdef PS_SPAWNER_TEST_HOOKS
  rc = ps_spawner_test_harden ? ps_spawner_test_harden(&h) : ps_worker_harden(&h);
#else
  rc = ps_worker_harden(&h);
#endif
  if (rc != 0)
    _exit(PS_EXIT_HARDEN_BASE + rc);
  if (ps_worker_report_ready(sock) < 0)
    _exit(PS_EXIT_READY_SEND);
  _exit(ps_worker_run(sock, cfg->scan, cfg->scan_ctx) == 0 ? 0 : 1);
}

/* Handle SPAWN: socketpair, fork, remember the child as pending. Any failure
 * is answered with FAILED right away. Returns -1 only if the reply itself
 * could not be sent. */
static inline int ps_spawner_do_spawn(struct ps_spawner *s,
                                      const struct ps_spawner_cfg *cfg, int ctl,
                                      uint64_t request_id,
                                      const sigset_t *oldmask) {
  struct ps_pending *p = ps_pending_free_slot(s);
  int sv[2];
  pid_t pid, spawner_pid;
  int err;

  /* Pending and live workers share the one budget, so a pending worker can
   * always be promoted to a live slot later. */
  if (!p || ps_in_use(s) >= PS_SPAWNER_MAX_WORKERS)
    return ps_spawner_reply_failed(ctl, request_id, PS_FAIL_RESOURCE, EMFILE);

  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0)
    return ps_spawner_reply_failed(ctl, request_id, PS_FAIL_RESOURCE, errno);

#ifdef PS_SPAWNER_TEST_HOOKS
  ps_spawner_test_forks++;
  if (ps_spawner_test_fail_fork && ps_spawner_test_forks == ps_spawner_test_fail_fork) {
    close(sv[0]);
    close(sv[1]);
    return ps_spawner_reply_failed(ctl, request_id, PS_FAIL_FORK, EAGAIN);
  }
#endif

  /* Recorded BEFORE the fork. The child compares getppid() with it after
   * setting its parent-death signal: reading getppid() in the child instead
   * would also "match" a spawner that had already died and orphaned it. */
  spawner_pid = getpid();
  pid = fork();
  if (pid < 0) {
    err = errno;
    close(sv[0]);
    close(sv[1]);
    return ps_spawner_reply_failed(ctl, request_id, PS_FAIL_FORK, err);
  }
  if (pid == 0) {
    close(sv[0]);
    ps_spawner_child(cfg, sv[1], spawner_pid, oldmask);
    _exit(PS_EXIT_READY_SEND); /* not reached */
  }

  close(sv[1]);
  p->used = true;
  p->request_id = request_id;
  p->worker_id = s->next_worker_id++;
  p->pid = pid;
  p->sock = sv[0];
  p->deadline_ms = ps_now_ms() + cfg->startup_timeout_ms;
  p->eof = false;
  return 0;
}

/* Forget a pending worker: close the spawner's end of its socket. The process
 * itself is the caller's business (killed here, or already reaped). */
static inline void ps_pending_drop(struct ps_pending *p) {
  close(p->sock);
  memset(p, 0, sizeof(*p));
}

/* Activity on a pending worker's socket: its ready report, or EOF.
 * Returns -1 only if a reply to main could not be sent. */
static inline int ps_spawner_pending_event(struct ps_spawner *s, int ctl,
                                           struct ps_pending *p) {
  struct ps_ctl_msg m;
  struct ps_live *l;
  int fd = -1;
  enum ps_ctl_recv_result r =
      ps_ctl_recv(p->sock, PS_FROM_WORKER, MSG_DONTWAIT, &m, &fd);

  if (r == PS_CTL_ERROR)
    return 0; /* EAGAIN or a spurious wakeup; the deadline still applies */

  if (r == PS_CTL_EOF) {
    /* The worker closed its end, almost certainly by exiting. Do not fail it
     * here: the SIGCHLD reap reports the exit status, which is what says
     * WHICH hardening step failed. The deadline covers a worker that closed
     * its socket and kept running. */
    p->eof = true;
    return 0;
  }

  if (r == PS_CTL_BAD) {
    uint64_t rid = p->request_id;

    kill(p->pid, SIGKILL); /* reaped later; the pid stays ours until then */
    ps_pending_drop(p);
    return ps_spawner_reply_failed(ctl, rid, PS_FAIL_PROTOCOL, 0);
  }

  /* PS_CTL_OK: a hardened worker is ready. Hand main its end of the socket,
   * then keep only the pid. */
  l = ps_live_free_slot(s);
  if (!l) { /* cannot happen: the budget is shared; fail closed anyway */
    uint64_t rid = p->request_id;

    kill(p->pid, SIGKILL);
    ps_pending_drop(p);
    return ps_spawner_reply_failed(ctl, rid, PS_FAIL_RESOURCE, EMFILE);
  }

  {
    struct ps_ctl_msg out;
    int rc;

    ps_ctl_msg_init(&out, PS_MSG_READY);
    out.request_id = p->request_id;
    out.worker_id = p->worker_id;
    out.pid = (int32_t)p->pid;
    rc = ps_ctl_send(ctl, &out, p->sock);

    l->used = true;
    l->worker_id = p->worker_id;
    l->pid = p->pid;
    ps_pending_drop(p);
    return rc;
  }
}

/* A pending worker ran out of time: kill it and fail the request now. */
static inline int ps_spawner_expire(struct ps_spawner *s, int ctl,
                                    int64_t now_ms) {
  for (int i = 0; i < PS_SPAWNER_MAX_PENDING; i++) {
    struct ps_pending *p = &s->pending[i];

    if (p->used && now_ms >= p->deadline_ms) {
      uint64_t rid = p->request_id;

      kill(p->pid, SIGKILL);
      ps_pending_drop(p);
      if (ps_spawner_reply_failed(ctl, rid, PS_FAIL_TIMEOUT, 0) < 0)
        return -1;
    }
  }
  return 0;
}

/* Reap every exited child (SIGCHLDs coalesce, hence the loop) and report it.
 * A live worker gets EXITED; a pending one gets FAILED, with the hardening
 * step recovered from its exit code. A pid in neither table is one the
 * spawner already killed and answered (timeout or protocol error): reaped
 * silently. Never blocks. Returns -1 only if a reply could not be sent. */
static inline int ps_spawner_reap(struct ps_spawner *s, int ctl) {
  for (;;) {
    int st = 0;
    pid_t pid = waitpid(-1, &st, WNOHANG);
    bool found = false;

    if (pid < 0 && errno == EINTR)
      continue;
    if (pid <= 0)
      return 0;

    for (int i = 0; i < PS_SPAWNER_MAX_WORKERS && !found; i++) {
      struct ps_live *l = &s->live[i];

      if (l->used && l->pid == pid) {
        struct ps_ctl_msg m;

        ps_ctl_msg_init(&m, PS_MSG_EXITED);
        m.worker_id = l->worker_id;
        m.detail = st;
        memset(l, 0, sizeof(*l));
        found = true;
        if (ps_ctl_send(ctl, &m, -1) < 0)
          return -1;
      }
    }
    for (int i = 0; i < PS_SPAWNER_MAX_PENDING && !found; i++) {
      struct ps_pending *p = &s->pending[i];

      if (p->used && p->pid == pid) {
        uint64_t rid = p->request_id;
        enum ps_fail_reason why = PS_FAIL_EXITED;
        int detail = st;

        if (WIFEXITED(st)) {
          int code = WEXITSTATUS(st);

          if (code > PS_EXIT_HARDEN_BASE &&
              code < PS_EXIT_HARDEN_BASE + PS_H_STEP_COUNT) {
            why = PS_FAIL_HARDEN;
            detail = code - PS_EXIT_HARDEN_BASE;
          }
        }
        ps_pending_drop(p);
        found = true;
        if (ps_spawner_reply_failed(ctl, rid, why, detail) < 0)
          return -1;
      }
    }
  }
}

/* Read and discard everything queued on the signalfd; the reap does the work. */
static inline void ps_spawner_drain_signalfd(int sfd) {
  struct signalfd_siginfo si;

  while (read(sfd, &si, sizeof(si)) == (ssize_t)sizeof(si)) {
  }
}

/* KILL: SIGKILL a live worker by id. An id that is not live (already exited,
 * never existed, or still pending) is a no-op. The reaping loop reports the
 * exit; this never waits. Only the spawner signals workers, and only a pid it
 * has not yet reaped, so a pid cannot have been reused. */
static inline void ps_spawner_do_kill(struct ps_spawner *s, uint64_t worker_id) {
  for (int i = 0; i < PS_SPAWNER_MAX_WORKERS; i++)
    if (s->live[i].used && s->live[i].worker_id == worker_id)
      kill(s->live[i].pid, SIGKILL);
}

/* Kill everything and release descriptors; used on the way out. */
static inline void ps_spawner_shutdown(struct ps_spawner *s) {
  for (int i = 0; i < PS_SPAWNER_MAX_PENDING; i++)
    if (s->pending[i].used) {
      kill(s->pending[i].pid, SIGKILL);
      ps_pending_drop(&s->pending[i]);
    }
  for (int i = 0; i < PS_SPAWNER_MAX_WORKERS; i++)
    if (s->live[i].used)
      kill(s->live[i].pid, SIGKILL);
}

/* The spawner's main loop, on `ctl` (its end of the bootstrap channel).
 * Returns 0 when main closes the channel (orderly: kills every worker first),
 * 1 on an unrecoverable error, including being unable to reply to main. The
 * caller exits with the result.
 *
 * One poll() covers the control channel, the SIGCHLD signalfd and the sockets
 * of every pending spawn, so a slow-starting worker never blocks anything. */
static inline int ps_spawner_run(const struct ps_spawner_cfg *cfg, int ctl) {
  struct ps_spawner s;
  struct pollfd fds[2 + PS_SPAWNER_MAX_PENDING];
  struct ps_pending *who[2 + PS_SPAWNER_MAX_PENDING];
  sigset_t mask, old;
  int sfd;
  int rc = 0;

  memset(&s, 0, sizeof(s));
  s.next_worker_id = 1;

  /* SIGCHLD is blocked and read from a signalfd: a blocked signal never runs
   * a handler, so a self-pipe handler must not be combined with this. */
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &mask, &old) < 0)
    return 1;
  sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (sfd < 0)
    return 1;

  for (;;) {
    int64_t now = ps_now_ms();
    int64_t soonest = -1;
    int n = 0;
    int pr;

    fds[n].fd = ctl;
    fds[n].events = POLLIN;
    who[n++] = NULL;
    fds[n].fd = sfd;
    fds[n].events = POLLIN;
    who[n++] = NULL;

    for (int i = 0; i < PS_SPAWNER_MAX_PENDING; i++) {
      struct ps_pending *p = &s.pending[i];

      if (!p->used)
        continue;
      if (soonest < 0 || p->deadline_ms < soonest)
        soonest = p->deadline_ms;
      if (p->eof) /* a closed socket would report POLLHUP forever */
        continue;
      fds[n].fd = p->sock;
      fds[n].events = POLLIN;
      who[n++] = p;
    }

    pr = poll(fds, (nfds_t)n,
              soonest < 0 ? -1 : (int)(soonest > now ? soonest - now : 0));
    if (pr < 0) {
      if (errno == EINTR)
        continue;
      rc = 1;
      break;
    }

    if (fds[0].revents) {
      struct ps_ctl_msg m;
      int fd = -1;
      enum ps_ctl_recv_result r =
          ps_ctl_recv(ctl, PS_FROM_MAIN, MSG_DONTWAIT, &m, &fd);

      if (r == PS_CTL_EOF)
        break; /* main is gone or closed the channel: orderly shutdown */
      if (r == PS_CTL_ERROR && errno != EAGAIN) {
        rc = 1;
        break;
      }
      /* PS_CTL_BAD: dropped. SEQPACKET keeps message boundaries, so there is
       * no stream to resynchronise, and there is nobody to answer. */
      if (r == PS_CTL_OK) {
        if (m.type == PS_MSG_SPAWN) {
          if (ps_spawner_do_spawn(&s, cfg, ctl, m.request_id, &old) < 0) {
            rc = 1;
            break;
          }
        } else {
          ps_spawner_do_kill(&s, m.worker_id);
        }
      }
    }

    if (fds[1].revents) {
      ps_spawner_drain_signalfd(sfd);
      if (ps_spawner_reap(&s, ctl) < 0) {
        rc = 1;
        break;
      }
    }

    for (int i = 2; i < n; i++) {
      /* A pending entry may have been dropped by the reap above. */
      if (fds[i].revents && who[i]->used && who[i]->sock == fds[i].fd &&
          ps_spawner_pending_event(&s, ctl, who[i]) < 0) {
        rc = 1;
        break;
      }
    }
    if (rc)
      break;

    if (ps_spawner_expire(&s, ctl, ps_now_ms()) < 0) {
      rc = 1;
      break;
    }
  }

  ps_spawner_shutdown(&s);
  close(sfd);
  return rc;
}

/* Main-process side: create the bootstrap channel and fork the spawner. Call
 * once, while the process is still single-threaded and holds no descriptors
 * the spawner must not inherit (the spawner closes everything but its end and
 * stderr regardless). On success returns 0 with *ctl_fd the main process's end
 * (CLOEXEC) and *spawner_pid the child; on failure returns -1.
 *
 * The spawner sets its parent-death signal and requires getppid() to still be
 * this process, so killing avd takes the spawner (and through it every
 * worker) down; see the design doc, "Reaping and lifecycle". */
static inline int ps_spawner_start(const struct ps_spawner_cfg *cfg,
                                   int *ctl_fd, pid_t *spawner_pid) {
  int sv[2];
  pid_t main_pid = getpid();
  pid_t pid;

  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0)
    return -1;
  pid = fork();
  if (pid < 0) {
    int e = errno;

    close(sv[0]);
    close(sv[1]);
    errno = e;
    return -1;
  }
  if (pid == 0) {
    close(sv[0]);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0 ||
        getppid() != main_pid)
      _exit(1);
    if (ps_close_all_but(sv[1], STDERR_FILENO) < 0)
      _exit(1);
    _exit(ps_spawner_run(cfg, sv[1]) == 0 ? 0 : 1);
  }
  close(sv[1]);
  *ctl_fd = sv[0];
  *spawner_pid = pid;
  return 0;
}

#endif /* AV_PRIVSEP_SPAWNER_H */
