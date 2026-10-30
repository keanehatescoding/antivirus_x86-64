/*
 * privsep_client.h - the main-process side of avd's privilege separation
 * (#103, Stage 1d; see docs/privilege-separation.md, "Correlating replies",
 * "IPC", "The parent treats every reply as untrusted" and "Failure handling").
 *
 * The scan threads in avd's main process use this to get an unprivileged,
 * hardened worker from the spawner (privsep_spawner.h) and to run one scan in
 * it:
 *
 *   ps_client_attach()   adopt the spawner's control channel and start the
 *                        one reader thread that owns reads from it
 *   ps_client_spawn()    SPAWN, wait (bounded) for READY or FAILED, then
 *                        check the worker's own /proc/<pid>/status
 *   ps_client_scan()     one request/reply round trip, every reply treated as
 *                        untrusted; any anomaly kills the worker and returns
 *                        the canonical failure result
 *   ps_client_release()  drop a worker the caller is done with
 *   ps_client_stop()     orderly shutdown
 *
 * A worker handle (struct ps_worker) belongs to exactly one thread: each scan
 * thread owns one worker, so the queue, the pool size and the fanotify
 * deadline handling are untouched (contracts 3 and 4). The client itself is
 * shared by all of them.
 *
 * Header-only and dependency-free apart from pthreads, like its siblings, so
 * tests/test_privsep_client.sh compiles this exact file standalone. Logging
 * and "what to do when the spawner dies" are callbacks, so this header never
 * decides policy: avd.c wires them (log lines; exit non-zero so systemd
 * restarts avd, never a silent fall back to scanning in the root process).
 *
 * Not wired into avd yet.
 */

#ifndef AV_PRIVSEP_CLIENT_H
#define AV_PRIVSEP_CLIENT_H

#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "privsep_spawner.h"

/* Outstanding SPAWNs. Each scan thread has at most one, so the scan pool size
 * (256 at most) bounds it. */
#ifndef PS_CLIENT_MAX_WAITERS
#define PS_CLIENT_MAX_WAITERS 256
#endif

/* Consecutive SPAWNs that get no reply at all before the spawner is treated
 * as hung, which is treated like death: a hung spawner cannot recover on its
 * own (docs: "Failure handling"). */
#define PS_CLIENT_HANG_LIMIT 3

/* ------------------------------------------------------------------------
 * Checking a worker the way the design asks
 * ------------------------------------------------------------------------ */

/* Find `key:` at the start of a line of /proc/<pid>/status and return a
 * pointer to its value. `Seccomp:` must not match `Seccomp_filters:`, hence
 * the colon. */
static inline const char *ps_status_value(const char *status, const char *key) {
  size_t kl = strlen(key);
  const char *p = status;

  while (*p) {
    if (strncmp(p, key, kl) == 0 && p[kl] == ':') {
      p += kl + 1;
      while (*p == ' ' || *p == '\t')
        p++;
      return p;
    }
    p = strchr(p, '\n');
    if (!p)
      break;
    p++;
  }
  return NULL;
}

static inline bool ps_status_cap_zero(const char *status, const char *key) {
  const char *v = ps_status_value(status, key);
  unsigned long long x;
  char *end;

  if (!v)
    return false;
  x = strtoull(v, &end, 16);
  return end != v && x == 0;
}

/* What the parent requires of a worker before it dispatches anything to it:
 * the dedicated uid and gid in all four slots each, every capability set
 * (including the bounding and ambient sets) empty, NoNewPrivs set, a seccomp
 * filter installed, the spawner as its parent, and not already a zombie. A
 * missing field fails closed. The pid is used for this read only, never to
 * signal or address the worker: dispatch goes through the socket and signals
 * go through the spawner, so a stale pid can only make this check fail, which
 * gets the worker replaced. On failure `why` names the first thing wrong. */
static inline bool ps_verify_worker(pid_t pid, uid_t uid, gid_t gid,
                                    pid_t spawner_pid, char *why,
                                    size_t whysz) {
  char path[64];
  char status[8192];
  const char *v;
  unsigned a, b, c, d;
  int fd;
  ssize_t n;
  size_t len = 0;

#define PS_VFAIL(...)                                                          \
  do {                                                                         \
    snprintf(why, whysz, __VA_ARGS__);                                         \
    return false;                                                              \
  } while (0)

  snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
  fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    PS_VFAIL("cannot open %s: %s", path, strerror(errno));
  while (len < sizeof(status) - 1 &&
         (n = read(fd, status + len, sizeof(status) - 1 - len)) > 0)
    len += (size_t)n;
  close(fd);
  status[len] = '\0';
  if (len == 0)
    PS_VFAIL("%s is empty", path);

  v = ps_status_value(status, "State");
  if (!v || *v == 'Z' || *v == 'X')
    PS_VFAIL("worker already gone (State: %.1s)", v ? v : "?");

  v = ps_status_value(status, "PPid");
  if (!v || (pid_t)strtol(v, NULL, 10) != spawner_pid)
    PS_VFAIL("PPid is not the spawner (%d)", (int)spawner_pid);

  v = ps_status_value(status, "Uid");
  if (!v || sscanf(v, "%u %u %u %u", &a, &b, &c, &d) != 4 || a != uid ||
      b != uid || c != uid || d != uid)
    PS_VFAIL("Uid is not %u in all four slots", (unsigned)uid);
  v = ps_status_value(status, "Gid");
  if (!v || sscanf(v, "%u %u %u %u", &a, &b, &c, &d) != 4 || a != gid ||
      b != gid || c != gid || d != gid)
    PS_VFAIL("Gid is not %u in all four slots", (unsigned)gid);

  if (!ps_status_cap_zero(status, "CapInh"))
    PS_VFAIL("CapInh is not empty");
  if (!ps_status_cap_zero(status, "CapPrm"))
    PS_VFAIL("CapPrm is not empty");
  if (!ps_status_cap_zero(status, "CapEff"))
    PS_VFAIL("CapEff is not empty");
  if (!ps_status_cap_zero(status, "CapBnd"))
    PS_VFAIL("CapBnd is not empty");
  if (!ps_status_cap_zero(status, "CapAmb"))
    PS_VFAIL("CapAmb is not empty");

  v = ps_status_value(status, "NoNewPrivs");
  if (!v || *v != '1')
    PS_VFAIL("NoNewPrivs is not 1");
  v = ps_status_value(status, "Seccomp");
  if (!v || *v != '2')
    PS_VFAIL("Seccomp is not 2 (no filter installed)");
#undef PS_VFAIL
  return true;
}

/* A readable account of a wait status, loud about the one that matters most:
 * SIGSYS means a worker used a syscall outside its seccomp allowlist, so
 * every scan on that worker failed open. */
static inline void ps_describe_status(int st, char *buf, size_t n) {
  if (WIFEXITED(st))
    snprintf(buf, n, "exited with status %d", WEXITSTATUS(st));
  else if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS)
    snprintf(buf, n,
             "killed by SIGSYS: it used a syscall outside the seccomp "
             "allowlist (scans on it failed open)");
  else if (WIFSIGNALED(st))
    snprintf(buf, n, "killed by signal %d (%s)", WTERMSIG(st),
             strsignal(WTERMSIG(st)));
  else
    snprintf(buf, n, "wait status 0x%x", (unsigned)st);
}

/* ------------------------------------------------------------------------
 * The client
 * ------------------------------------------------------------------------ */

struct ps_waiter {
  bool used;
  bool abandoned; /* the scan thread gave up; a late reply must be cleaned up */
  bool done;
  uint64_t request_id;
  struct ps_ctl_msg reply;
  int fd; /* READY's worker socket, otherwise -1 */
};

/* What main knows about each live worker, kept by the reader thread so an
 * EXITED can be logged with the cause and a stale one recognised. */
struct ps_wentry {
  bool used;
  uint64_t worker_id;
  pid_t pid;
};

struct ps_client {
  int ctl;
  pid_t spawner_pid;
  uid_t uid; /* the dedicated worker credentials the /proc check requires */
  gid_t gid;
  bool verify_proc; /* production: true. Tests with a stub hardening: false */

  pthread_mutex_t wlock; /* serialises writes on ctl */
  pthread_mutex_t lock;  /* everything below */
  pthread_cond_t cond;
  uint64_t next_request_id;
  struct ps_waiter waiters[PS_CLIENT_MAX_WAITERS];
  struct ps_wentry workers[PS_SPAWNER_MAX_WORKERS];
  int missed; /* consecutive SPAWNs with no reply */
  bool dead;
  bool dead_notified;
  bool stopping;
  pthread_t reader;
  bool reader_started;

  /* Policy hooks. Either may be NULL. Never called with a lock held. */
  void (*log)(void *ctx, const char *msg);
  void *log_ctx;
  void (*on_dead)(void *ctx);
  void *on_dead_ctx;
};

/* A worker owned by one scan thread. sock < 0 means "none, spawn one". */
struct ps_worker {
  int sock;
  uint64_t worker_id;
  pid_t pid;
  uint64_t next_id; /* per-worker request counter */
};

static inline void ps_worker_init(struct ps_worker *w) {
  memset(w, 0, sizeof(*w));
  w->sock = -1;
}

static inline void ps_client_logf(struct ps_client *c, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static inline void ps_client_logf(struct ps_client *c, const char *fmt, ...) {
  char buf[512];
  va_list ap;

  if (!c->log)
    return;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  c->log(c->log_ctx, buf);
}

/* Tell the owner the spawner is gone, once. Never holds a lock while the
 * callback runs. With `need_hung` the decision is made under the lock from
 * the current miss count, so a reply the reader has just matched (which
 * resets the count) cancels it instead of a stale decision killing the
 * client for good. */
static inline void ps_client_declare_dead(struct ps_client *c, const char *why,
                                          bool need_hung) {
  bool first = false;

  pthread_mutex_lock(&c->lock);
  if (need_hung && (c->dead || c->missed < PS_CLIENT_HANG_LIMIT)) {
    pthread_mutex_unlock(&c->lock);
    return;
  }
  c->dead = true;
  if (!c->dead_notified && !c->stopping) {
    c->dead_notified = true;
    first = true;
  }
  pthread_cond_broadcast(&c->cond);
  pthread_mutex_unlock(&c->lock);
  if (first) {
    ps_client_logf(c, "privsep spawner lost: %s", why);
    if (c->on_dead)
      c->on_dead(c->on_dead_ctx);
  }
}

static inline void ps_client_notify_dead(struct ps_client *c, const char *why) {
  ps_client_declare_dead(c, why, false);
}

static inline void ps_client_declare_hung(struct ps_client *c) {
  ps_client_declare_dead(c, "no reply to several consecutive SPAWNs", true);
}

/* KILL by id, best effort and never blocking: if the spawner has stopped
 * draining its channel the message is dropped, which is what a hang counter
 * and the exit-on-death policy are for. */
static inline void ps_client_send_kill(struct ps_client *c, uint64_t worker_id) {
  struct ps_ctl_msg m;

  ps_ctl_msg_init(&m, PS_MSG_KILL);
  m.worker_id = worker_id;
  pthread_mutex_lock(&c->wlock);
  (void)ps_ctl_sendf(c->ctl, &m, -1, MSG_DONTWAIT);
  pthread_mutex_unlock(&c->wlock);
}

static inline struct ps_waiter *ps_waiter_find(struct ps_client *c,
                                               uint64_t request_id) {
  for (int i = 0; i < PS_CLIENT_MAX_WAITERS; i++)
    if (c->waiters[i].used && c->waiters[i].request_id == request_id)
      return &c->waiters[i];
  return NULL;
}

/* The one thread that reads the channel. It hands each READY/FAILED to the
 * scan thread waiting on that request id, applies each EXITED to the worker
 * table, and drops (logging) anything naming a request or worker it does not
 * know. A READY for a request nobody waits for any more is cleaned up here:
 * the worker's socket is closed and the worker killed, so a scan thread that
 * timed out cannot leak a worker. */
static inline void *ps_client_reader(void *arg) {
  struct ps_client *c = arg;
  const char *why = "end of file on the control channel";

  for (;;) {
    struct ps_ctl_msg m;
    int fd = -1;
    enum ps_ctl_recv_result r = ps_ctl_recv(c->ctl, PS_FROM_SPAWNER, 0, &m, &fd);
    uint64_t kill_id = 0;
    char note[256];

    note[0] = '\0';
    if (r == PS_CTL_EOF)
      break;
    if (r == PS_CTL_ERROR) {
      why = "read error on the control channel";
      break;
    }
    if (r == PS_CTL_BAD) {
      ps_client_logf(c, "privsep: dropped a malformed message from the spawner");
      continue;
    }

    pthread_mutex_lock(&c->lock);
    if (m.type == PS_MSG_READY || m.type == PS_MSG_FAILED) {
      struct ps_waiter *w = ps_waiter_find(c, m.request_id);

      if (!w || w->done) {
        /* Nobody to hand it to. A READY still owns a live worker. */
        snprintf(note, sizeof(note), "privsep: %s for unknown request %llu",
                 m.type == PS_MSG_READY ? "READY" : "FAILED",
                 (unsigned long long)m.request_id);
        if (m.type == PS_MSG_READY)
          kill_id = m.worker_id;
      } else if (w->abandoned) {
        c->missed = 0; /* only a reply that matches a SPAWN proves liveness */
        snprintf(note, sizeof(note),
                 "privsep: late %s for abandoned request %llu",
                 m.type == PS_MSG_READY ? "READY" : "FAILED",
                 (unsigned long long)m.request_id);
        if (m.type == PS_MSG_READY)
          kill_id = m.worker_id;
        memset(w, 0, sizeof(*w));
        w->fd = -1;
      } else {
        c->missed = 0;
        w->reply = m;
        w->fd = fd;
        fd = -1;
        w->done = true;
      }
      if (m.type == PS_MSG_READY && !kill_id) {
        struct ps_wentry *e = NULL;

        for (int i = 0; i < PS_SPAWNER_MAX_WORKERS && !e; i++)
          if (!c->workers[i].used)
            e = &c->workers[i];
        if (e) {
          e->used = true;
          e->worker_id = m.worker_id;
          e->pid = m.pid;
        }
        /* A full table cannot happen (it is the spawner's size); a worker we
         * could not track still works, it just cannot be logged by id. */
      }
    } else if (m.type == PS_MSG_EXITED) {
      struct ps_wentry *e = NULL;

      for (int i = 0; i < PS_SPAWNER_MAX_WORKERS && !e; i++)
        if (c->workers[i].used && c->workers[i].worker_id == m.worker_id)
          e = &c->workers[i];
      if (e) {
        char st[160];

        ps_describe_status(m.detail, st, sizeof(st));
        snprintf(note, sizeof(note), "privsep: worker %llu (pid %d) %s",
                 (unsigned long long)m.worker_id, (int)e->pid, st);
        memset(e, 0, sizeof(*e));
      } else {
        snprintf(note, sizeof(note), "privsep: EXITED for unknown worker %llu",
                 (unsigned long long)m.worker_id);
      }
    }
    pthread_cond_broadcast(&c->cond);
    pthread_mutex_unlock(&c->lock);

    if (fd >= 0)
      close(fd); /* READY we had no taker for */
    if (kill_id)
      ps_client_send_kill(c, kill_id);
    if (note[0])
      ps_client_logf(c, "%s", note);
  }

  pthread_mutex_lock(&c->lock);
  bool stopping = c->stopping;
  pthread_mutex_unlock(&c->lock);
  if (!stopping)
    ps_client_notify_dead(c, why);
  else {
    pthread_mutex_lock(&c->lock);
    c->dead = true;
    pthread_cond_broadcast(&c->cond);
    pthread_mutex_unlock(&c->lock);
  }
  return NULL;
}

/* Adopt the spawner's channel (from ps_spawner_start()) and start the reader.
 * `uid`/`gid` are what the workers must run as (checked in ps_client_spawn()
 * when verify_proc is set). Returns 0, or -1 if the reader thread could not be
 * created. Safe to call after other threads exist: the spawner has already
 * been forked by then. */
static inline int ps_client_attach(struct ps_client *c, int ctl_fd,
                                   pid_t spawner_pid, uid_t uid, gid_t gid,
                                   bool verify_proc) {
  pthread_condattr_t ca;

  memset(c, 0, sizeof(*c));
  c->ctl = ctl_fd;
  c->spawner_pid = spawner_pid;
  c->uid = uid;
  c->gid = gid;
  c->verify_proc = verify_proc;
  for (int i = 0; i < PS_CLIENT_MAX_WAITERS; i++)
    c->waiters[i].fd = -1;
  pthread_mutex_init(&c->wlock, NULL);
  pthread_mutex_init(&c->lock, NULL);
  pthread_condattr_init(&ca);
  pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
  pthread_cond_init(&c->cond, &ca);
  pthread_condattr_destroy(&ca);
  return 0;
}

/* Set callbacks, then call this to start the reader (kept separate so the
 * hooks are in place before the first message can arrive). */
static inline int ps_client_start(struct ps_client *c) {
  if (pthread_create(&c->reader, NULL, ps_client_reader, c) != 0)
    return -1;
  c->reader_started = true;
  return 0;
}

enum ps_spawn_status {
  PS_SPAWN_OK = 0,
  PS_SPAWN_FAILED,     /* the spawner replied FAILED; see info */
  PS_SPAWN_TIMEOUT,    /* no reply within the bound */
  PS_SPAWN_DEAD,       /* the spawner is gone (or treated as hung) */
  PS_SPAWN_BAD_WORKER, /* READY, but the /proc check rejected the worker */
  PS_SPAWN_BUSY        /* too many requests outstanding, or a send failed */
};

struct ps_spawn_info {
  uint32_t reason; /* enum ps_fail_reason when PS_SPAWN_FAILED */
  int detail;      /* hardening step / errno / wait status, per reason */
  char why[160];   /* PS_SPAWN_BAD_WORKER: the first thing wrong */
};

/* Get a hardened worker. `timeout_ms` should be a little above the spawner's
 * own startup timeout. On PS_SPAWN_OK, *w is ready for ps_client_scan().
 *
 * Every failure leaves *w without a socket and nothing leaked: a worker the
 * check rejects is killed through the spawner and its socket closed; a request
 * that times out keeps its table slot, so a READY that arrives late is
 * recognised by the reader and cleaned up instead of leaking a worker. */
static inline enum ps_spawn_status
ps_client_spawn(struct ps_client *c, struct ps_worker *w, int timeout_ms,
                struct ps_spawn_info *info) {
  struct ps_waiter *slot = NULL;
  struct ps_ctl_msg m, reply;
  struct timespec dl;
  uint64_t rid;
  int fd = -1, rc;
  bool got;

  ps_worker_init(w);
  memset(info, 0, sizeof(*info));

  pthread_mutex_lock(&c->lock);
  if (c->dead) {
    pthread_mutex_unlock(&c->lock);
    return PS_SPAWN_DEAD;
  }
  for (int i = 0; i < PS_CLIENT_MAX_WAITERS && !slot; i++)
    if (!c->waiters[i].used)
      slot = &c->waiters[i];
  if (!slot) {
    pthread_mutex_unlock(&c->lock);
    return PS_SPAWN_BUSY;
  }
  rid = ++c->next_request_id;
  memset(slot, 0, sizeof(*slot));
  slot->used = true;
  slot->request_id = rid;
  slot->fd = -1;
  pthread_mutex_unlock(&c->lock);

  ps_ctl_msg_init(&m, PS_MSG_SPAWN);
  m.request_id = rid;
  pthread_mutex_lock(&c->wlock);
  rc = ps_ctl_sendf(c->ctl, &m, -1, MSG_DONTWAIT);
  pthread_mutex_unlock(&c->wlock);
  if (rc < 0) {
    int e = errno;

    pthread_mutex_lock(&c->lock);
    memset(slot, 0, sizeof(*slot));
    slot->fd = -1;
    pthread_mutex_unlock(&c->lock);
    /* EAGAIN: the spawner has stopped reading. Anything else: it is gone. */
    return e == EAGAIN ? PS_SPAWN_BUSY : PS_SPAWN_DEAD;
  }

  clock_gettime(CLOCK_MONOTONIC, &dl);
  dl.tv_sec += timeout_ms / 1000;
  dl.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
  if (dl.tv_nsec >= 1000000000L) {
    dl.tv_sec++;
    dl.tv_nsec -= 1000000000L;
  }

  pthread_mutex_lock(&c->lock);
  while (!slot->done && !c->dead) {
    if (pthread_cond_timedwait(&c->cond, &c->lock, &dl) != 0)
      break;
  }
  got = slot->done;
  if (got) {
    reply = slot->reply;
    fd = slot->fd;
    memset(slot, 0, sizeof(*slot));
    slot->fd = -1;
  } else {
    /* Keep the slot: a late reply must find it. */
    slot->abandoned = true;
    c->missed++;
  }
  {
    bool hung = !got && !c->dead && c->missed >= PS_CLIENT_HANG_LIMIT;
    bool dead = c->dead;

    pthread_mutex_unlock(&c->lock);
    if (!got) {
      if (hung)
        ps_client_declare_hung(c);
      return dead || hung ? PS_SPAWN_DEAD : PS_SPAWN_TIMEOUT;
    }
  }

  if (reply.type == PS_MSG_FAILED) {
    info->reason = reply.reason;
    info->detail = reply.detail;
    return PS_SPAWN_FAILED;
  }

  /* READY. The check reads the worker's own status, so what the spawner
   * claimed is not taken on trust. */
  if (c->verify_proc &&
      !ps_verify_worker((pid_t)reply.pid, c->uid, c->gid, c->spawner_pid,
                        info->why, sizeof(info->why))) {
    close(fd);
    ps_client_send_kill(c, reply.worker_id);
    return PS_SPAWN_BAD_WORKER;
  }

  w->sock = fd;
  w->worker_id = reply.worker_id;
  w->pid = (pid_t)reply.pid;
  return PS_SPAWN_OK;
}

/* Drop a worker we are done with: closing the socket makes it exit, and the
 * spawner reaps it. Idempotent. */
static inline void ps_client_release(struct ps_client *c, struct ps_worker *w) {
  (void)c;
  if (w->sock >= 0)
    close(w->sock);
  ps_worker_init(w);
}

/* Replace a worker after an anomaly: kill it through the spawner (only the
 * spawner signals workers) and never reuse its socket, so a late reply can
 * never be matched to a later scan. */
static inline void ps_client_discard(struct ps_client *c, struct ps_worker *w) {
  uint64_t id = w->worker_id;

  if (w->sock >= 0 && id)
    ps_client_send_kill(c, id);
  ps_client_release(c, w);
}

/* One scan. Sends the already-open `fd` with a fixed-size header, waits at
 * most `timeout_ms` for the reply and validates it. Returns true and fills
 * *out only for a well-formed reply to this request; on ANY anomaly (send
 * failure, timeout, EOF, wrong length, bad magic/version/id, a verdict
 * outside {CLEAN, MALICIOUS}, descriptors attached to the reply...) the worker
 * is discarded, *out is the canonical failure result and `*why` says what. A
 * caller that ignores the return value still fails open correctly.
 *
 * The caller keeps `fd` and closes it when its own work (quarantine) is done:
 * the descriptor is duplicated into the worker by SCM_RIGHTS. */
static inline bool ps_client_scan(struct ps_client *c, struct ps_worker *w,
                                  int fd, int timeout_ms,
                                  struct ps_verdict *out, const char **why) {
  struct ps_request rq;
  unsigned char buf[sizeof(struct ps_reply) + 1];
  union {
    char b[CMSG_SPACE(sizeof(int) * PS_CTL_MAX_FDS)];
    struct cmsghdr align;
  } ctl;
  struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
  struct msghdr msg;
  struct pollfd pf;
  int64_t end = ps_now_ms() + timeout_ms;
  ssize_t len;
  uint64_t rid;
  bool had_fds = false;
  const char *reason;

  ps_verdict_failure(out);
  if (w->sock < 0) {
    *why = "no worker";
    return false;
  }

  rid = ++w->next_id;
  ps_request_init(&rq, rid);
  if (ps_sendmsg_fd(w->sock, &rq, sizeof(rq), fd, MSG_DONTWAIT) < 0) {
    reason = "could not send the request to the worker";
    goto anomaly;
  }

  pf.fd = w->sock;
  pf.events = POLLIN;
  for (;;) {
    int64_t left = end - ps_now_ms();
    int pr;

    if (left < 0)
      left = 0;
    pr = poll(&pf, 1, (int)left);
    if (pr < 0 && errno == EINTR)
      continue;
    if (pr < 0) {
      reason = "poll on the worker socket failed";
      goto anomaly;
    }
    if (pr == 0) {
      reason = "the worker did not reply in time";
      goto anomaly;
    }
    break;
  }

  memset(&msg, 0, sizeof(msg));
  memset(&ctl, 0, sizeof(ctl));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = ctl.b;
  msg.msg_controllen = sizeof(ctl.b);
  do {
    len = recvmsg(w->sock, &msg, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
  } while (len < 0 && errno == EINTR);

  /* A worker may attach descriptors to a reply. Whatever arrived is closed
   * on every path, so a hostile worker cannot make the parent accumulate
   * them. */
  for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); len >= 0 && cm;
       cm = CMSG_NXTHDR(&msg, cm)) {
    if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
      size_t cnt = (cm->cmsg_len - CMSG_LEN(0)) / sizeof(int);
      int tmp[PS_CTL_MAX_FDS];

      if (cnt > PS_CTL_MAX_FDS)
        cnt = PS_CTL_MAX_FDS;
      memcpy(tmp, CMSG_DATA(cm), cnt * sizeof(int));
      for (size_t k = 0; k < cnt; k++)
        close(tmp[k]);
      had_fds = true;
    }
  }

  if (len < 0) {
    reason = "recv from the worker failed";
    goto anomaly;
  }
  if (len == 0) {
    reason = "the worker closed its socket (it died, or sent an empty record)";
    goto anomaly;
  }
  if (had_fds || (msg.msg_flags & MSG_CTRUNC)) {
    reason = "the worker attached descriptors to its reply";
    goto anomaly;
  }
  if (!ps_reply_validate(buf, (size_t)len, rid, out)) {
    reason = "the worker's reply was malformed";
    goto anomaly;
  }
  return true;

anomaly:
  ps_verdict_failure(out);
  ps_client_discard(c, w);
  *why = reason;
  return false;
}

/* Orderly shutdown: stop the reader (which makes the spawner see the channel
 * close, kill every worker and exit), then reap the spawner, killing it if it
 * does not go. Safe to call once. */
static inline void ps_client_stop(struct ps_client *c) {
  int st = 0;
  int64_t end = ps_now_ms() + 5000;
  bool gone = false;

  pthread_mutex_lock(&c->lock);
  c->stopping = true;
  pthread_mutex_unlock(&c->lock);
  shutdown(c->ctl, SHUT_RDWR);
  if (c->reader_started)
    pthread_join(c->reader, NULL);
  close(c->ctl);
  c->ctl = -1;
  while (c->spawner_pid > 0) {
    pid_t r = waitpid(c->spawner_pid, &st, WNOHANG);

    /* ECHILD: already reaped elsewhere (SIGCHLD ignored, or a wait(-1)). It
     * is gone, and its pid may be reused, so it must not be signalled. */
    if (r == c->spawner_pid || (r < 0 && errno == ECHILD)) {
      gone = true;
      break;
    }
    if (ps_now_ms() >= end)
      break;
    usleep(10 * 1000);
  }
  if (!gone && c->spawner_pid > 0) {
    kill(c->spawner_pid, SIGKILL);
    waitpid(c->spawner_pid, &st, 0);
  }
}

#endif /* AV_PRIVSEP_CLIENT_H */
