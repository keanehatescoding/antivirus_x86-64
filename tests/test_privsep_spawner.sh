#!/usr/bin/env bash
#
# tests/test_privsep_spawner.sh - coverage for userspace/avd/privsep_spawner.h,
# the spawner process and its control channel (#103, Stage 1c; see
# docs/privilege-separation.md, "The spawner", "Correlating replies" and
# "Reaping and lifecycle").
#
# Three binaries, all against the production header compiled standalone (same
# arrangement as test_privsep_worker.sh):
#
#   beh     ASan+UBSan. The control-channel wire format (validation matrix,
#           descriptor handling, no leaks) and the spawner's behaviour: spawn,
#           round trip over the passed worker socket, KILL, EXITED, every
#           failure reason, concurrent spawns answered out of order, reaping,
#           descriptor hygiene, orderly shutdown and parent death. The forked
#           worker's hardening is replaced by a test-only stub (compiled in
#           only with PS_SPAWNER_TEST_HOOKS), so this needs no root.
#   limits  Same, built with tiny table sizes to hit the resource limits.
#   kern    Plain build, real kernel, real hardening (uid change, empty
#           capability sets, NoNewPrivs, seccomp) with the parent-side view
#           from /proc/<pid>/status. Needs root; without it these tests print
#           SKIP, never PASS:
#             sudo tests/test_privsep_spawner.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${PS_SRC_DIR:-$REPO_ROOT/userspace/avd}"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_privsep_spawner.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
# False positive: cleanup() IS invoked via `trap` on the next line.
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
cat > "$BUILD_DIR/common.h" <<'EOF'
#ifndef T_COMMON_H
#define T_COMMON_H
#pragma GCC diagnostic ignored "-Wunused-function"
#include <dirent.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#include "privsep_spawner.h"

static int PASS, FAIL, SKIP;

#define CHECK(cond, label) do { \
    if (cond) { printf("  PASS: %s\n", label); PASS++; } \
    else { printf("  FAIL: %s\n", label); FAIL++; } \
} while (0)

#define SKIPT(label) do { printf("  SKIP: %s\n", label); SKIP++; } while (0)

#define SUMMARY(name) do { \
    printf("\n===================================\n"); \
    printf("%s: %d passed, %d failed, %d skipped\n", name, PASS, FAIL, SKIP); \
    printf("===================================\n"); \
    return FAIL ? 1 : 0; \
} while (0)

/* Entries in a /proc/<pid>/fd directory. Only for /proc/self/fd is the
 * descriptor opendir() itself uses one to skip: in another process's
 * directory that number means something else entirely. */
static int count_fds_dir(const char *path, bool self) {
    DIR *d = opendir(path);
    struct dirent *e;
    int n = 0, dfd;

    if (!d) return -1;
    dfd = dirfd(d);
    while ((e = readdir(d)))
        if (e->d_name[0] != '.' && !(self && atoi(e->d_name) == dfd)) n++;
    closedir(d);
    return n;
}
static int count_fds(void) { return count_fds_dir("/proc/self/fd", true); }
static void dump_fds(pid_t pid) {
    char dir[64], p[400], t[128];
    struct dirent *e;
    DIR *d;

    snprintf(dir, sizeof(dir), "/proc/%d/fd", (int)pid);
    d = opendir(dir);
    if (!d) return;
    while ((e = readdir(d))) {
        ssize_t n;
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        n = readlink(p, t, sizeof(t) - 1);
        if (n < 0) continue;
        t[n] = 0;
        printf("      fd %s -> %s\n", e->d_name, t);
    }
    closedir(d);
}
static int fds_of_raw(pid_t pid);
/* The spawner sends READY and only then closes its own copy of the worker
 * socket, so a count taken the instant READY arrives can include that
 * descriptor for a moment. Wait until two reads agree. */
static int fds_of(pid_t pid) {
    int prev = fds_of_raw(pid);
    for (int i = 0; i < 50; i++) {
        int cur;
        usleep(20 * 1000);
        cur = fds_of_raw(pid);
        if (cur == prev) return cur;
        prev = cur;
    }
    return prev;
}
static int fds_of_raw(pid_t pid) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/fd", (int)pid);
    return count_fds_dir(p, false);
}

/* Children of `parent`, and how many of them are zombies. */
static int child_stats(pid_t parent, int *zombies) {
    DIR *d = opendir("/proc");
    struct dirent *e;
    int n = 0;

    *zombies = 0;
    if (!d) return -1;
    while ((e = readdir(d))) {
        char p[300], buf[512], *rp;
        char st;
        int pp;
        FILE *f;
        size_t l;

        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(p, sizeof(p), "/proc/%s/stat", e->d_name);
        f = fopen(p, "r");
        if (!f) continue;
        l = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[l] = 0;
        rp = strrchr(buf, ')');
        if (rp && sscanf(rp + 1, " %c %d", &st, &pp) == 2 && pp == parent) {
            n++;
            if (st == 'Z') (*zombies)++;
        }
    }
    closedir(d);
    return n;
}

/* Wait (bounded) until `parent` has exactly `want` children and no zombies. */
static bool children_settle(pid_t parent, int want, int ms) {
    int64_t end = ps_now_ms() + ms;
    for (;;) {
        int z, n = child_stats(parent, &z);
        if (n == want && z == 0) return true;
        if (ps_now_ms() >= end) return false;
        usleep(20 * 1000);
    }
}

static int ppid_of(pid_t pid) {
    char p[64], buf[512], *rp;
    char st;
    int pp = -1;
    FILE *f;
    size_t l;

    snprintf(p, sizeof(p), "/proc/%d/stat", (int)pid);
    f = fopen(p, "r");
    if (!f) return -1;
    l = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[l] = 0;
    rp = strrchr(buf, ')');
    if (!rp || sscanf(rp + 1, " %c %d", &st, &pp) != 2) return -1;
    return pp;
}

static unsigned long cpu_ticks(pid_t pid) {
    char p[64], buf[512], *rp;
    unsigned long ut = 0, stt = 0;
    char st;
    int pp;
    FILE *f;
    size_t l;

    snprintf(p, sizeof(p), "/proc/%d/stat", (int)pid);
    f = fopen(p, "r");
    if (!f) return 0;
    l = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[l] = 0;
    rp = strrchr(buf, ')');
    if (rp)
        sscanf(rp + 1, " %c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
               &st, &pp, &ut, &stt);
    return ut + stt;
}

static int send_msg(int sock, const void *buf, size_t len, const int *fds,
                    int nfds) {
    struct iovec iov = {.iov_base = (void *)buf, .iov_len = len};
    union { char b[CMSG_SPACE(sizeof(int) * 16)]; struct cmsghdr a; } c;
    struct msghdr m;
    struct cmsghdr *cm;

    memset(&m, 0, sizeof(m));
    memset(&c, 0, sizeof(c));
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    if (nfds > 0) {
        m.msg_control = c.b;
        m.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)nfds);
        cm = CMSG_FIRSTHDR(&m);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)nfds);
        memcpy(CMSG_DATA(cm), fds, sizeof(int) * (size_t)nfds);
    }
    return (int)sendmsg(sock, &m, MSG_NOSIGNAL);
}

static int make_file(const char *content) {
    char path[] = "/tmp/av_privsep_spawner_XXXXXX";
    int fd = mkstemp(path);

    if (fd < 0) return -1;
    unlink(path);
    if (write(fd, content, strlen(content)) < 0) { close(fd); return -1; }
    return fd;
}

/* The scan every worker runs: only pread, so it is legal under the real
 * seccomp filter too. Convicts on "EVIL". */
static void scan_cb(int fd, void *ctx, struct ps_reply *rep) {
    char b[64];
    ssize_t n = pread(fd, b, sizeof(b) - 1, 0);

    (void)ctx;
    if (n < 0) return;
    b[n] = 0;
    rep->inconclusive = 0;
    if (strstr(b, "EVIL")) {
        rep->verdict = PS_VERDICT_MALICIOUS;
        rep->score = 150;
        snprintf(rep->rule_name, sizeof(rep->rule_name), "Test:evil");
    }
}

/* Send a scan request over a worker socket and validate the reply. */
static bool roundtrip(int w, uint64_t rid, const char *content,
                      struct ps_verdict *v) {
    int fd = make_file(content);
    struct ps_request rq;
    unsigned char buf[sizeof(struct ps_reply) + 1];
    struct pollfd p = {.fd = w, .events = POLLIN};
    ssize_t n;

    if (fd < 0) return false;
    ps_request_init(&rq, rid);
    if (send_msg(w, &rq, sizeof(rq), &fd, 1) < 0) { close(fd); return false; }
    close(fd);
    if (poll(&p, 1, 5000) <= 0) return false;
    n = recv(w, buf, sizeof(buf), 0);
    return n > 0 && ps_reply_validate(buf, (size_t)n, rid, v);
}

/* ---- control channel client (what avd.c's reader thread will do) ---- */

#define MAXQ 256
static struct ps_ctl_msg REPLY[MAXQ];
static int REPLY_FD[MAXQ];
static int NREPLY;
static struct ps_ctl_msg EXITS[MAXQ];
static int NEXITS;

static void reset_queues(void) {
    for (int i = 0; i < NREPLY; i++)
        if (REPLY_FD[i] >= 0) close(REPLY_FD[i]);
    NREPLY = NEXITS = 0;
}

/* Read at most one message, waiting up to `ms`. 1 got one, 0 timed out,
 * -1 EOF, -2 malformed. */
static int pump(int ctl, int ms) {
    struct pollfd p = {.fd = ctl, .events = POLLIN};
    struct ps_ctl_msg m;
    int fd = -1;
    enum ps_ctl_recv_result rr;

    if (poll(&p, 1, ms) <= 0) return 0;
    rr = ps_ctl_recv(ctl, PS_FROM_SPAWNER, 0, &m, &fd);
    if (rr == PS_CTL_EOF) return -1;
    if (rr != PS_CTL_OK) return -2;
    if (m.type == PS_MSG_EXITED) {
        if (NEXITS < MAXQ) EXITS[NEXITS++] = m;
    } else if (NREPLY < MAXQ) {
        REPLY[NREPLY] = m;
        REPLY_FD[NREPLY++] = fd;
    } else if (fd >= 0) {
        close(fd);
    }
    return 1;
}

static int find_reply(uint64_t rid) {
    for (int i = 0; i < NREPLY; i++)
        if (REPLY[i].request_id == rid) return i;
    return -1;
}
static int find_exit(uint64_t wid) {
    for (int i = 0; i < NEXITS; i++)
        if (EXITS[i].worker_id == wid) return i;
    return -1;
}
static int count_exits(uint64_t wid) {
    int n = 0;
    for (int i = 0; i < NEXITS; i++)
        if (EXITS[i].worker_id == wid) n++;
    return n;
}

static int wait_reply(int ctl, uint64_t rid, int ms) {
    int64_t end = ps_now_ms() + ms;
    for (;;) {
        int i = find_reply(rid);
        int64_t left = end - ps_now_ms();
        if (i >= 0) return i;
        if (left <= 0 || pump(ctl, (int)left) < 0) return -1;
    }
}
static int wait_exit(int ctl, uint64_t wid, int ms) {
    int64_t end = ps_now_ms() + ms;
    for (;;) {
        int i = find_exit(wid);
        int64_t left = end - ps_now_ms();
        if (i >= 0) return i;
        if (left <= 0 || pump(ctl, (int)left) < 0) return -1;
    }
}
static int take_fd(int i) { int fd = REPLY_FD[i]; REPLY_FD[i] = -1; return fd; }

static int send_spawn(int ctl, uint64_t rid) {
    struct ps_ctl_msg m;
    ps_ctl_msg_init(&m, PS_MSG_SPAWN);
    m.request_id = rid;
    return ps_ctl_send(ctl, &m, -1);
}
static int send_kill(int ctl, uint64_t wid) {
    struct ps_ctl_msg m;
    ps_ctl_msg_init(&m, PS_MSG_KILL);
    m.worker_id = wid;
    return ps_ctl_send(ctl, &m, -1);
}

static struct ps_spawner_cfg base_cfg(void) {
    struct ps_spawner_cfg c;
    memset(&c, 0, sizeof(c));
    c.harden.uid = 65534;
    c.harden.gid = 65534;
    c.harden.as_bytes = 1ull << 30;
    c.harden.cpu_seconds = 60;
    c.harden.nofile = 16;
    c.scan = scan_cb;
    c.startup_timeout_ms = 3000;
    return c;
}

/* Close our end and wait for the spawner; then reap whatever it orphaned
 * (this process is a subreaper). Returns the spawner's wait status. */
static int stop_spawner(int ctl, pid_t sp) {
    int st = 0;
    close(ctl);
    waitpid(sp, &st, 0);
    while (waitpid(-1, NULL, 0) > 0) {
    }
    return st;
}

#ifdef PS_SPAWNER_TEST_HOOKS
/* Scripted worker behaviour, chosen by the fork's ordinal in the spawner
 * (ps_spawner_test_forks is incremented before each fork, so the child sees
 * its own 1-based index). The script is set before the spawner starts and is
 * inherited by it. */
enum { M_OK, M_FAIL, M_SLEEP, M_EXITN, M_GARBAGE, M_EOF, M_SLOW, M_SLOWFAIL };
struct step { int mode; int arg; };
static struct step SCRIPT[16];
static int NSCRIPT;

static int stub_harden(const struct ps_harden_cfg *h) {
    int k = (int)ps_spawner_test_forks - 1;
    struct step st = (k >= 0 && k < NSCRIPT) ? SCRIPT[k] : (struct step){M_OK, 0};

    ps_close_all_but(h->ipc_fd, -1);
    switch (st.mode) {
    case M_OK: return 0;
    case M_FAIL: return st.arg;
    case M_SLOW: usleep((useconds_t)st.arg * 1000); return 0;
    case M_SLOWFAIL: usleep((useconds_t)st.arg * 1000); return PS_H_CAPABILITIES;
    case M_SLEEP: for (;;) pause();
    case M_EXITN: _exit(st.arg);
    case M_GARBAGE:
        (void)!send(h->ipc_fd, "garbage", 7, MSG_NOSIGNAL);
        for (;;) pause();
    case M_EOF: close(h->ipc_fd); for (;;) pause();
    }
    return 0;
}

static void script(int n, const struct step *s) {
    memcpy(SCRIPT, s, sizeof(*s) * (size_t)n);
    NSCRIPT = n;
}

static int start_stubbed(const struct ps_spawner_cfg *cfg, int *ctl, pid_t *sp) {
    ps_spawner_test_harden = stub_harden;
    reset_queues();
    return ps_spawner_start(cfg, ctl, sp);
}
#endif
#endif
EOF

# ---------------------------------------------------------------------------
# beh: wire format + spawner behaviour (ASan+UBSan, no root)
# ---------------------------------------------------------------------------
cat > "$BUILD_DIR/beh.c" <<'EOF'
#include "common.h"

enum fld { F_MAGIC, F_VERSION, F_REASON, F_REQ, F_WID, F_PID, F_DETAIL };

static void setf(struct ps_ctl_msg *m, enum fld f, int64_t v) {
    switch (f) {
    case F_MAGIC: m->magic = (uint32_t)v; break;
    case F_VERSION: m->version = (uint32_t)v; break;
    case F_REASON: m->reason = (uint32_t)v; break;
    case F_REQ: m->request_id = (uint64_t)v; break;
    case F_WID: m->worker_id = (uint64_t)v; break;
    case F_PID: m->pid = (int32_t)v; break;
    case F_DETAIL: m->detail = (int32_t)v; break;
    }
}

/* A valid message of each type. */
static struct ps_ctl_msg canon(int type) {
    struct ps_ctl_msg m;
    ps_ctl_msg_init(&m, (enum ps_ctl_type)type);
    switch (type) {
    case PS_MSG_SPAWN: m.request_id = 5; break;
    case PS_MSG_KILL: m.worker_id = 7; break;
    case PS_MSG_READY: m.request_id = 5; m.worker_id = 7; m.pid = 100; break;
    case PS_MSG_FAILED: m.request_id = 5; m.reason = PS_FAIL_HARDEN; m.detail = 3; break;
    case PS_MSG_EXITED: m.worker_id = 7; m.detail = 9; break;
    default: break;
    }
    return m;
}

static void test_wire_validity(void) {
    static const struct { int type; bool from_main, from_spawner, from_worker; } T[] = {
        {PS_MSG_SPAWN, 1, 0, 0}, {PS_MSG_KILL, 1, 0, 0},
        {PS_MSG_READY, 0, 1, 0}, {PS_MSG_FAILED, 0, 1, 0},
        {PS_MSG_EXITED, 0, 1, 0}, {PS_MSG_WORKER_READY, 0, 0, 1},
    };
    /* {type, field, value, valid?} - one field changed from the canonical
     * message. Fields a type does not use must be zero; the ones it does use
     * must be sane. */
    static const struct { int type; enum fld f; int64_t v; bool ok; } M[] = {
        {PS_MSG_SPAWN, F_MAGIC, 0, false},   {PS_MSG_SPAWN, F_VERSION, 2, false},
        {PS_MSG_SPAWN, F_REASON, 1, false},  {PS_MSG_SPAWN, F_WID, 1, false},
        {PS_MSG_SPAWN, F_PID, 1, false},     {PS_MSG_SPAWN, F_DETAIL, 1, false},
        {PS_MSG_SPAWN, F_REQ, 0, true},      /* id 0 is the caller's choice */
        {PS_MSG_KILL, F_WID, 0, false},      {PS_MSG_KILL, F_REQ, 1, false},
        {PS_MSG_KILL, F_REASON, 1, false},   {PS_MSG_KILL, F_PID, 1, false},
        {PS_MSG_KILL, F_DETAIL, 1, false},
        {PS_MSG_READY, F_WID, 0, false},     {PS_MSG_READY, F_PID, 0, false},
        {PS_MSG_READY, F_PID, -1, false},    {PS_MSG_READY, F_REASON, 1, false},
        {PS_MSG_READY, F_DETAIL, 1, false},
        {PS_MSG_FAILED, F_REASON, 0, false}, {PS_MSG_FAILED, F_REASON, PS_FAIL_END, false},
        {PS_MSG_FAILED, F_REASON, 1000, false}, {PS_MSG_FAILED, F_WID, 1, false},
        {PS_MSG_FAILED, F_PID, 1, false},    {PS_MSG_FAILED, F_DETAIL, -7, true},
        {PS_MSG_EXITED, F_WID, 0, false},    {PS_MSG_EXITED, F_REQ, 1, false},
        {PS_MSG_EXITED, F_REASON, 1, false}, {PS_MSG_EXITED, F_PID, 1, false},
        {PS_MSG_EXITED, F_DETAIL, 0x100, true},
        {PS_MSG_WORKER_READY, F_REQ, 1, false}, {PS_MSG_WORKER_READY, F_WID, 1, false},
        {PS_MSG_WORKER_READY, F_REASON, 1, false}, {PS_MSG_WORKER_READY, F_PID, 1, false},
        {PS_MSG_WORKER_READY, F_DETAIL, 1, false},
    };
    bool matrix = true, mut = true, types = true;
    struct ps_ctl_msg m;

    printf("\ncontrol channel: message validity\n");
    CHECK(sizeof(struct ps_ctl_msg) == 40, "the wire struct is 40 bytes, no padding");

    for (size_t i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
        m = canon(T[i].type);
        if (ps_ctl_msg_valid(&m, PS_FROM_MAIN) != T[i].from_main ||
            ps_ctl_msg_valid(&m, PS_FROM_SPAWNER) != T[i].from_spawner ||
            ps_ctl_msg_valid(&m, PS_FROM_WORKER) != T[i].from_worker) {
            printf("    sender matrix wrong for type %d\n", T[i].type);
            matrix = false;
        }
    }
    CHECK(matrix, "each message type is accepted only from its legitimate sender");

    for (size_t i = 0; i < sizeof(M) / sizeof(M[0]); i++) {
        enum ps_ctl_from from = M[i].type <= PS_MSG_KILL ? PS_FROM_MAIN
                              : M[i].type == PS_MSG_WORKER_READY ? PS_FROM_WORKER
                              : PS_FROM_SPAWNER;
        m = canon(M[i].type);
        setf(&m, M[i].f, M[i].v);
        if (ps_ctl_msg_valid(&m, from) != M[i].ok) {
            printf("    mutation %zu wrong (type %d field %d value %lld)\n", i,
                   M[i].type, (int)M[i].f, (long long)M[i].v);
            mut = false;
        }
    }
    CHECK(mut, "unused fields must be zero and used fields sane (per-field table)");

    for (int t = 0; t < 3; t++) {
        int bad[] = {0, PS_MSG_TYPE_END, 99};
        ps_ctl_msg_init(&m, PS_MSG_SPAWN);
        m.type = (uint32_t)bad[t];
        if (ps_ctl_msg_valid(&m, PS_FROM_MAIN) || ps_ctl_msg_valid(&m, PS_FROM_SPAWNER) ||
            ps_ctl_msg_valid(&m, PS_FROM_WORKER))
            types = false;
    }
    CHECK(types, "type 0, the end marker and an unknown type are never valid");
    CHECK(!ps_ctl_msg_valid(&m, (enum ps_ctl_from)42), "an unknown sender class is refused");
}

static void test_wire_recv(void) {
    int sv[2], fds[2], tmp[9], got = -1;
    int before;
    struct ps_ctl_msg m, ok, junk;
    unsigned char big[100];
    int one;

    printf("\ncontrol channel: receive and descriptor handling\n");
    memset(&junk, 0, sizeof(junk));
    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
    fds[0] = make_file("x");
    before = count_fds();

    /* READY + exactly one descriptor is the only way a descriptor is accepted. */
    ok = canon(PS_MSG_READY);
    ps_ctl_send(sv[0], &ok, fds[0]);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_OK && got >= 0 &&
              m.type == PS_MSG_READY && m.worker_id == 7 && m.pid == 100,
          "READY with one descriptor is accepted and the descriptor handed over");
    if (got >= 0) close(got);
    got = -1;

    ps_ctl_send(sv[0], &ok, -1);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_BAD && got == -1 &&
              m.type == 0,
          "READY without a descriptor is malformed (and the output is zeroed)");

    tmp[0] = tmp[1] = fds[0];
    send_msg(sv[0], &ok, sizeof(ok), tmp, 2);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_BAD && got == -1,
          "READY with two descriptors is malformed");

    m = canon(PS_MSG_FAILED);
    ps_ctl_send(sv[0], &m, fds[0]);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_BAD && got == -1,
          "a descriptor on FAILED is malformed");

    m = canon(PS_MSG_SPAWN);
    ps_ctl_send(sv[0], &m, fds[0]);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_MAIN, 0, &m, &got) == PS_CTL_BAD && got == -1,
          "a descriptor on SPAWN is malformed");

    for (int i = 0; i < 9; i++) tmp[i] = fds[0];
    send_msg(sv[0], &ok, sizeof(ok), tmp, 9);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_BAD && got == -1,
          "more descriptors than the receive buffer holds is malformed");

    send_msg(sv[0], &ok, sizeof(ok) - 1, &fds[0], 1);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_BAD && got == -1,
          "a short message is malformed");
    send_msg(sv[0], big, sizeof(ok) + 1, &fds[0], 1);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_BAD && got == -1,
          "a message one byte too long is malformed");
    memset(big, 0xAB, sizeof(big));
    send_msg(sv[0], big, sizeof(big), &fds[0], 1);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_BAD && got == -1,
          "an oversized (truncated) message is malformed");

    m = canon(PS_MSG_FAILED);
    m.magic ^= 1;
    ps_ctl_send(sv[0], &m, -1);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_BAD,
          "a bad magic is malformed");

    one = 1;
    setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
    m = canon(PS_MSG_FAILED);
    ps_ctl_send(sv[0], &m, -1);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_BAD,
          "an ancillary message of another type (SCM_CREDENTIALS) is malformed");
    one = 0;
    setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));

    m = canon(PS_MSG_EXITED);
    ps_ctl_send(sv[0], &m, -1);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_OK && m.type == PS_MSG_EXITED,
          "a valid message after a run of malformed ones is still accepted");

    /* recvmsg() returns 0 for an empty SEQPACKET record just as it does for
     * a closed peer; with the peer still open it must not read as EOF. */
    (void)!send(sv[0], "", 0, MSG_NOSIGNAL);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_BAD,
          "a zero-length record from a live peer is malformed, not EOF");
    m = canon(PS_MSG_EXITED);
    ps_ctl_send(sv[0], &m, -1);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_OK,
          "and the channel is still usable afterwards");

    errno = 0;
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, MSG_DONTWAIT, &m, &got) == PS_CTL_ERROR &&
              errno == EAGAIN,
          "MSG_DONTWAIT on an empty channel reports EAGAIN");

    /* A write-half-closed peer will never send again, so it is EOF. Reporting
     * it as malformed would leave the socket readable forever and spin any
     * loop that drops malformed messages. (Run after the EAGAIN check above:
     * once the peer half-closes, recvmsg() returns 0 instead of EAGAIN.) */
    CHECK(shutdown(sv[0], SHUT_WR) == 0, "the peer can half-close its write side");
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_EOF,
          "a write-half-closed peer is EOF, not malformed");

    CHECK(count_fds() == before, "no descriptor leaked across all of the above");

    close(sv[0]);
    CHECK(ps_ctl_recv(sv[1], PS_FROM_SPAWNER, 0, &m, &got) == PS_CTL_EOF,
          "the peer closing is EOF");
    CHECK(ps_ctl_send(sv[1], &ok, -1) < 0 && errno == EPIPE,
          "sending to a closed peer is EPIPE, not SIGPIPE");
    close(sv[1]);
    close(fds[0]);
}

#ifdef PS_SPAWNER_TEST_HOOKS

static void test_spawn_basic(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    int ctl, a, b, expect_fds;
    pid_t sp;
    struct ps_verdict v;
    int wa, wb, z;

    printf("\nspawner: spawn, round trip, KILL, EXITED\n");
    NSCRIPT = 0;
    CHECK(start_stubbed(&cfg, &ctl, &sp) == 0 && sp > 0, "the spawner starts");

    send_spawn(ctl, 11);
    send_spawn(ctl, 12);
    a = wait_reply(ctl, 11, 5000);
    b = wait_reply(ctl, 12, 5000);
    CHECK(a >= 0 && b >= 0 && REPLY[a].type == PS_MSG_READY && REPLY[b].type == PS_MSG_READY,
          "two SPAWNs get two READYs");
    if (a < 0 || b < 0) { stop_spawner(ctl, sp); return; }
    CHECK(REPLY[a].worker_id == 1 && REPLY[b].worker_id == 2,
          "worker ids start at 1 and increase");
    CHECK(REPLY[a].pid > 0 && REPLY[b].pid > 0 && REPLY[a].pid != REPLY[b].pid,
          "READY carries distinct pids");
    CHECK(ppid_of(REPLY[a].pid) == sp && ppid_of(REPLY[b].pid) == sp,
          "the workers are children of the spawner");

    wa = take_fd(a);
    wb = take_fd(b);
    CHECK(wa >= 0 && wb >= 0, "READY carries the worker socket");
    CHECK(roundtrip(wa, 1001, "this is EVIL data", &v) && v.verdict == PS_VERDICT_MALICIOUS &&
              !v.inconclusive && strcmp(v.rule_name, "Test:evil") == 0,
          "a scan round trip over the passed socket convicts");
    CHECK(roundtrip(wb, 1002, "harmless", &v) && v.verdict == PS_VERDICT_CLEAN && !v.inconclusive,
          "and a clean file is clean, on the other worker");

    expect_fds = 2 + (fcntl(2, F_GETFD) >= 0);
    if (fds_of(sp) != expect_fds) dump_fds(sp);
    CHECK(fds_of(sp) == expect_fds,
          "the spawner holds only its channel, the signalfd and stderr");

    /* KILL */
    send_kill(ctl, 1);
    CHECK(wait_exit(ctl, 1, 5000) >= 0 && WIFSIGNALED(EXITS[find_exit(1)].detail) &&
              WTERMSIG(EXITS[find_exit(1)].detail) == SIGKILL,
          "KILL produces EXITED with the SIGKILL wait status");
    {
        char c;
        struct pollfd pf = {.fd = wa, .events = POLLIN};
        CHECK(poll(&pf, 1, 3000) == 1 && recv(wa, &c, 1, MSG_DONTWAIT) == 0,
              "the killed worker's socket reads EOF in main");
    }
    close(wa);

    send_kill(ctl, 1);   /* already gone */
    send_kill(ctl, 999); /* never existed */
    send_spawn(ctl, 13);
    CHECK(wait_reply(ctl, 13, 5000) >= 0 && REPLY[find_reply(13)].type == PS_MSG_READY,
          "KILL of an exited or unknown id is a no-op and the spawner carries on");
    CHECK(count_exits(1) == 1 && count_exits(999) == 0,
          "no second or invented EXITED");
    if (find_reply(13) >= 0) close(take_fd(find_reply(13)));

    /* The worker exits by itself when main closes its socket. */
    close(wb);
    CHECK(wait_exit(ctl, 2, 5000) >= 0 && WIFEXITED(EXITS[find_exit(2)].detail) &&
              WEXITSTATUS(EXITS[find_exit(2)].detail) == 0,
          "closing the worker socket makes the worker exit 0, reported as EXITED");

    /* worker 3 is still live (its socket was closed by us above, so it exits too) */
    (void)wait_exit(ctl, 3, 5000);
    CHECK(children_settle(sp, 0, 3000) && (child_stats(sp, &z), z == 0),
          "every worker was reaped: no children, no zombies");
    stop_spawner(ctl, sp);
}

static void test_failures(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    int ctl, i;
    pid_t sp;
    int64_t t0;
    bool all = true;

    printf("\nspawner: every failure reason\n");

    /* A hardening failure at each step is reported with that step. */
    {
        struct step s[PS_H_STEP_COUNT];
        for (int k = 1; k < PS_H_STEP_COUNT; k++) s[k - 1] = (struct step){M_FAIL, k};
        script(PS_H_STEP_COUNT - 1, s);
    }
    start_stubbed(&cfg, &ctl, &sp);
    for (int k = 1; k < PS_H_STEP_COUNT; k++) {
        send_spawn(ctl, 100 + (uint64_t)k);
        i = wait_reply(ctl, 100 + (uint64_t)k, 5000);
        if (i < 0 || REPLY[i].type != PS_MSG_FAILED || REPLY[i].reason != PS_FAIL_HARDEN ||
            REPLY[i].detail != k) {
            printf("    step %d not reported correctly\n", k);
            all = false;
        }
    }
    CHECK(all, "a hardening failure at each of the steps is FAILED(HARDEN, that step)");
    CHECK(children_settle(sp, 0, 3000), "the failed workers were all reaped");
    stop_spawner(ctl, sp);

    /* Exit codes that must NOT be mistaken for a hardening failure. */
    {
        struct step s[] = {{M_EXITN, 3}, {M_EXITN, PS_EXIT_HARDEN_BASE},
                           {M_EXITN, PS_EXIT_HARDEN_BASE + PS_H_STEP_COUNT},
                           {M_EXITN, PS_EXIT_READY_SEND}};
        script(4, s);
    }
    start_stubbed(&cfg, &ctl, &sp);
    all = true;
    for (int k = 0; k < 4; k++) {
        send_spawn(ctl, 200 + (uint64_t)k);
        i = wait_reply(ctl, 200 + (uint64_t)k, 5000);
        if (i < 0 || REPLY[i].type != PS_MSG_FAILED || REPLY[i].reason != PS_FAIL_EXITED ||
            !WIFEXITED(REPLY[i].detail)) {
            printf("    exit case %d wrong\n", k);
            all = false;
        }
    }
    CHECK(all, "other exit codes before ready are FAILED(EXITED) with the wait status");
    stop_spawner(ctl, sp);

    /* Timeout. */
    {
        struct step s[] = {{M_SLEEP, 0}};
        script(1, s);
    }
    cfg.startup_timeout_ms = 300;
    start_stubbed(&cfg, &ctl, &sp);
    t0 = ps_now_ms();
    send_spawn(ctl, 300);
    i = wait_reply(ctl, 300, 5000);
    {
        int64_t dt = ps_now_ms() - t0;
        CHECK(i >= 0 && REPLY[i].type == PS_MSG_FAILED && REPLY[i].reason == PS_FAIL_TIMEOUT &&
                  dt >= 250 && dt < 3000,
              "a worker that never reports ready is FAILED(TIMEOUT) at the startup timeout");
    }
    CHECK(children_settle(sp, 0, 3000), "the timed-out worker was killed and reaped");
    send_spawn(ctl, 301);
    CHECK(wait_reply(ctl, 301, 5000) >= 0 && REPLY[find_reply(301)].type == PS_MSG_READY,
          "the spawner serves the next request after a timeout");
    stop_spawner(ctl, sp);

    /* Malformed readiness. */
    {
        struct step s[] = {{M_GARBAGE, 0}};
        script(1, s);
    }
    cfg.startup_timeout_ms = 3000;
    start_stubbed(&cfg, &ctl, &sp);
    send_spawn(ctl, 400);
    i = wait_reply(ctl, 400, 5000);
    CHECK(i >= 0 && REPLY[i].type == PS_MSG_FAILED && REPLY[i].reason == PS_FAIL_PROTOCOL,
          "a malformed ready report is FAILED(PROTOCOL)");
    CHECK(children_settle(sp, 0, 3000), "and that worker is killed and reaped");
    stop_spawner(ctl, sp);

    /* A worker that closes its socket but lives on: no spin, then timeout. */
    {
        struct step s[] = {{M_EOF, 0}};
        script(1, s);
    }
    cfg.startup_timeout_ms = 800;
    start_stubbed(&cfg, &ctl, &sp);
    {
        unsigned long c0, c1;
        send_spawn(ctl, 500);
        c0 = cpu_ticks(sp);
        i = wait_reply(ctl, 500, 5000);
        c1 = cpu_ticks(sp);
        CHECK(i >= 0 && REPLY[i].type == PS_MSG_FAILED && REPLY[i].reason == PS_FAIL_TIMEOUT,
              "a worker that closes its socket and lives on is FAILED(TIMEOUT)");
        CHECK(c1 - c0 < 20, "the spawner does not spin on the closed socket (POLLHUP)");
    }
    stop_spawner(ctl, sp);

    /* Fork failure. */
    NSCRIPT = 0;
    cfg.startup_timeout_ms = 3000;
    ps_spawner_test_fail_fork = 2;
    start_stubbed(&cfg, &ctl, &sp);
    ps_spawner_test_fail_fork = 0;
    send_spawn(ctl, 600);
    send_spawn(ctl, 601);
    send_spawn(ctl, 602);
    CHECK(wait_reply(ctl, 600, 5000) >= 0 && REPLY[find_reply(600)].type == PS_MSG_READY,
          "the first spawn succeeds");
    i = wait_reply(ctl, 601, 5000);
    CHECK(i >= 0 && REPLY[i].type == PS_MSG_FAILED && REPLY[i].reason == PS_FAIL_FORK &&
              REPLY[i].detail == EAGAIN,
          "a failing fork() is FAILED(FORK, errno)");
    CHECK(wait_reply(ctl, 602, 5000) >= 0 && REPLY[find_reply(602)].type == PS_MSG_READY,
          "and the next spawn succeeds again");
    stop_spawner(ctl, sp);

    /* socketpair() failure is reported as RESOURCE, like a full table. */
    ps_spawner_test_fail_socketpair = 2;
    start_stubbed(&cfg, &ctl, &sp);
    ps_spawner_test_fail_socketpair = 0;
    send_spawn(ctl, 650);
    send_spawn(ctl, 651);
    send_spawn(ctl, 652);
    CHECK(wait_reply(ctl, 650, 5000) >= 0 && REPLY[find_reply(650)].type == PS_MSG_READY,
          "the first spawn succeeds");
    i = wait_reply(ctl, 651, 5000);
    CHECK(i >= 0 && REPLY[i].type == PS_MSG_FAILED && REPLY[i].reason == PS_FAIL_RESOURCE &&
              REPLY[i].detail == EMFILE,
          "a failing socketpair() is FAILED(RESOURCE, errno)");
    CHECK(wait_reply(ctl, 652, 5000) >= 0 && REPLY[find_reply(652)].type == PS_MSG_READY,
          "and the next spawn succeeds again");
    CHECK(children_settle(sp, 2, 3000), "no stray child from the failed spawn");
    stop_spawner(ctl, sp);
}

/* The caller's SIGCHLD disposition is inherited by the spawner. Ignored (or
 * SA_NOCLDWAIT) it would make the kernel reap workers itself, and EXITED would
 * never arrive. */
static void test_inherited_sigchld(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    static const char *name[] = {"SIG_IGN", "SA_NOCLDWAIT"};

    printf("\nspawner: an inherited SIGCHLD disposition does not stop reaping\n");
    for (int variant = 0; variant < 2; variant++) {
        struct sigaction sa, restore;
        int ctl, r;
        pid_t sp;
        char label[96];

        memset(&sa, 0, sizeof(sa));
        sigemptyset(&sa.sa_mask);
        if (variant == 0) {
            sa.sa_handler = SIG_IGN;
        } else {
            sa.sa_handler = SIG_DFL;
            sa.sa_flags = SA_NOCLDWAIT;
        }
        NSCRIPT = 0;
        sigaction(SIGCHLD, &sa, &restore); /* inherited across the fork */
        start_stubbed(&cfg, &ctl, &sp);
        sigaction(SIGCHLD, &restore, NULL);

        send_spawn(ctl, 1000 + (uint64_t)variant);
        r = wait_reply(ctl, 1000 + (uint64_t)variant, 5000);
        if (r >= 0 && REPLY[r].type == PS_MSG_READY) {
            uint64_t wid = REPLY[r].worker_id;
            int i;

            send_kill(ctl, wid);
            i = wait_exit(ctl, wid, 3000);
            snprintf(label, sizeof(label),
                     "with %s inherited, KILL still produces EXITED with the SIGKILL status",
                     name[variant]);
            CHECK(i >= 0 && WIFSIGNALED(EXITS[i].detail) && WTERMSIG(EXITS[i].detail) == SIGKILL,
                  label);
        } else {
            CHECK(false, "a worker to kill");
        }
        stop_spawner(ctl, sp);
    }
}

static void test_concurrent(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    struct step s[] = {{M_SLOW, 400}, {M_OK, 0}, {M_SLOWFAIL, 200}, {M_SLOW, 100},
                       {M_FAIL, PS_H_RLIMITS}};
    int ctl, idx[5];
    pid_t sp;
    bool ok = true;
    uint64_t seen_w[5] = {0};

    printf("\nspawner: concurrent spawns are correlated by request id\n");
    script(5, s);
    start_stubbed(&cfg, &ctl, &sp);
    for (uint64_t r = 21; r <= 25; r++) send_spawn(ctl, r);
    for (int k = 0; k < 5; k++) idx[k] = wait_reply(ctl, 21 + (uint64_t)k, 8000);

    CHECK(idx[0] >= 0 && idx[1] >= 0 && idx[2] >= 0 && idx[3] >= 0 && idx[4] >= 0,
          "five outstanding SPAWNs each get exactly one reply");
    if (idx[0] < 0 || idx[1] < 0 || idx[2] < 0 || idx[3] < 0 || idx[4] < 0) {
        stop_spawner(ctl, sp);
        return;
    }
    CHECK(REPLY[idx[0]].type == PS_MSG_READY && REPLY[idx[1]].type == PS_MSG_READY &&
              REPLY[idx[3]].type == PS_MSG_READY,
          "the slow and fast successes are READY");
    CHECK(REPLY[idx[2]].type == PS_MSG_FAILED && REPLY[idx[2]].reason == PS_FAIL_HARDEN &&
              REPLY[idx[2]].detail == PS_H_CAPABILITIES &&
              REPLY[idx[4]].type == PS_MSG_FAILED && REPLY[idx[4]].detail == PS_H_RLIMITS,
          "the failures carry their own step, matched to their own request");
    CHECK(idx[1] < idx[0] && idx[3] < idx[0] && idx[4] < idx[0],
          "replies arrive in completion order, not request order (no head-of-line blocking)");
    for (int k = 0; k < 5; k++)
        if (REPLY[idx[k]].type == PS_MSG_READY) seen_w[k] = REPLY[idx[k]].worker_id;
    for (int a = 0; a < 5; a++)
        for (int b = a + 1; b < 5; b++)
            if (seen_w[a] && seen_w[a] == seen_w[b]) ok = false;
    CHECK(ok, "worker ids are distinct");
    stop_spawner(ctl, sp);
}

static void test_churn(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    int ctl, base_fds;
    pid_t sp;
    uint64_t last = 0;
    bool mono = true, rt = true, exits = true;
    int z;

    printf("\nspawner: churn leaves no zombies and no descriptors behind\n");
    NSCRIPT = 0;
    start_stubbed(&cfg, &ctl, &sp);
    /* Baseline only once the spawner is in its loop (it has answered one
     * request); right after fork it is still closing inherited descriptors. */
    send_spawn(ctl, 699);
    if (wait_reply(ctl, 699, 5000) >= 0) close(take_fd(find_reply(699)));
    base_fds = fds_of(sp);
    for (int i = 0; i < 25; i++) {
        uint64_t rid = 700 + (uint64_t)i;
        int r, w;
        struct ps_verdict v;

        send_spawn(ctl, rid);
        r = wait_reply(ctl, rid, 5000);
        if (r < 0 || REPLY[r].type != PS_MSG_READY) { mono = false; break; }
        if (REPLY[r].worker_id <= last) mono = false;
        last = REPLY[r].worker_id;
        w = take_fd(r);
        if (!roundtrip(w, rid, (i & 1) ? "EVIL" : "fine", &v) ||
            v.verdict != ((i & 1) ? PS_VERDICT_MALICIOUS : PS_VERDICT_CLEAN))
            rt = false;
        send_kill(ctl, last);
        if (wait_exit(ctl, last, 5000) < 0) exits = false;
        close(w);
        if (!exits || !rt) break; /* fail fast: every further cycle would time out too */
    }
    CHECK(mono, "25 spawn/kill cycles, worker ids strictly increasing, never reused");
    CHECK(rt, "every worker served a scan correctly");
    CHECK(exits, "every KILL was answered with EXITED");
    CHECK(children_settle(sp, 0, 3000) && (child_stats(sp, &z), z == 0),
          "no children and no zombies afterwards");
    if (fds_of(sp) != base_fds) { printf("    spawner fds: start %d, now %d\n", base_fds, fds_of(sp)); dump_fds(sp); }
    CHECK(fds_of(sp) == base_fds, "the spawner's descriptor count is back where it started");
    stop_spawner(ctl, sp);
}

static void test_hostile_main(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    int ctl, before, after, tmp, z;
    pid_t sp;
    struct ps_ctl_msg m;

    printf("\nspawner: malformed input from main is dropped\n");
    NSCRIPT = 0;
    start_stubbed(&cfg, &ctl, &sp);
    send_spawn(ctl, 800);
    (void)wait_reply(ctl, 800, 5000);
    before = fds_of(sp);

    (void)!send(ctl, "garbage", 7, MSG_NOSIGNAL);
    (void)!send(ctl, "", 0, MSG_NOSIGNAL); /* must not look like EOF */
    tmp = make_file("x");
    m = canon(PS_MSG_SPAWN);
    ps_ctl_send(ctl, &m, tmp);                  /* SPAWN carrying a descriptor */
    m = canon(PS_MSG_EXITED);
    ps_ctl_send(ctl, &m, -1);                   /* a spawner->main type */
    m = canon(PS_MSG_KILL);
    m.worker_id = 0;
    ps_ctl_send(ctl, &m, -1);                   /* KILL of id 0 */
    m = canon(PS_MSG_SPAWN);
    m.detail = 1;
    ps_ctl_send(ctl, &m, -1);                   /* SPAWN with a stray field */
    close(tmp);

    send_spawn(ctl, 801);
    CHECK(wait_reply(ctl, 801, 5000) >= 0 && REPLY[find_reply(801)].type == PS_MSG_READY,
          "a good SPAWN after a run of bad messages is still served");
    /* (801's socket stays open in the queue, so that worker stays alive) */
    after = fds_of(sp);
    if (after != before) { printf("    spawner fds: before %d, after %d\n", before, after); dump_fds(sp); }
    CHECK(after == before, "no descriptor attached to a rejected message is kept");
    {
        int n = child_stats(sp, &z);
        printf("    children: %d (zombies %d)\n", n, z);
        CHECK(n == 2, "none of the rejected messages spawned a worker");
    }
    stop_spawner(ctl, sp);
}

static void test_shutdown(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    int ctl, st;
    pid_t sp, wp[3];
    bool all = true;

    printf("\nspawner: shutdown and parent death\n");
    NSCRIPT = 0;
    start_stubbed(&cfg, &ctl, &sp);
    for (uint64_t r = 900; r < 903; r++) send_spawn(ctl, r);
    for (int k = 0; k < 3; k++) {
        int i = wait_reply(ctl, 900 + (uint64_t)k, 5000);
        if (i < 0 || REPLY[i].type != PS_MSG_READY) { all = false; break; }
        wp[k] = REPLY[i].pid;
        /* keep the worker sockets open so the workers do not exit on EOF */
    }
    CHECK(all, "three live workers");
    close(ctl);
    waitpid(sp, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "when main closes the channel the spawner exits 0");
    all = true;
    for (int k = 0; k < 3; k++) {
        int ws = 0;
        if (waitpid(wp[k], &ws, 0) != wp[k] || !WIFSIGNALED(ws) || WTERMSIG(ws) != SIGKILL)
            all = false;
    }
    CHECK(all, "and every worker was killed with SIGKILL first");
    reset_queues();
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }

    /* Main half-closes its end (write side only): no more commands can ever
     * arrive, so this is a shutdown too, and must not leave the spawner
     * spinning on a socket that is readable forever. */
    {
        int c2, st2 = 0;
        pid_t s2, w2;
        unsigned long t0, t1;

        NSCRIPT = 0;
        start_stubbed(&cfg, &c2, &s2);
        send_spawn(c2, 950);
        if (wait_reply(c2, 950, 5000) >= 0) {
            w2 = REPLY[find_reply(950)].pid;
            shutdown(c2, SHUT_WR);
            t0 = cpu_ticks(s2);
            usleep(500 * 1000);
            t1 = cpu_ticks(s2);
            CHECK(waitpid(s2, &st2, WNOHANG) == s2 || t1 - t0 < 10,
                  "a half-closed channel does not spin the spawner");
            if (waitpid(s2, &st2, WNOHANG) != s2) waitpid(s2, &st2, 0);
            CHECK(WIFEXITED(st2) && WEXITSTATUS(st2) == 0,
                  "and shuts it down in order (exit 0)");
            {
                int ws = 0;
                CHECK(waitpid(w2, &ws, 0) == w2 && WIFSIGNALED(ws) && WTERMSIG(ws) == SIGKILL,
                      "killing its worker first");
            }
        } else {
            CHECK(false, "a worker for the half-close test");
        }
        close(c2);
        reset_queues();
        while (waitpid(-1, NULL, WNOHANG) > 0) {
        }
    }

    /* Main dies: a grandchild "main" starts the spawner and exits at once. */
    {
        int p[2];
        pid_t mid, spawner = 0;

        if (pipe(p) < 0) { CHECK(false, "pipe"); return; }
        mid = fork();
        if (mid == 0) {
            int c;
            pid_t s2;
            close(p[0]);
            if (ps_spawner_start(&cfg, &c, &s2) != 0) _exit(2);
            (void)!write(p[1], &s2, sizeof(s2));
            _exit(0);
        }
        close(p[1]);
        (void)!read(p[0], &spawner, sizeof(spawner));
        close(p[0]);
        waitpid(mid, NULL, 0);
        CHECK(spawner > 0, "a short-lived main started a spawner");
        if (spawner > 0) {
            int ws = 0;
            /* We are a subreaper, so the orphaned spawner comes to us. */
            CHECK(waitpid(spawner, &ws, 0) == spawner && WIFSIGNALED(ws) &&
                      WTERMSIG(ws) == SIGKILL,
                  "the spawner dies with SIGKILL when main dies (PR_SET_PDEATHSIG)");
        }
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(240);
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    printf("privsep spawner: wire format and behaviour (ASan+UBSan)\n");
    test_wire_validity();
    test_wire_recv();
    test_spawn_basic();
    test_failures();
    test_inherited_sigchld();
    test_concurrent();
    test_churn();
    test_hostile_main();
    test_shutdown();
    SUMMARY("privsep_spawner (behaviour)");
}

#else
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(60);
    printf("privsep spawner: wire format\n");
    test_wire_validity();
    test_wire_recv();
    SUMMARY("privsep_spawner (wire)");
}
#endif
EOF

# ---------------------------------------------------------------------------
# limits: table sizes (built with PS_SPAWNER_MAX_WORKERS=4, MAX_PENDING=3)
# ---------------------------------------------------------------------------
cat > "$BUILD_DIR/limits.c" <<'EOF'
#include "common.h"

static void test_limits(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    int ctl, i;
    pid_t sp;
    int64_t t0;

    printf("\nspawner: table limits (workers=%d, pending=%d)\n",
           PS_SPAWNER_MAX_WORKERS, PS_SPAWNER_MAX_PENDING);
    CHECK(PS_SPAWNER_MAX_WORKERS == 4 && PS_SPAWNER_MAX_PENDING == 3,
          "built with the small test limits");

    /* A: the worker table fills, then frees up. */
    NSCRIPT = 0;
    start_stubbed(&cfg, &ctl, &sp);
    /* One at a time: this binary also limits simultaneous spawns to 3, so
     * four back-to-back SPAWNs could be refused for that reason, depending on
     * how quickly the first ones become ready. */
    for (uint64_t r = 1; r <= 4; r++) {
        send_spawn(ctl, r);
        (void)wait_reply(ctl, r, 5000);
    }
    CHECK(find_reply(4) >= 0 && REPLY[find_reply(4)].type == PS_MSG_READY &&
              find_reply(1) >= 0 && REPLY[find_reply(1)].type == PS_MSG_READY &&
              find_reply(2) >= 0 && REPLY[find_reply(2)].type == PS_MSG_READY &&
              find_reply(3) >= 0 && REPLY[find_reply(3)].type == PS_MSG_READY,
          "four workers fit");
    t0 = ps_now_ms();
    send_spawn(ctl, 5);
    i = wait_reply(ctl, 5, 5000);
    CHECK(i >= 0 && REPLY[i].type == PS_MSG_FAILED && REPLY[i].reason == PS_FAIL_RESOURCE &&
              ps_now_ms() - t0 < 1500,
          "a fifth is refused at once with FAILED(RESOURCE)");
    send_kill(ctl, REPLY[find_reply(2)].worker_id);
    (void)wait_exit(ctl, REPLY[find_reply(2)].worker_id, 5000);
    send_spawn(ctl, 6);
    i = wait_reply(ctl, 6, 5000);
    CHECK(i >= 0 && REPLY[i].type == PS_MSG_READY,
          "once a worker exits, a new spawn is accepted again");
    stop_spawner(ctl, sp);

    /* B: the pending table fills. */
    {
        struct step s[] = {{M_SLEEP, 0}, {M_SLEEP, 0}, {M_SLEEP, 0}, {M_OK, 0}};
        script(4, s);
    }
    cfg.startup_timeout_ms = 1500;
    start_stubbed(&cfg, &ctl, &sp);
    for (uint64_t r = 11; r <= 13; r++) send_spawn(ctl, r);
    t0 = ps_now_ms();
    send_spawn(ctl, 14);
    i = wait_reply(ctl, 14, 1200);
    CHECK(i >= 0 && REPLY[i].type == PS_MSG_FAILED && REPLY[i].reason == PS_FAIL_RESOURCE &&
              ps_now_ms() - t0 < 1000,
          "with every pending slot taken, the next SPAWN is refused straight away");
    {
        bool all = true;
        for (uint64_t r = 11; r <= 13; r++) {
            i = wait_reply(ctl, r, 5000);
            if (i < 0 || REPLY[i].reason != PS_FAIL_TIMEOUT) all = false;
        }
        CHECK(all, "the three stuck workers each time out");
    }
    send_spawn(ctl, 15);
    CHECK(wait_reply(ctl, 15, 5000) >= 0 && REPLY[find_reply(15)].type == PS_MSG_READY,
          "and the slots are reusable afterwards");
    stop_spawner(ctl, sp);

    /* C: pending and live share one budget, so a pending worker can always
     * be promoted. */
    {
        struct step s[] = {{M_OK, 0}, {M_OK, 0}, {M_OK, 0}, {M_SLEEP, 0}};
        script(4, s);
    }
    cfg.startup_timeout_ms = 2000;
    start_stubbed(&cfg, &ctl, &sp);
    for (uint64_t r = 21; r <= 23; r++) send_spawn(ctl, r);
    for (uint64_t r = 21; r <= 23; r++) (void)wait_reply(ctl, r, 5000);
    send_spawn(ctl, 24); /* pending: 3 live + 1 pending = 4 */
    send_spawn(ctl, 25);
    i = wait_reply(ctl, 25, 1500);
    CHECK(i >= 0 && REPLY[i].type == PS_MSG_FAILED && REPLY[i].reason == PS_FAIL_RESOURCE,
          "live plus pending count against one budget (pending slots were still free)");
    stop_spawner(ctl, sp);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(120);
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    printf("privsep spawner: table limits (ASan+UBSan)\n");
    test_limits();
    SUMMARY("privsep_spawner (limits)");
}
EOF

# ---------------------------------------------------------------------------
# kern: the real kernel, real hardening (root)
# ---------------------------------------------------------------------------
cat > "$BUILD_DIR/kern.c" <<'EOF'
#include "common.h"

#define WORKER_UID 65534

/* Hardening needs these in the EFFECTIVE set: a root process whose bounding
 * set holds them but whose effective set does not would pass a bounding-set
 * check and then fail at the first credential step instead of skipping. */
static bool have_cap(int cap) {
    struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct d[2];

    if (syscall(SYS_capget, &h, d) < 0) return false;
    return (d[cap / 32].effective >> (cap % 32)) & 1u;
}

static bool can_spawn_hardened(void) {
    return geteuid() == 0 && have_cap(CAP_SETUID) && have_cap(CAP_SETGID) &&
           have_cap(CAP_SETPCAP) && have_cap(CAP_KILL);
}

static bool status_field(pid_t pid, const char *key, char *out, size_t cap) {
    char p[64], line[256];
    FILE *f;
    size_t kl = strlen(key);

    snprintf(p, sizeof(p), "/proc/%d/status", (int)pid);
    f = fopen(p, "r");
    if (!f) return false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, kl) == 0) {
            char *v = line + kl;
            size_t n;
            while (*v == ' ' || *v == '\t') v++;
            n = strlen(v);
            while (n && (v[n - 1] == '\n' || v[n - 1] == ' ')) v[--n] = 0;
            snprintf(out, cap, "%s", v);
            fclose(f);
            return true;
        }
    }
    fclose(f);
    return false;
}

static bool field_is(pid_t pid, const char *key, const char *want) {
    char got[128];
    return status_field(pid, key, got, sizeof(got)) && strcmp(got, want) == 0;
}

static void test_real_spawn(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    int ctl, r, w, z;
    pid_t sp, wp;
    struct ps_verdict v;
    char uid[64];

    printf("\nreal workers under the real kernel (root):\n");
    if (!can_spawn_hardened()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID, CAP_SETPCAP and CAP_KILL");
        return;
    }
    ps_test_fail_step = 0;
    CHECK(ps_spawner_start(&cfg, &ctl, &sp) == 0, "the spawner starts");
    send_spawn(ctl, 1);
    r = wait_reply(ctl, 1, 10000);
    CHECK(r >= 0 && REPLY[r].type == PS_MSG_READY, "a hardened worker reports ready");
    if (r < 0 || REPLY[r].type != PS_MSG_READY) { stop_spawner(ctl, sp); return; }
    wp = REPLY[r].pid;
    w = take_fd(r);

    /* The parent-side check the design asks for, done here the way avd will. */
    snprintf(uid, sizeof(uid), "%d\t%d\t%d\t%d", WORKER_UID, WORKER_UID, WORKER_UID, WORKER_UID);
    CHECK(field_is(wp, "Uid:", uid) && field_is(wp, "Gid:", uid), "uids and gids are the dedicated ones");
    CHECK(field_is(wp, "CapEff:", "0000000000000000") && field_is(wp, "CapPrm:", "0000000000000000") &&
              field_is(wp, "CapInh:", "0000000000000000") && field_is(wp, "CapBnd:", "0000000000000000") &&
              field_is(wp, "CapAmb:", "0000000000000000"),
          "every capability set is empty, including the bounding set");
    CHECK(field_is(wp, "NoNewPrivs:", "1") && field_is(wp, "Seccomp:", "2"),
          "NoNewPrivs is 1 and a seccomp filter is installed");
    CHECK(ppid_of(wp) == sp, "the worker is a child of the spawner");

    CHECK(roundtrip(w, 77, "EVIL bytes", &v) && v.verdict == PS_VERDICT_MALICIOUS &&
              strcmp(v.rule_name, "Test:evil") == 0,
          "a hardened worker serves a scan under its seccomp filter (convicts)");
    CHECK(roundtrip(w, 78, "clean", &v) && v.verdict == PS_VERDICT_CLEAN,
          "and the next scan on the same worker");

    send_kill(ctl, REPLY[r].worker_id);
    CHECK(wait_exit(ctl, REPLY[r].worker_id, 5000) >= 0 &&
              WIFSIGNALED(EXITS[find_exit(REPLY[r].worker_id)].detail) &&
              WTERMSIG(EXITS[find_exit(REPLY[r].worker_id)].detail) == SIGKILL,
          "the spawner (root) can kill a worker running as another uid");
    close(w);
    CHECK(children_settle(sp, 0, 3000) && (child_stats(sp, &z), z == 0), "no zombie left");
    stop_spawner(ctl, sp);
}

static void test_real_failures(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    bool all = true;

    printf("\nreal hardening failure at each step (root):\n");
    if (!can_spawn_hardened()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID, CAP_SETPCAP and CAP_KILL");
        return;
    }
    for (int k = 1; k < PS_H_STEP_COUNT; k++) {
        int ctl, i;
        pid_t sp;

        ps_test_fail_step = k; /* inherited by the spawner and its workers */
        reset_queues();
        if (ps_spawner_start(&cfg, &ctl, &sp) != 0) { all = false; continue; }
        ps_test_fail_step = 0;
        send_spawn(ctl, 50 + (uint64_t)k);
        i = wait_reply(ctl, 50 + (uint64_t)k, 10000);
        if (i < 0 || REPLY[i].type != PS_MSG_FAILED || REPLY[i].reason != PS_FAIL_HARDEN ||
            REPLY[i].detail != k) {
            printf("    step %d: not FAILED(HARDEN, %d)\n", k, k);
            all = false;
        }
        stop_spawner(ctl, sp);
    }
    CHECK(all, "a failure injected at each hardening step reaches main as FAILED(HARDEN, step)");
}

static void test_real_orphan(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    int ctl, r;
    pid_t sp, wp;
    int st = 0;

    printf("\nreal workers when the spawner dies (root):\n");
    if (!can_spawn_hardened()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID, CAP_SETPCAP and CAP_KILL");
        return;
    }
    ps_test_fail_step = 0;
    reset_queues();
    ps_spawner_start(&cfg, &ctl, &sp);
    send_spawn(ctl, 1);
    r = wait_reply(ctl, 1, 10000);
    if (r < 0 || REPLY[r].type != PS_MSG_READY) {
        CHECK(false, "a worker to orphan");
        stop_spawner(ctl, sp);
        return;
    }
    wp = REPLY[r].pid;
    kill(sp, SIGKILL);
    waitpid(sp, NULL, 0);
    /* As a subreaper the worker now comes to us. It set PR_SET_PDEATHSIG only
     * after its credential change (the kernel clears it on a uid change), so
     * this is the end-to-end check of that ordering. */
    CHECK(waitpid(wp, &st, 0) == wp && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL,
          "SIGKILL on the spawner takes its hardened worker down with SIGKILL");
    close(ctl);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

static void test_real_churn(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    int ctl, base, z;
    pid_t sp;
    bool ok = true;

    printf("\nreal workers: churn (root):\n");
    if (!can_spawn_hardened()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID, CAP_SETPCAP and CAP_KILL");
        return;
    }
    ps_test_fail_step = 0;
    reset_queues();
    ps_spawner_start(&cfg, &ctl, &sp);
    send_spawn(ctl, 299); /* baseline once the spawner is in its loop */
    if (wait_reply(ctl, 299, 10000) >= 0) close(take_fd(find_reply(299)));
    base = fds_of(sp);
    for (int i = 0; i < 40; i++) {
        uint64_t rid = 300 + (uint64_t)i;
        int r, w;
        struct ps_verdict v;

        send_spawn(ctl, rid);
        r = wait_reply(ctl, rid, 10000);
        if (r < 0 || REPLY[r].type != PS_MSG_READY) { ok = false; break; }
        w = take_fd(r);
        if (!roundtrip(w, rid, "EVIL", &v) || v.verdict != PS_VERDICT_MALICIOUS) ok = false;
        send_kill(ctl, REPLY[r].worker_id);
        if (wait_exit(ctl, REPLY[r].worker_id, 5000) < 0) ok = false;
        close(w);
        if (!ok) break; /* fail fast */
    }
    CHECK(ok, "40 spawn/scan/kill cycles with real hardening");
    CHECK(children_settle(sp, 0, 3000) && (child_stats(sp, &z), z == 0), "no children or zombies");
    if (fds_of(sp) != base) { printf("    spawner fds: start %d, now %d\n", base, fds_of(sp)); dump_fds(sp); }
    CHECK(fds_of(sp) == base, "the spawner's descriptor count is unchanged");
    stop_spawner(ctl, sp);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(180);
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    printf("privsep spawner: real hardening against the real kernel\n");
    test_real_spawn();
    test_real_failures();
    test_real_orphan();
    test_real_churn();
    SUMMARY("privsep_spawner (kernel)");
}
EOF

CC="${CC:-gcc}"
rc=0

# The test hooks must not exist in a production build.
echo "### checking the production header carries no test hooks ###"
if "$CC" -std=gnu11 -E -I"$SRC_DIR" -x c - <<< '#include "privsep_spawner.h"' 2>/dev/null |
    grep -q 'ps_spawner_test_'; then
    echo "  FAIL: ps_spawner_test_* is present without PS_SPAWNER_TEST_HOOKS"
    rc=1
else
    echo "  PASS: no ps_spawner_test_* symbols without PS_SPAWNER_TEST_HOOKS"
fi

SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined"

echo "### building (ASan+UBSan: wire format and spawner behaviour) ###"
# shellcheck disable=SC2086
"$CC" -std=gnu11 -Wall -Wextra -Werror -O1 -g -fno-omit-frame-pointer $SAN \
    -DPS_SPAWNER_TEST_HOOKS -I"$SRC_DIR" -I"$BUILD_DIR" \
    -o "$BUILD_DIR/beh" "$BUILD_DIR/beh.c" || exit 1

echo "### building (ASan+UBSan: table limits) ###"
# shellcheck disable=SC2086
"$CC" -std=gnu11 -Wall -Wextra -Werror -O1 -g -fno-omit-frame-pointer $SAN \
    -DPS_SPAWNER_TEST_HOOKS -DPS_SPAWNER_MAX_WORKERS=4 -DPS_SPAWNER_MAX_PENDING=3 \
    -I"$SRC_DIR" -I"$BUILD_DIR" -o "$BUILD_DIR/limits" "$BUILD_DIR/limits.c" || exit 1

echo "### building (plain -O2: real hardening in the kernel) ###"
"$CC" -std=gnu11 -Wall -Wextra -Werror -O2 -fstack-protector-strong \
    -DPS_WORKER_TEST_HOOKS -I"$SRC_DIR" -I"$BUILD_DIR" \
    -o "$BUILD_DIR/kern" "$BUILD_DIR/kern.c" || exit 1

echo
"$BUILD_DIR/beh" || rc=1
echo
"$BUILD_DIR/limits" || rc=1
echo
"$BUILD_DIR/kern" || rc=1

exit $rc
