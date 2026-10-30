#!/usr/bin/env bash
#
# tests/test_privsep_client.sh - coverage for userspace/avd/privsep_client.h,
# the main-process side of avd's privilege separation (#103, Stage 1d; see
# docs/privilege-separation.md, "Correlating replies", "IPC", "The parent
# treats every reply as untrusted" and "Failure handling").
#
# Binaries, all against the production header compiled standalone (same
# arrangement as test_privsep_spawner.sh):
#
#   beh    ASan+UBSan. The status/verdict helpers; the client against a real
#          spawner whose workers' hardening is a test-only stub (compiled in
#          only with PS_SPAWNER_TEST_HOOKS), so no root: spawn, scan round
#          trips, every hostile-worker behaviour, concurrent scan threads,
#          late replies, a hung and a dead spawner, orderly stop; and the
#          reader thread against a fake spawner that sends junk.
#   tsan   The same sources under ThreadSanitizer (skipped if unavailable).
#   kern   Plain build, real kernel, real hardening; needs root. The /proc
#          check against a ladder of partly hardened processes, a worker
#          killed by seccomp, and a real worker passing the check. Without
#          root these print SKIP, never PASS:
#            sudo tests/test_privsep_client.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${PS_SRC_DIR:-$REPO_ROOT/userspace/avd}"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_privsep_client.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
# False positive: cleanup() IS invoked via `trap` on the next line.
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

cat > "$BUILD_DIR/common.h" <<'EOF'
#ifndef T_COMMON_H
#define T_COMMON_H
#pragma GCC diagnostic ignored "-Wunused-function"
#include <dirent.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#include "privsep_client.h"

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

static int count_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    struct dirent *e;
    int n = 0, dfd;

    if (!d) return -1;
    dfd = dirfd(d);
    while ((e = readdir(d)))
        if (e->d_name[0] != '.' && atoi(e->d_name) != dfd) n++;
    closedir(d);
    return n;
}

/* Parse /proc/<pid>/stat: parent pid and state; -1 if the process is gone. */
static int stat_of(pid_t pid, char *state) {
    char p[64], buf[512], *rp;
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
    if (!rp || sscanf(rp + 1, " %c %d", state, &pp) != 2) return -1;
    return pp;
}

/* Children of `parent` and how many are zombies. */
static int child_stats(pid_t parent, int *zombies) {
    DIR *d = opendir("/proc");
    struct dirent *e;
    int n = 0;

    *zombies = 0;
    if (!d) return -1;
    while ((e = readdir(d))) {
        char st;
        pid_t pid;

        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        pid = (pid_t)atoi(e->d_name);
        if (stat_of(pid, &st) == parent) {
            n++;
            if (st == 'Z') (*zombies)++;
        }
    }
    closedir(d);
    return n;
}

static bool children_settle(pid_t parent, int want, int ms) {
    int64_t end = ps_now_ms() + ms;
    for (;;) {
        int z, n = child_stats(parent, &z);
        if (n == want && z == 0) return true;
        if (ps_now_ms() >= end) return false;
        usleep(20 * 1000);
    }
}

static bool reap_within(pid_t pid, int *st, int ms) {
    int64_t end = ps_now_ms() + ms;
    for (;;) {
        if (waitpid(pid, st, WNOHANG) == pid) return true;
        if (ps_now_ms() >= end) return false;
        usleep(20 * 1000);
    }
}

static int make_file(const char *content) {
    char path[] = "/tmp/av_privsep_client_XXXXXX";
    int fd = mkstemp(path);

    if (fd < 0) return -1;
    unlink(path);
    if (write(fd, content, strlen(content)) < 0) { close(fd); return -1; }
    return fd;
}

/* ---- log and on_dead hooks ---- */
#define MAXLOG 512
static char LOGS[MAXLOG][512];
static int NLOGS;
static pthread_mutex_t LOGLOCK = PTHREAD_MUTEX_INITIALIZER;
static atomic_int DEAD_CALLS;

static void log_hook(void *ctx, const char *msg) {
    (void)ctx;
    pthread_mutex_lock(&LOGLOCK);
    if (NLOGS < MAXLOG) snprintf(LOGS[NLOGS++], sizeof(LOGS[0]), "%s", msg);
    pthread_mutex_unlock(&LOGLOCK);
}
static void dead_hook(void *ctx) { (void)ctx; atomic_fetch_add(&DEAD_CALLS, 1); }
static void log_clear(void) {
    pthread_mutex_lock(&LOGLOCK);
    NLOGS = 0;
    pthread_mutex_unlock(&LOGLOCK);
    atomic_store(&DEAD_CALLS, 0);
}
static int log_count(const char *needle) {
    int n = 0;
    pthread_mutex_lock(&LOGLOCK);
    for (int i = 0; i < NLOGS; i++) if (strstr(LOGS[i], needle)) n++;
    pthread_mutex_unlock(&LOGLOCK);
    return n;
}
static bool log_wait(const char *needle, int ms) {
    int64_t end = ps_now_ms() + ms;
    for (;;) {
        if (log_count(needle) > 0) return true;
        if (ps_now_ms() >= end) return false;
        usleep(10 * 1000);
    }
}
static void log_dump(void) {
    pthread_mutex_lock(&LOGLOCK);
    for (int i = 0; i < NLOGS; i++) printf("    log: %s\n", LOGS[i]);
    pthread_mutex_unlock(&LOGLOCK);
}

static bool is_canonical_failure(const struct ps_verdict *v) {
    struct ps_verdict f;
    ps_verdict_failure(&f);
    return memcmp(v, &f, sizeof(f)) == 0;
}

/* ---- the worker's scan: behaviour chosen by the file's first line ---- */
static int g_ipc = -1;

static void send_raw(const void *b, size_t n) { (void)!send(g_ipc, b, n, MSG_NOSIGNAL); }

static void scan_cb(int fd, void *ctx, struct ps_reply *rep) {
    char b[64];
    ssize_t n = pread(fd, b, sizeof(b) - 1, 0);

    (void)ctx;
    if (n < 0) return;
    b[n] = 0;

    if (!strncmp(b, "MODE:HANG", 9)) for (;;) pause();
    if (!strncmp(b, "MODE:CRASH", 10)) kill(getpid(), SIGKILL);
    if (!strncmp(b, "MODE:EXIT", 9)) _exit(7);
    if (!strncmp(b, "MODE:TRUNC", 10)) send_raw("short", 5);
    if (!strncmp(b, "MODE:EMPTY", 10)) send_raw("", 0);
    if (!strncmp(b, "MODE:BIG", 8)) { static char big[4096]; send_raw(big, sizeof(big)); }
    if (!strncmp(b, "MODE:BADVERDICT", 15)) {
        struct ps_reply r = *rep;
        r.verdict = 7;
        r.inconclusive = 0;
        send_raw(&r, sizeof(r));
    }
    if (!strncmp(b, "MODE:WRONGID", 12)) {
        struct ps_reply r = *rep;
        r.request_id += 1;
        r.inconclusive = 0;
        send_raw(&r, sizeof(r));
    }
    if (!strncmp(b, "MODE:BADMAGIC", 13)) {
        struct ps_reply r = *rep;
        r.magic ^= 1;
        r.inconclusive = 0;
        send_raw(&r, sizeof(r));
    }
    if (!strncmp(b, "MODE:RESERVED", 13)) {
        struct ps_reply r = *rep;
        r.reserved = 1;
        r.inconclusive = 0;
        send_raw(&r, sizeof(r));
    }
    if (!strncmp(b, "MODE:EXTRAFD", 12)) {
        struct ps_reply r = *rep;
        int x = open("/dev/null", O_RDONLY);
        r.inconclusive = 0;
        (void)ps_sendmsg_fd(g_ipc, &r, sizeof(r), x, 0);
        close(x);
    }
    if (!strncmp(b, "MODE:DOUBLE", 11)) {
        struct ps_reply r = *rep;
        r.inconclusive = 0;
        send_raw(&r, sizeof(r)); /* a valid reply, then the loop sends another */
    }
    if (!strncmp(b, "MODE:OPEN", 9)) {
        int x = open("/etc/passwd", O_RDONLY); /* not allowed under seccomp */
        if (x >= 0) close(x);
    }

    rep->inconclusive = 0;
    if (strstr(b, "EVIL")) {
        rep->verdict = PS_VERDICT_MALICIOUS;
        rep->score = 150;
        snprintf(rep->rule_name, sizeof(rep->rule_name), "Test:evil");
    }
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

#ifdef PS_SPAWNER_TEST_HOOKS
enum { M_OK, M_FAIL, M_SLOW };
struct step { int mode; int arg; };
static struct step SCRIPT[64];
static int NSCRIPT;

static int stub_harden(const struct ps_harden_cfg *h) {
    int k = (int)ps_spawner_test_forks - 1;
    struct step st = (k >= 0 && k < NSCRIPT) ? SCRIPT[k] : (struct step){M_OK, 0};

    ps_close_all_but(h->ipc_fd, -1);
    g_ipc = h->ipc_fd;
    if (st.mode == M_FAIL) return st.arg;
    if (st.mode == M_SLOW) usleep((useconds_t)st.arg * 1000);
    return 0;
}
static void script(int n, const struct step *s) {
    memcpy(SCRIPT, s, sizeof(*s) * (size_t)n);
    NSCRIPT = n;
}

/* A real spawner with stubbed worker hardening, and a client on it. */
static struct ps_client CL;
static pid_t SP;

static bool start_client(bool verify_proc) {
    struct ps_spawner_cfg cfg = base_cfg();
    int ctl;

    ps_spawner_test_harden = stub_harden;
    log_clear();
    if (ps_spawner_start(&cfg, &ctl, &SP) != 0) return false;
    ps_client_attach(&CL, ctl, SP, cfg.harden.uid, cfg.harden.gid, verify_proc);
    CL.log = log_hook;
    CL.on_dead = dead_hook;
    return ps_client_start(&CL) == 0;
}
#endif
#endif
EOF

# ---------------------------------------------------------------------------
# beh: helpers, client against a real spawner, fake spawner (no root)
# ---------------------------------------------------------------------------
cat > "$BUILD_DIR/beh.c" <<'EOF'
#include "common.h"

static bool scan_str(struct ps_worker *w, const char *content, struct ps_verdict *v,
                     const char **why, int timeout_ms) {
    int fd = make_file(content);
    bool ok;

    if (fd < 0) return false;
    ok = ps_client_scan(&CL, w, fd, timeout_ms, v, why);
    close(fd);
    return ok;
}

static void test_status_helpers(void) {
    char st[300];
    int status;

    printf("\n/proc status parsing and wait-status descriptions\n");
    {
        const char *s = "Name:\tx\nUid:\t1\t2\t3\t4\nSeccomp:\t2\nSeccomp_filters:\t1\nCapEff:\t00000000000000ff\n"
                        "Tricky:\tUid:\t9\n";
        CHECK(ps_status_value(s, "Seccomp") && *ps_status_value(s, "Seccomp") == '2',
              "Seccomp: is not confused with Seccomp_filters:");
        CHECK(ps_status_value(s, "Seccomp_filters") && *ps_status_value(s, "Seccomp_filters") == '1',
              "and Seccomp_filters: is found on its own");
        CHECK(ps_status_value(s, "Uid") && *ps_status_value(s, "Uid") == '1',
              "a key is only found at the start of a line, never inside a value");
        CHECK(ps_status_value(s, "Missing") == NULL, "a missing key is NULL");
        CHECK(ps_status_value(s, "Ui") == NULL, "a prefix of a key does not match");
        CHECK(!ps_status_cap_zero(s, "CapEff"), "a non-zero capability set is not zero");
        CHECK(!ps_status_cap_zero(s, "CapBnd"), "a missing capability set is not zero (fails closed)");
        CHECK(ps_status_cap_zero("CapBnd:\t0000000000000000\n", "CapBnd"), "an all-zero set is zero");
        CHECK(!ps_status_cap_zero("CapBnd:\tzz\n", "CapBnd"), "a non-hex value is not zero");
    }
    status = 0;
    ps_describe_status(status, st, sizeof(st));
    CHECK(strstr(st, "exited with status 0"), "a clean exit is described");
    status = SIGSYS;
    ps_describe_status(status, st, sizeof(st));
    CHECK(strstr(st, "SIGSYS") && strstr(st, "seccomp") && strstr(st, "failed open"),
          "SIGSYS is called out as a seccomp violation that failed scans open");
    status = SIGKILL;
    ps_describe_status(status, st, sizeof(st));
    CHECK(strstr(st, "signal 9"), "another signal is described by number");
    {
        char small[16];
        ps_describe_status(SIGSYS, small, sizeof(small));
        CHECK(strlen(small) < sizeof(small), "the description is bounded by the buffer");
    }
    {
        char why[160];
        CHECK(!ps_verify_worker(getpid(), 65534, 65534, getppid(), why, sizeof(why)) &&
                  strstr(why, "Uid"),
              "an ordinary process is rejected (and the reason names the field)");
        CHECK(!ps_verify_worker(999999999, 65534, 65534, 1, why, sizeof(why)) &&
                  strstr(why, "cannot open"),
              "a pid that does not exist is rejected, not trusted");
    }
}

#ifdef PS_SPAWNER_TEST_HOOKS

static void test_basic(void) {
    struct ps_worker w;
    struct ps_spawn_info info;
    struct ps_verdict v;
    const char *why = "";
    int fds0, st;

    printf("\nclient: spawn, scan, release\n");
    NSCRIPT = 0;
    CHECK(start_client(false), "the client attaches to a real spawner");
    fds0 = count_fds();

    CHECK(ps_client_spawn(&CL, &w, 5000, &info) == PS_SPAWN_OK && w.sock >= 0 &&
              w.worker_id == 1 && w.pid > 0,
          "a worker is spawned");
    CHECK(scan_str(&w, "this is EVIL", &v, &why, 5000) && v.verdict == PS_VERDICT_MALICIOUS &&
              !v.inconclusive && strcmp(v.rule_name, "Test:evil") == 0 && v.score == 150,
          "a scan convicts, with the validated fields");
    CHECK(scan_str(&w, "benign", &v, &why, 5000) && v.verdict == PS_VERDICT_CLEAN && !v.inconclusive,
          "and a clean file is clean, on the same worker");

    /* Many more scans than the worker's RLIMIT_NOFILE, with no growth in
     * either process. */
    {
        bool all = true;
        for (int i = 0; i < 120; i++)
            if (!scan_str(&w, (i & 1) ? "EVIL" : "ok", &v, &why, 5000) ||
                v.verdict != ((i & 1) ? PS_VERDICT_MALICIOUS : PS_VERDICT_CLEAN))
                all = false;
        CHECK(all, "120 further scans on one worker, each correct");
    }
    CHECK(count_fds() == fds0 + 1, "main holds exactly the worker's socket and nothing else");

    ps_client_release(&CL, &w);
    CHECK(w.sock < 0, "release clears the handle");
    CHECK(log_wait("exited with status 0", 3000), "the exit is reported with its cause (EXITED)");
    CHECK(count_fds() == fds0, "and main's descriptors are back where they started");

    ps_client_stop(&CL);
    CHECK(atomic_load(&DEAD_CALLS) == 0, "an orderly stop does not look like spawner death");
    (void)st;
}

static void test_spawn_failures(void) {
    struct ps_worker w;
    struct ps_spawn_info info;
    int fds0;
    enum ps_spawn_status s;

    printf("\nclient: FAILED, and the /proc check\n");
    {
        struct step sc[] = {{M_FAIL, PS_H_CAPABILITIES}, {M_OK, 0}};
        script(2, sc);
    }
    start_client(false);
    fds0 = count_fds();
    s = ps_client_spawn(&CL, &w, 5000, &info);
    CHECK(s == PS_SPAWN_FAILED && info.reason == PS_FAIL_HARDEN && info.detail == PS_H_CAPABILITIES &&
              w.sock < 0,
          "a hardening failure is FAILED(HARDEN, step) with no socket");
    CHECK(count_fds() == fds0, "and leaks no descriptor");
    CHECK(ps_client_spawn(&CL, &w, 5000, &info) == PS_SPAWN_OK, "the next spawn succeeds");
    ps_client_release(&CL, &w);
    ps_client_stop(&CL);

    /* verify_proc on, worker not actually hardened: the check must reject it
     * even though the spawner said READY. */
    NSCRIPT = 0;
    start_client(true);
    fds0 = count_fds();
    s = ps_client_spawn(&CL, &w, 5000, &info);
    CHECK(s == PS_SPAWN_BAD_WORKER && w.sock < 0 && strstr(info.why, "Uid"),
          "a worker the spawner calls READY but /proc shows unhardened is rejected, and why");
    CHECK(count_fds() == fds0, "its socket was closed");
    CHECK(log_wait("exited with status", 100) || log_wait("killed by signal 9", 3000),
          "and it was killed through the spawner (EXITED with SIGKILL)");
    CHECK(children_settle(SP, 0, 3000), "and reaped");
    ps_client_stop(&CL);
}

static void test_hostile_workers(void) {
    static const struct { const char *mode; const char *what; int timeout; } M[] = {
        {"MODE:HANG", "a worker that never replies", 400},
        {"MODE:CRASH", "a worker killed mid-scan", 3000},
        {"MODE:EXIT", "a worker that exits mid-scan", 3000},
        {"MODE:TRUNC", "a truncated reply", 3000},
        {"MODE:EMPTY", "a zero-length record", 3000},
        {"MODE:BIG", "an oversized reply", 3000},
        {"MODE:BADVERDICT", "a verdict outside CLEAN/MALICIOUS", 3000},
        {"MODE:WRONGID", "a reply to the wrong request", 3000},
        {"MODE:BADMAGIC", "a reply with the wrong magic", 3000},
        {"MODE:RESERVED", "a reply with a non-zero reserved word", 3000},
        {"MODE:EXTRAFD", "a valid reply with a descriptor attached", 3000},
    };
    struct ps_worker w;
    struct ps_spawn_info info;
    struct ps_verdict v;
    const char *why;
    int fds0;

    printf("\nclient: every hostile worker behaviour\n");
    NSCRIPT = 0;
    start_client(false);
    fds0 = count_fds();

    for (size_t i = 0; i < sizeof(M) / sizeof(M[0]); i++) {
        char label[200];
        int64_t t0;
        bool ok;
        int64_t dt;

        why = "";
        if (ps_client_spawn(&CL, &w, 5000, &info) != PS_SPAWN_OK) {
            CHECK(false, M[i].what);
            continue;
        }
        t0 = ps_now_ms();
        ok = scan_str(&w, M[i].mode, &v, &why, M[i].timeout);
        dt = ps_now_ms() - t0;
        snprintf(label, sizeof(label), "%s: the scan fails with the canonical result and the worker is discarded", M[i].what);
        CHECK(!ok && is_canonical_failure(&v) && w.sock < 0 && why[0], label);
        if (!strcmp(M[i].mode, "MODE:HANG"))
            CHECK(dt >= M[i].timeout - 50 && dt < M[i].timeout + 1500,
                  "a hung worker is given up on at the timeout, not before and not long after");
        snprintf(label, sizeof(label), "%s: nothing leaks and the worker is gone", M[i].what);
        CHECK(children_settle(SP, 0, 4000) && count_fds() == fds0, label);

        /* The replacement works: a late reply from the old worker cannot be
         * matched to this scan because it is a different socket. */
        if (ps_client_spawn(&CL, &w, 5000, &info) != PS_SPAWN_OK ||
            !scan_str(&w, "EVIL after", &v, &why, 5000) || v.verdict != PS_VERDICT_MALICIOUS) {
            snprintf(label, sizeof(label), "%s: the replacement worker scans correctly", M[i].what);
            CHECK(false, label);
        }
        ps_client_release(&CL, &w);
        children_settle(SP, 0, 3000);
    }
    CHECK(true, "(every behaviour above recovered onto a fresh worker)");

    /* A stale duplicate reply is never matched to a later scan. */
    ps_client_spawn(&CL, &w, 5000, &info);
    CHECK(scan_str(&w, "MODE:DOUBLE", &v, &why, 3000) && !v.inconclusive,
          "a worker that sends its reply twice: the first is accepted");
    CHECK(!scan_str(&w, "EVIL", &v, &why, 3000) && is_canonical_failure(&v) && w.sock < 0,
          "the stale second reply is rejected on the NEXT scan (id mismatch), never applied to it");
    children_settle(SP, 0, 3000);

    ps_client_stop(&CL);
}

static void test_late_ready_and_hang(void) {
    struct ps_worker w;
    struct ps_spawn_info info;
    int fds0, z;

    printf("\nclient: a spawn that times out, and a spawner that hangs or dies\n");

    /* Late READY for an abandoned request: the reader must clean it up. */
    {
        struct step sc[] = {{M_SLOW, 900}};
        script(1, sc);
    }
    start_client(false);
    fds0 = count_fds();
    CHECK(ps_client_spawn(&CL, &w, 200, &info) == PS_SPAWN_TIMEOUT && w.sock < 0,
          "a spawn slower than its bound is PS_SPAWN_TIMEOUT");
    CHECK(log_wait("late READY for abandoned request", 4000),
          "the late READY is recognised as belonging to an abandoned request");
    CHECK(children_settle(SP, 0, 4000), "the orphaned worker was killed and reaped");
    CHECK(count_fds() == fds0, "its socket was closed (nothing leaked)");
    NSCRIPT = 0;
    CHECK(ps_client_spawn(&CL, &w, 5000, &info) == PS_SPAWN_OK, "and the next spawn succeeds");
    ps_client_release(&CL, &w);
    ps_client_stop(&CL);
    CHECK(atomic_load(&DEAD_CALLS) == 0, "none of that counted as the spawner dying");

    /* Hung spawner: replies stop. */
    NSCRIPT = 0;
    start_client(false);
    kill(SP, SIGSTOP);
    {
        enum ps_spawn_status a, b, c;
        int64_t t0;

        a = ps_client_spawn(&CL, &w, 150, &info);
        b = ps_client_spawn(&CL, &w, 150, &info);
        CHECK(a == PS_SPAWN_TIMEOUT && b == PS_SPAWN_TIMEOUT && atomic_load(&DEAD_CALLS) == 0,
              "the first misses are timeouts and the spawner is not yet declared dead");
        c = ps_client_spawn(&CL, &w, 150, &info);
        CHECK(c == PS_SPAWN_DEAD && atomic_load(&DEAD_CALLS) == 1,
              "after PS_CLIENT_HANG_LIMIT consecutive misses it is treated as dead, once");
        t0 = ps_now_ms();
        CHECK(ps_client_spawn(&CL, &w, 5000, &info) == PS_SPAWN_DEAD && ps_now_ms() - t0 < 200,
              "later spawns fail at once instead of waiting");
        CHECK(atomic_load(&DEAD_CALLS) == 1, "and the death hook is not called again");
    }
    kill(SP, SIGCONT);
    ps_client_stop(&CL);

    /* Dead spawner. */
    NSCRIPT = 0;
    start_client(false);
    CHECK(ps_client_spawn(&CL, &w, 5000, &info) == PS_SPAWN_OK, "a worker before the spawner dies");
    {
        struct ps_verdict v;
        const char *why;

        kill(SP, SIGKILL);
        waitpid(SP, NULL, 0);
        CHECK(log_wait("spawner lost", 3000), "the reader notices the channel closing");
        {
            int64_t end = ps_now_ms() + 3000;
            while (atomic_load(&DEAD_CALLS) == 0 && ps_now_ms() < end) usleep(10000);
        }
        CHECK(atomic_load(&DEAD_CALLS) == 1, "and calls the death hook exactly once");
        CHECK(ps_client_spawn(&CL, &w, 5000, &info) == PS_SPAWN_DEAD, "spawning now reports DEAD");
        (void)v; (void)why;
    }
    ps_client_stop(&CL);
    (void)z;
}

static void test_orderly_stop(void) {
    struct ps_worker w[3];
    struct ps_spawn_info info;
    pid_t pids[3];

    printf("\nclient: orderly stop with live workers\n");
    NSCRIPT = 0;
    start_client(false);
    for (int i = 0; i < 3; i++) {
        ps_client_spawn(&CL, &w[i], 5000, &info);
        pids[i] = w[i].pid;
    }
    ps_client_stop(&CL);
    CHECK(atomic_load(&DEAD_CALLS) == 0, "stopping does not call the death hook");
    {
        bool gone = true;
        char st;
        for (int i = 0; i < 3; i++) {
            int64_t end = ps_now_ms() + 3000;
            while (stat_of(pids[i], &st) >= 0 && st != 'Z' && ps_now_ms() < end) usleep(10000);
            if (stat_of(pids[i], &st) >= 0 && st != 'Z') gone = false;
        }
        CHECK(gone, "the spawner took its workers down with it");
    }
    for (int i = 0; i < 3; i++) close(w[i].sock);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

/* ---- concurrency ---- */

struct tctx { int id; int fails; int ok; int spawn_failed; };

static void *scan_thread(void *arg) {
    struct tctx *t = arg;
    struct ps_worker w;
    struct ps_spawn_info info;

    for (int iter = 0; iter < 12; iter++) {
        enum ps_spawn_status s = ps_client_spawn(&CL, &w, 8000, &info);

        if (s == PS_SPAWN_FAILED) { t->spawn_failed++; continue; }
        if (s != PS_SPAWN_OK) { t->fails++; continue; }
        for (int k = 0; k < 4; k++) {
            struct ps_verdict v;
            const char *why;
            int fd;
            bool evil = ((t->id + iter + k) & 1) != 0;
            char content[64];

            snprintf(content, sizeof(content), "%s thread %d iter %d", evil ? "EVIL" : "fine", t->id, iter);
            fd = make_file(content);
            if (fd < 0 || !ps_client_scan(&CL, &w, fd, 8000, &v, &why) ||
                v.verdict != (evil ? PS_VERDICT_MALICIOUS : PS_VERDICT_CLEAN) || v.inconclusive)
                t->fails++;
            else
                t->ok++;
            if (fd >= 0) close(fd);
        }
        ps_client_release(&CL, &w);
    }
    return NULL;
}

static void test_concurrent(void) {
    enum { N = 8 };
    pthread_t th[N];
    struct tctx ctx[N];
    int fds0, total_ok = 0, total_fail = 0, total_sf = 0;

    printf("\nclient: concurrent scan threads\n");
    {
        struct step sc[40];
        int k = 0;
        for (int i = 0; i < 40; i++) sc[i] = (struct step){M_OK, 0};
        sc[2] = (struct step){M_FAIL, PS_H_RLIMITS};
        sc[9] = (struct step){M_FAIL, PS_H_SECCOMP};
        sc[17] = (struct step){M_SLOW, 300};
        sc[25] = (struct step){M_SLOW, 150};
        (void)k;
        script(40, sc);
    }
    start_client(false);
    fds0 = count_fds();
    memset(ctx, 0, sizeof(ctx));
    for (int i = 0; i < N; i++) { ctx[i].id = i; pthread_create(&th[i], NULL, scan_thread, &ctx[i]); }
    for (int i = 0; i < N; i++) pthread_join(th[i], NULL);
    for (int i = 0; i < N; i++) { total_ok += ctx[i].ok; total_fail += ctx[i].fails; total_sf += ctx[i].spawn_failed; }

    CHECK(total_fail == 0, "no scan from any thread got another thread's answer or failed");
    CHECK(total_sf == 2, "exactly the two scripted spawn failures were reported, each to one thread");
    CHECK(total_ok == (N * 12 - 2) * 4, "every other iteration completed all of its scans");
    CHECK(children_settle(SP, 0, 5000), "afterwards no worker is left and none is a zombie");
    CHECK(count_fds() == fds0, "and main holds no descriptor it did not start with");
    CHECK(log_count("unknown request") == 0 && log_count("malformed") == 0,
          "the reader never saw a reply it could not place");
    ps_client_stop(&CL);
}

/* ---- the reader against a fake spawner ---- */

static void test_fake_spawner(void) {
    int sv[2];
    struct ps_client c;
    struct ps_ctl_msg m, got;
    int fd, fds0;
    int wsv[2];

    printf("\nreader thread: a fake spawner that sends junk\n");
    log_clear();
    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
    ps_client_attach(&c, sv[0], -1, 65534, 65534, false);
    c.log = log_hook;
    c.on_dead = dead_hook;
    ps_client_start(&c);
    fds0 = count_fds();

    /* Junk. */
    (void)!send(sv[1], "garbage", 7, MSG_NOSIGNAL);
    (void)!send(sv[1], "", 0, MSG_NOSIGNAL);
    CHECK(log_wait("malformed", 3000), "a malformed message is logged and dropped");
    CHECK(atomic_load(&DEAD_CALLS) == 0, "an empty record from a live spawner is not EOF");

    /* A READY nobody asked for: its socket is closed and its worker killed. */
    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, wsv);
    ps_ctl_msg_init(&m, PS_MSG_READY);
    m.request_id = 4242;
    m.worker_id = 77;
    m.pid = 1234;
    ps_ctl_send(sv[1], &m, wsv[0]);
    close(wsv[0]);
    {
        struct pollfd p = {.fd = sv[1], .events = POLLIN};
        int fd2 = -1;
        bool saw = poll(&p, 1, 3000) == 1 &&
                   ps_ctl_recv(sv[1], PS_FROM_MAIN, 0, &got, &fd2) == PS_CTL_OK;
        CHECK(saw && got.type == PS_MSG_KILL && got.worker_id == 77,
              "a READY for an unknown request makes the client KILL that worker id");
    }
    {
        char ch;
        CHECK(recv(wsv[1], &ch, 1, MSG_DONTWAIT) == 0, "and the socket it carried was closed");
    }
    close(wsv[1]);
    CHECK(log_wait("READY for unknown request 4242", 1000), "and it is logged");

    /* Unknown FAILED and EXITED are logged and ignored. */
    ps_ctl_msg_init(&m, PS_MSG_FAILED);
    m.request_id = 999;
    m.reason = PS_FAIL_TIMEOUT;
    ps_ctl_send(sv[1], &m, -1);
    ps_ctl_msg_init(&m, PS_MSG_EXITED);
    m.worker_id = 555;
    ps_ctl_send(sv[1], &m, -1);
    CHECK(log_wait("FAILED for unknown request 999", 3000) && log_wait("EXITED for unknown worker 555", 3000),
          "FAILED and EXITED naming nothing the client tracks are logged and ignored");

    /* A real flow: the client SPAWNs, the fake answers READY, then EXITED by SIGSYS. */
    {
        struct ps_worker w;
        struct ps_spawn_info info;
        pthread_t th;
        struct { struct ps_client *c; struct ps_worker *w; struct ps_spawn_info *i; enum ps_spawn_status s; } a =
            {&c, &w, &info, PS_SPAWN_DEAD};
        int sock_for_main[2];
        struct pollfd p = {.fd = sv[1], .events = POLLIN};
        bool saw_spawn;

        void *runner(void *x) {
            typeof(a) *q = x;
            q->s = ps_client_spawn(q->c, q->w, 5000, q->i);
            return NULL;
        }
        pthread_create(&th, NULL, runner, &a);
        fd = -1;
        saw_spawn = poll(&p, 1, 3000) == 1 &&
                    ps_ctl_recv(sv[1], PS_FROM_MAIN, 0, &got, &fd) == PS_CTL_OK &&
                    got.type == PS_MSG_SPAWN;
        CHECK(saw_spawn, "the client sends a SPAWN with a fresh request id");
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sock_for_main);
        ps_ctl_msg_init(&m, PS_MSG_READY);
        m.request_id = got.request_id;
        m.worker_id = 5;
        m.pid = 4321;
        ps_ctl_send(sv[1], &m, sock_for_main[0]);
        close(sock_for_main[0]);
        pthread_join(th, NULL);
        CHECK(a.s == PS_SPAWN_OK && w.sock >= 0 && w.worker_id == 5 && w.pid == 4321,
              "READY for it completes the spawn with the worker's id, pid and socket");

        /* A duplicate READY for the same request: not applied twice. */
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, wsv);
        m.worker_id = 6;
        ps_ctl_send(sv[1], &m, wsv[0]);
        close(wsv[0]);
        {
            int fd2 = -1;
            struct pollfd p2 = {.fd = sv[1], .events = POLLIN};
            bool k = poll(&p2, 1, 3000) == 1 && ps_ctl_recv(sv[1], PS_FROM_MAIN, 0, &got, &fd2) == PS_CTL_OK;
            CHECK(k && got.type == PS_MSG_KILL && got.worker_id == 6,
                  "a duplicate READY for the same request is not applied: that extra worker is killed");
        }
        close(wsv[1]);

        ps_ctl_msg_init(&m, PS_MSG_EXITED);
        m.worker_id = 5;
        m.detail = SIGSYS;
        ps_ctl_send(sv[1], &m, -1);
        CHECK(log_wait("worker 5 (pid 4321) killed by SIGSYS", 3000),
              "EXITED for a tracked worker is logged with the pid and a loud SIGSYS");
        ps_ctl_send(sv[1], &m, -1);
        CHECK(log_wait("EXITED for unknown worker 5", 3000),
              "and a repeat of it is then unknown: the table entry was freed");
        close(w.sock);
        close(sock_for_main[1]);
    }

    CHECK(count_fds() == fds0, "the client leaked no descriptor through any of that");
    CHECK(atomic_load(&DEAD_CALLS) == 0, "and the spawner was never wrongly declared dead");

    /* A real EOF is death. */
    close(sv[1]);
    CHECK(log_wait("spawner lost", 3000) && atomic_load(&DEAD_CALLS) == 1,
          "closing the channel for real calls the death hook once");
    ps_client_stop(&c);
}

/* Replies that match no SPAWN do not prove the spawner is draining requests. */
static void test_unmatched_replies_keep_hang_count(void) {
    int sv[2];
    struct ps_client c;
    struct ps_ctl_msg m;
    struct ps_worker w;
    struct ps_spawn_info info;
    enum ps_spawn_status s[3];

    printf("\nreader thread: unmatched replies do not reset the hang count\n");
    log_clear();
    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
    ps_client_attach(&c, sv[0], -1, 65534, 65534, false);
    c.log = log_hook;
    c.on_dead = dead_hook;
    ps_client_start(&c);
    for (int i = 0; i < 3; i++) {
        s[i] = ps_client_spawn(&c, &w, 120, &info);
        if (i < 2) {
            ps_ctl_msg_init(&m, PS_MSG_FAILED);
            m.request_id = 900000 + (uint64_t)i; /* matches nothing */
            m.reason = PS_FAIL_TIMEOUT;
            ps_ctl_send(sv[1], &m, -1);
            if (!log_wait("unknown request 90000", 2000)) log_dump();
        }
    }
    CHECK(s[0] == PS_SPAWN_TIMEOUT && s[1] == PS_SPAWN_TIMEOUT && s[2] == PS_SPAWN_DEAD &&
              atomic_load(&DEAD_CALLS) == 1,
          "three unanswered SPAWNs still declare the spawner hung, whatever else it sends");
    close(sv[1]);
    ps_client_stop(&c);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(240);
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    printf("privsep client: helpers and behaviour\n");
    test_status_helpers();
    test_basic();
    test_spawn_failures();
    test_hostile_workers();
    test_late_ready_and_hang();
    test_orderly_stop();
    test_concurrent();
    test_fake_spawner();
    test_unmatched_replies_keep_hang_count();
    SUMMARY("privsep_client (behaviour)");
}

#else
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(60);
    test_status_helpers();
    SUMMARY("privsep_client (helpers)");
}
#endif
EOF

# ---------------------------------------------------------------------------
# kern: the real kernel, real hardening (root)
# ---------------------------------------------------------------------------
cat > "$BUILD_DIR/kern.c" <<'EOF'
#include "common.h"

#define WORKER_UID 65534

static bool have_cap(int cap) {
    struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct d[2];

    if (syscall(SYS_capget, &h, d) < 0) return false;
    return (d[cap / 32].effective >> (cap % 32)) & 1u;
}
static bool can_harden(void) {
    return geteuid() == 0 && have_cap(CAP_SETUID) && have_cap(CAP_SETGID) &&
           have_cap(CAP_SETPCAP) && have_cap(CAP_KILL);
}

/* A child hardened up to `level`, then parked. 0: nothing. 1: credentials.
 * 2: + empty bounding set. 3: + NoNewPrivs. 4: + the real seccomp filter. */
static pid_t parked(int level, int *ready_r) {
    int p[2];
    pid_t pid;

    if (pipe(p) < 0) return -1;
    pid = fork();
    if (pid == 0) {
        char b = 'r';
        int sv[2];

        close(p[0]);
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
        if (level >= 2 && ps_drop_bounding_set() < 0) _exit(10);
        if (level >= 1 && ps_drop_credentials(WORKER_UID, WORKER_UID) < 0) _exit(11);
        if (level >= 1 && ps_clear_capabilities() < 0) _exit(12);
        if (level >= 3 && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) _exit(13);
        if (level < 4) (void)!write(p[1], &b, 1);
        /* The filter forbids write(): at level 4 the parent polls /proc. */
        if (level >= 4 && ps_seccomp_install(sv[1]) < 0) _exit(14);
        for (;;) {
            /* pause() is not on the allowlist; recvmsg on the IPC fd is. */
            char c;
            struct iovec iv = {&c, 1};
            struct msghdr mh;
            memset(&mh, 0, sizeof(mh));
            mh.msg_iov = &iv;
            mh.msg_iovlen = 1;
            (void)recvmsg(sv[1], &mh, 0);
        }
    }
    close(p[1]);
    *ready_r = p[0];
    return pid;
}

static bool wait_ready(pid_t pid, int rd, int level) {
    char b, p[64], buf[4096];
    int64_t end = ps_now_ms() + 3000;

    if (level < 4) return read(rd, &b, 1) == 1;
    snprintf(p, sizeof(p), "/proc/%d/status", (int)pid);
    while (ps_now_ms() < end) {
        FILE *f = fopen(p, "r");
        size_t l;
        if (f) {
            l = fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
            buf[l] = 0;
            if (ps_status_value(buf, "Seccomp") && *ps_status_value(buf, "Seccomp") == '2') return true;
        }
        usleep(10000);
    }
    return false;
}

/* A seccomp filter is inherited across fork(): under one (a container's
 * default profile, say) even an otherwise unhardened child reports
 * Seccomp: 2, so the "no filter yet" rung cannot be observed. */
static bool self_has_seccomp(void) {
    char buf[8192];
    FILE *f = fopen("/proc/self/status", "r");
    size_t l;
    const char *v;

    if (!f) return false;
    l = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[l] = 0;
    v = ps_status_value(buf, "Seccomp");
    return v && *v == '2';
}

static void test_proc_ladder(void) {
    static const struct { int level; const char *want; const char *what; } L[] = {
        {0, "Uid", "an unhardened process (still root)"},
        {1, "CapBnd", "credentials dropped but the bounding set still full"},
        {2, "NoNewPrivs", "+ empty bounding set, but NoNewPrivs not set"},
        {3, "Seccomp", "+ NoNewPrivs, but no seccomp filter"},
    };
    char why[160];

    printf("\n/proc check against partly hardened processes (root):\n");
    if (!can_harden()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID, CAP_SETPCAP and CAP_KILL");
        return;
    }
    for (size_t i = 0; i < sizeof(L) / sizeof(L[0]); i++) {
        int rd;
        pid_t pid = parked(L[i].level, &rd);
        char label[200];
        bool rejected;

        if (L[i].level == 3 && self_has_seccomp()) {
            if (pid > 0) { kill(pid, SIGKILL); waitpid(pid, NULL, 0); }
            close(rd);
            SKIPT("the no-seccomp-yet rung: this process already runs under a seccomp filter");
            continue;
        }
        if (pid < 0 || !wait_ready(pid, rd, L[i].level)) { CHECK(false, L[i].what); continue; }
        rejected = !ps_verify_worker(pid, WORKER_UID, WORKER_UID, getpid(), why, sizeof(why));
        snprintf(label, sizeof(label), "%s is rejected, naming %s", L[i].what, L[i].want);
        CHECK(rejected && strstr(why, L[i].want), label);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        close(rd);
    }
    {
        int rd;
        pid_t pid = parked(4, &rd);

        CHECK(pid > 0 && wait_ready(pid, rd, 4), "a fully hardened process comes up");
        CHECK(ps_verify_worker(pid, WORKER_UID, WORKER_UID, getpid(), why, sizeof(why)),
              "and passes the check");
        CHECK(!ps_verify_worker(pid, WORKER_UID + 1, WORKER_UID, getpid(), why, sizeof(why)) &&
                  strstr(why, "Uid"),
              "but not with a different expected uid");
        CHECK(!ps_verify_worker(pid, WORKER_UID, WORKER_UID + 1, getpid(), why, sizeof(why)) &&
                  strstr(why, "Gid"),
              "nor a different expected gid");
        CHECK(!ps_verify_worker(pid, WORKER_UID, WORKER_UID, getpid() + 1, why, sizeof(why)) &&
                  strstr(why, "PPid"),
              "nor with a different expected parent");
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        {
            int64_t end = ps_now_ms() + 100;
            while (ps_now_ms() < end) usleep(1000);
        }
        CHECK(!ps_verify_worker(pid, WORKER_UID, WORKER_UID, getpid(), why, sizeof(why)),
              "a worker that is gone (even as a reused pid) is rejected, not trusted");
        close(rd);
    }
}

static struct ps_client CL;

static void test_real_worker(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    struct ps_worker w;
    struct ps_spawn_info info;
    struct ps_verdict v;
    const char *why = "";
    int ctl = -1, fd;
    pid_t sp = -1;

    printf("\nreal workers through the client (root):\n");
    if (!can_harden()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID, CAP_SETPCAP and CAP_KILL");
        return;
    }
    log_clear();
    ps_spawner_start(&cfg, &ctl, &sp);
    ps_client_attach(&CL, ctl, sp, cfg.harden.uid, cfg.harden.gid, true);
    CL.log = log_hook;
    CL.on_dead = dead_hook;
    ps_client_start(&CL);

    CHECK(ps_client_spawn(&CL, &w, 10000, &info) == PS_SPAWN_OK && w.sock >= 0,
          "a really hardened worker is spawned and passes the /proc check");
    fd = make_file("EVIL bytes");
    CHECK(ps_client_scan(&CL, &w, fd, 5000, &v, &why) && v.verdict == PS_VERDICT_MALICIOUS &&
              strcmp(v.rule_name, "Test:evil") == 0,
          "it serves a scan under its seccomp filter");
    close(fd);

    /* The worker is killed by seccomp: a syscall it may not make. */
    fd = make_file("MODE:OPEN");
    CHECK(!ps_client_scan(&CL, &w, fd, 5000, &v, &why) && is_canonical_failure(&v) && w.sock < 0,
          "a worker that makes a forbidden syscall dies, and the scan is the canonical failure");
    close(fd);
    CHECK(log_wait("killed by SIGSYS", 5000), "and its death is reported loudly as SIGSYS");
    if (log_count("killed by SIGSYS") == 0) log_dump();

    CHECK(ps_client_spawn(&CL, &w, 10000, &info) == PS_SPAWN_OK, "a replacement is spawned");
    fd = make_file("fine");
    CHECK(ps_client_scan(&CL, &w, fd, 5000, &v, &why) && v.verdict == PS_VERDICT_CLEAN,
          "and works");
    close(fd);
    ps_client_release(&CL, &w);
    ps_client_stop(&CL);
    CHECK(atomic_load(&DEAD_CALLS) == 0, "an orderly stop is not spawner death");
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(120);
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    printf("privsep client: real hardening against the real kernel\n");
    test_proc_ladder();
    test_real_worker();
    SUMMARY("privsep_client (kernel)");
}
EOF

CC="${CC:-gcc}"
rc=0
SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined"
# The scan callback and nested test helpers use GNU C.
COMMON="-std=gnu11 -Wall -Wextra -Werror -pthread -I$SRC_DIR -I$BUILD_DIR"

echo "### building (ASan+UBSan: helpers and client behaviour) ###"
# shellcheck disable=SC2086
"$CC" $COMMON -O1 -g -fno-omit-frame-pointer $SAN -DPS_SPAWNER_TEST_HOOKS \
    -o "$BUILD_DIR/beh" "$BUILD_DIR/beh.c" || exit 1

echo "### building (plain -O2: real hardening in the kernel) ###"
# shellcheck disable=SC2086
"$CC" $COMMON -O2 -fstack-protector-strong -DPS_WORKER_TEST_HOOKS \
    -o "$BUILD_DIR/kern" "$BUILD_DIR/kern.c" || exit 1

TSAN=""
# shellcheck disable=SC2086
if "$CC" $COMMON -O1 -g -fsanitize=thread -DPS_SPAWNER_TEST_HOOKS \
        -o "$BUILD_DIR/tsan" "$BUILD_DIR/beh.c" 2> "$BUILD_DIR/tsan.log"; then
    TSAN=1
else
    echo "### ThreadSanitizer build unavailable here - skipping that run ###"
fi

echo
"$BUILD_DIR/beh" || rc=1
if [ -n "$TSAN" ]; then
    echo
    echo "### ThreadSanitizer run ###"
    TSAN_OPTIONS="halt_on_error=1:report_signal_unsafe=0" "$BUILD_DIR/tsan" || rc=1
fi
echo
"$BUILD_DIR/kern" || rc=1

exit $rc
