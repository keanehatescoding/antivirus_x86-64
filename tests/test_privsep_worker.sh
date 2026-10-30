#!/usr/bin/env bash
#
# tests/test_privsep_worker.sh - coverage for userspace/avd/privsep_worker.h,
# the worker side of avd's privilege separation (#103, Stage 1b; see
# docs/privilege-separation.md, "Worker hardening fails closed", "IPC" and
# "Seccomp allowlist (worker)").
#
# Three layers, all against the production header compiled standalone (same
# arrangement as test_privsep_proto.sh):
#
#   1. The seccomp program, checked exhaustively with a small classic-BPF
#      interpreter: every syscall number on every architecture value, the x32
#      bit, and the argument checks, with an independent list of what must be
#      allowed and what must never be.
#   2. The request/reply loop under ASan+UBSan, in-process and over a forked
#      worker without seccomp: descriptor lifetime, malformed requests, reply
#      normalisation.
#   3. Real workers under the real kernel: the hardening sequence (failure
#      injected at every step, state read back from /proc/<pid>/status the way
#      the parent will), the seccomp filter killing what it should and
#      allowing what it should, and parent-death handling.
#
# Layer 3 needs root (credential change, capabilities); the seccomp-only part
# of it does not. Without root those tests print SKIP, not PASS:
#   sudo tests/test_privsep_worker.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${PS_SRC_DIR:-$REPO_ROOT/userspace/avd}"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_privsep_worker.XXXXXX")" || exit 1

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
/* Each binary uses a different subset of these helpers. */
#pragma GCC diagnostic ignored "-Wunused-function"
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

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

/* Open descriptors in this process, not counting the one used to look. */
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

/* A file whose content the test scan callback recognises. */
static int make_file(const char *content) {
    char path[] = "/tmp/av_privsep_worker_XXXXXX";
    int fd = mkstemp(path);

    if (fd < 0) return -1;
    unlink(path);
    if (write(fd, content, strlen(content)) < 0) { close(fd); return -1; }
    return fd;
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

static int send_req(int sock, uint64_t id, const int *fds, int nfds) {
    struct ps_request rq;

    ps_request_init(&rq, id);
    return send_msg(sock, &rq, sizeof(rq), fds, nfds);
}

/* The scan used by both binaries. Only syscalls the worker filter allows:
 * pread, and malloc/free big enough to go through mmap/munmap. Convicts on
 * "EVIL", reports the byte count as the score. */
static void scan_cb(int fd, void *ctx, struct ps_reply *rep) {
    size_t cap = 1u << 20;
    unsigned char *b = malloc(cap);
    ssize_t n;

    (void)ctx;
    if (!b) return;
    n = pread(fd, b, cap, 0);
    if (n >= 0) {
        rep->inconclusive = 0;
        rep->score = (int32_t)n;
        if (memmem(b, (size_t)n, "EVIL", 4)) {
            rep->verdict = PS_VERDICT_MALICIOUS;
            snprintf(rep->rule_name, sizeof(rep->rule_name), "Test:Evil");
        }
    }
    free(b);
}

static bool read_reply(int sock, uint64_t id, struct ps_verdict *v) {
    /* One byte of slack so an oversized reply would be seen as oversized. */
    unsigned char buf[sizeof(struct ps_reply) + 1];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);

    if (n < 0) { ps_verdict_failure(v); return false; }
    return ps_reply_validate(buf, (size_t)n, id, v);
}
#endif
EOF

# ---------------------------------------------------------------------------
# Layer 1 + 2: BPF program and IPC loop (ASan+UBSan, no seccomp installed)
# ---------------------------------------------------------------------------
cat > "$BUILD_DIR/ipc.c" <<'EOF'
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/wait.h>
#include "privsep_worker.h"
#include "common.h"

/* ---- Layer 1: the BPF program, run in userspace ---- */

static uint32_t bpf_run(const struct sock_filter *p, size_t n,
                        const struct seccomp_data *d) {
    uint32_t A = 0;
    size_t pc = 0;
    const unsigned char *raw = (const unsigned char *)d;

    while (pc < n) {
        const struct sock_filter *i = &p[pc];
        switch (i->code) {
        case BPF_LD | BPF_W | BPF_ABS:
            memcpy(&A, raw + i->k, 4);
            pc++;
            break;
        case BPF_JMP | BPF_JEQ | BPF_K:
            pc += 1 + (A == i->k ? i->jt : i->jf);
            break;
        case BPF_JMP | BPF_JSET | BPF_K:
            pc += 1 + ((A & i->k) ? i->jt : i->jf);
            break;
        case BPF_RET | BPF_K:
            return i->k;
        default:
            return 0xdeadbeef; /* an opcode the filter should never use */
        }
    }
    return 0xdeadbeef; /* ran off the end */
}

static bool allowed(const struct sock_filter *p, size_t n, uint32_t arch,
                    int nr, uint64_t a0, uint64_t a3) {
    struct seccomp_data d;

    memset(&d, 0, sizeof(d));
    d.arch = arch;
    d.nr = nr;
    d.args[0] = a0;
    d.args[3] = a3;
    return bpf_run(p, n, &d) == SECCOMP_RET_ALLOW;
}

/* An independent statement of what the worker may do, deliberately not
 * derived from the header's table. */
static bool want_plain(int nr) {
    switch (nr) {
    case SYS_read: case SYS_pread64: case SYS_lseek: case SYS_fstat:
    case SYS_fstatfs:
    case SYS_mmap: case SYS_munmap: case SYS_mprotect: case SYS_mremap:
    case SYS_brk: case SYS_madvise: case SYS_futex: case SYS_dup:
    case SYS_close: case SYS_clock_gettime: case SYS_clock_nanosleep:
    case SYS_rt_sigaction: case SYS_rt_sigprocmask: case SYS_rt_sigreturn:
    case SYS_getrandom: case SYS_exit_group:
        return true;
    default:
        return false;
    }
}

static void test_bpf(void) {
    struct sock_filter prog[PS_BPF_MAX];
    const int FD = 7;
    size_t n = ps_seccomp_build(prog, FD);
    int bad = 0, plain_ok = 0, sdone = 0;
    static const int never[] = {
        SYS_open, SYS_openat, SYS_creat, SYS_socket, SYS_connect, SYS_bind,
        SYS_listen, SYS_accept, SYS_accept4, SYS_sendto, SYS_recvfrom,
        SYS_sendmmsg, SYS_recvmmsg, SYS_execve, SYS_execveat, SYS_clone,
        SYS_clone3, SYS_fork, SYS_vfork, SYS_ptrace, SYS_kill, SYS_tgkill,
        SYS_tkill, SYS_write, SYS_writev, SYS_pwrite64, SYS_unlink,
        SYS_unlinkat, SYS_rename, SYS_mkdir, SYS_chmod, SYS_chown, SYS_mount,
        SYS_umount2, SYS_setuid, SYS_setresuid, SYS_setgid, SYS_truncate,
        SYS_ftruncate, SYS_fallocate, SYS_io_uring_setup, SYS_bpf,
        SYS_perf_event_open, SYS_process_vm_writev, SYS_memfd_create,
        SYS_userfaultfd, SYS_prctl, SYS_seccomp, SYS_capset, SYS_chroot,
        SYS_unshare, SYS_setns, SYS_pivot_root, SYS_ioctl, SYS_pipe, SYS_dup2,
        SYS_dup3, SYS_fcntl, SYS_getdents64, SYS_readlink, SYS_stat,
        SYS_lstat, SYS_access, SYS_socketpair, SYS_shutdown,
    };

    printf("\nseccomp program:\n");
    CHECK(n > 0 && n <= PS_BPF_MAX, "builds, and fits the budget");
    CHECK(ps_seccomp_build(prog, -1) == 0, "refuses a negative ipc fd");
    if (n == 0) return;

    /* Structural: every jump is forward and lands inside the program. */
    for (size_t i = 0; i < n; i++) {
        uint16_t c = prog[i].code;
        if ((c & 7) == BPF_JMP) {
            if (i + 1 + prog[i].jt >= n || i + 1 + prog[i].jf >= n) bad++;
        }
    }
    CHECK(bad == 0, "every jump lands inside the program");
    CHECK(prog[n - 1].code == (BPF_RET | BPF_K) &&
          prog[n - 1].k == SECCOMP_RET_KILL_PROCESS,
          "falls off into KILL_PROCESS, not ALLOW");

    /* Exhaustive over syscall numbers on the right architecture. */
    bad = 0;
    for (int nr = 0; nr < 1024; nr++) {
        bool is_msg = (nr == SYS_recvmsg || nr == SYS_sendmsg);
        bool is_stat = (nr == SYS_newfstatat);
        bool got = allowed(prog, n, AUDIT_ARCH_X86_64, nr, 0, 0);
        if (want_plain(nr)) {
            plain_ok++;
            if (!allowed(prog, n, AUDIT_ARCH_X86_64, nr, 0, 0)) bad++;
        } else if (is_msg || is_stat) {
            if (got) bad++; /* never allowed with all-zero arguments */
        } else if (got) {
            bad++;
        }
    }
    CHECK(bad == 0, "only the allowlist is allowed, for syscall 0..1023");
    CHECK(plain_ok == 21, "all twenty-one plain entries are exercised");

    /* The explicit never-list, with every argument shape that might help. */
    bad = 0;
    for (size_t i = 0; i < sizeof(never) / sizeof(never[0]); i++) {
        uint64_t a0s[] = {0, FD, 3, ~0ull, (1ull << 32) | FD};
        for (size_t j = 0; j < sizeof(a0s) / sizeof(a0s[0]); j++)
            if (allowed(prog, n, AUDIT_ARCH_X86_64, never[i], a0s[j],
                        AT_EMPTY_PATH))
                bad++;
    }
    CHECK(bad == 0, "no forbidden syscall is allowed, whatever the arguments");

    /* Architecture and ABI. */
    bad = 0;
    for (int nr = 0; nr < 1024; nr++) {
        if (allowed(prog, n, AUDIT_ARCH_I386, nr, FD, AT_EMPTY_PATH)) bad++;
        if (allowed(prog, n, AUDIT_ARCH_AARCH64, nr, FD, AT_EMPTY_PATH)) bad++;
        if (allowed(prog, n, 0, nr, FD, AT_EMPTY_PATH)) bad++;
        if (allowed(prog, n, AUDIT_ARCH_X86_64, nr | PS_X32_BIT, FD,
                    AT_EMPTY_PATH))
            bad++;
    }
    CHECK(bad == 0, "other architectures and the x32 ABI are always killed");

    /* sendmsg / recvmsg only on the IPC descriptor, all 64 bits. */
    bad = 0;
    for (int k = 0; k < 2; k++) {
        int nr = k ? SYS_sendmsg : SYS_recvmsg;
        if (!allowed(prog, n, AUDIT_ARCH_X86_64, nr, FD, 0)) bad++;
        if (allowed(prog, n, AUDIT_ARCH_X86_64, nr, FD + 1, 0)) bad++;
        if (allowed(prog, n, AUDIT_ARCH_X86_64, nr, 0, 0)) bad++;
        if (allowed(prog, n, AUDIT_ARCH_X86_64, nr, (uint64_t)-1, 0)) bad++;
        if (allowed(prog, n, AUDIT_ARCH_X86_64, nr, (1ull << 32) | FD, 0)) bad++;
        if (allowed(prog, n, AUDIT_ARCH_X86_64, nr, (uint64_t)FD << 32, 0)) bad++;
    }
    CHECK(bad == 0, "sendmsg/recvmsg are allowed on exactly the IPC fd");

    /* newfstatat only with AT_EMPTY_PATH. */
    CHECK(allowed(prog, n, AUDIT_ARCH_X86_64, SYS_newfstatat, 5,
                  AT_EMPTY_PATH), "newfstatat(AT_EMPTY_PATH) allowed");
    CHECK(allowed(prog, n, AUDIT_ARCH_X86_64, SYS_newfstatat, 5,
                  AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW),
          "newfstatat(AT_EMPTY_PATH|NOFOLLOW) allowed");
    CHECK(!allowed(prog, n, AUDIT_ARCH_X86_64, SYS_newfstatat, 5, 0),
          "newfstatat by path is killed");
    CHECK(!allowed(prog, n, AUDIT_ARCH_X86_64, SYS_newfstatat, 5,
                   AT_SYMLINK_NOFOLLOW), "newfstatat(NOFOLLOW) alone is killed");
    (void)sdone;

    /* A different ipc fd number gives a different program. */
    {
        struct sock_filter p2[PS_BPF_MAX];
        size_t n2 = ps_seccomp_build(p2, 11);
        CHECK(n2 == n && allowed(p2, n2, AUDIT_ARCH_X86_64, SYS_sendmsg, 11, 0) &&
              !allowed(p2, n2, AUDIT_ARCH_X86_64, SYS_sendmsg, FD, 0),
              "the fd check follows the configured descriptor");
    }
}

/* ---- ps_close_all_but ---- */

static void test_close_all_but(void) {
    int pid_status = 0;
    pid_t pid;

    printf("\nclosing inherited descriptors:\n");
    for (int variant = 0; variant < 4; variant++) {
        pid = fork();
        if (pid == 0) {
            int keep_a, keep_b = -1, extra[6], ok = 1;
            int fd0 = open("/dev/null", O_RDONLY);
            for (int i = 0; i < 6; i++) extra[i] = open("/dev/null", O_RDONLY);
            keep_a = extra[1];
            if (variant == 1) keep_b = extra[4];
            if (variant == 2) { keep_b = keep_a; keep_a = extra[4]; }
            if (variant == 3) { keep_a = fd0; keep_b = extra[5]; }
            if (ps_close_all_but(keep_a, keep_b) < 0) _exit(2);
            for (int fd = 0; fd < 64; fd++) {
                bool open_now = fcntl(fd, F_GETFD) >= 0;
                bool should = (fd == keep_a || fd == keep_b);
                if (open_now != should) ok = 0;
            }
            _exit(ok ? 0 : 1);
        }
        waitpid(pid, &pid_status, 0);
        {
            char label[80];
            snprintf(label, sizeof(label),
                     "variant %d: only the kept descriptors stay open", variant);
            CHECK(WIFEXITED(pid_status) && WEXITSTATUS(pid_status) == 0, label);
        }
    }
}

/* ---- Layer 2: ps_worker_recv, in this process ---- */

static void test_recv(void) {
    int sv[2];
    uint64_t id;
    bool have;
    int fd, before, after;
    int f1, f2;

    printf("\nreceiving requests (descriptor handling):\n");
    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
    f1 = make_file("hello");
    f2 = make_file("world");
    before = count_fds();

    /* well-formed */
    send_req(sv[0], 0xabcdef0123ull, &f1, 1);
    CHECK(ps_worker_recv(sv[1], &id, &have, &fd) == PS_RECV_OK && have &&
          id == 0xabcdef0123ull && fd >= 0, "one fd and a good header: OK");
    CHECK(fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC),
          "the received descriptor is close-on-exec");
    {
        char b[8] = "";
        CHECK(fd >= 0 && pread(fd, b, 5, 0) == 5 && !memcmp(b, "hello", 5),
              "and it reads the file the parent opened");
    }
    if (fd >= 0) close(fd);
    CHECK(count_fds() == before, "closing it leaves nothing behind");

    /* zero descriptors */
    send_req(sv[0], 1, NULL, 0);
    CHECK(ps_worker_recv(sv[1], &id, &have, &fd) == PS_RECV_PROTOCOL && have &&
          id == 1 && fd == -1, "no descriptor: protocol error, id still known");

    /* two, five and nine descriptors */
    {
        int many[9];
        int counts[] = {2, 5, 9};
        for (int c = 0; c < 3; c++) {
            int opened = 0;
            char label[96];
            for (int i = 0; i < counts[c]; i++) many[i] = dup(f1), opened++;
            before = count_fds();
            send_req(sv[0], 2, many, counts[c]);
            for (int i = 0; i < opened; i++) close(many[i]);
            {
                int base = count_fds();
                enum ps_recv_result r = ps_worker_recv(sv[1], &id, &have, &fd);
                after = count_fds();
                snprintf(label, sizeof(label),
                         "%d descriptors: protocol error, all of them closed",
                         counts[c]);
                CHECK(r == PS_RECV_PROTOCOL && fd == -1 && after == base, label);
            }
            (void)before;
        }
    }

    /* header problems, each with a descriptor attached */
    {
        struct ps_request rq;
        unsigned char big[sizeof(rq) + 1];
        int base;

        ps_request_init(&rq, 3);
        base = count_fds();
        send_msg(sv[0], &rq, sizeof(rq) - 1, &f1, 1);
        CHECK(ps_worker_recv(sv[1], &id, &have, &fd) == PS_RECV_PROTOCOL &&
              !have && count_fds() == base, "short request: rejected, fd closed");

        memcpy(big, &rq, sizeof(rq));
        big[sizeof(rq)] = 0;
        send_msg(sv[0], big, sizeof(big), &f1, 1);
        CHECK(ps_worker_recv(sv[1], &id, &have, &fd) == PS_RECV_PROTOCOL &&
              !have && count_fds() == base,
              "request one byte too long: rejected, fd closed");

        send_msg(sv[0], NULL, 0, &f1, 1);
        CHECK(ps_worker_recv(sv[1], &id, &have, &fd) == PS_RECV_PROTOCOL &&
              !have && count_fds() == base,
              "empty message carrying a descriptor: rejected, fd closed");

        ps_request_init(&rq, 3);
        rq.magic ^= 1;
        send_msg(sv[0], &rq, sizeof(rq), &f1, 1);
        CHECK(ps_worker_recv(sv[1], &id, &have, &fd) == PS_RECV_PROTOCOL &&
              !have && count_fds() == base, "bad magic: rejected, fd closed");

        ps_request_init(&rq, 3);
        rq.version++;
        send_msg(sv[0], &rq, sizeof(rq), &f1, 1);
        CHECK(ps_worker_recv(sv[1], &id, &have, &fd) == PS_RECV_PROTOCOL &&
              !have && count_fds() == base, "bad version: rejected, fd closed");
    }

    /* orderly shutdown */
    close(sv[0]);
    CHECK(ps_worker_recv(sv[1], &id, &have, &fd) == PS_RECV_EOF,
          "peer closing is EOF, not an error");
    close(sv[1]);
    close(f1);
    close(f2);
}

/* ---- Layer 2: ps_worker_run in a forked worker (no seccomp) ---- */

static void scan_fdcount(int fd, void *ctx, struct ps_reply *rep) {
    scan_cb(fd, ctx, rep);
    rep->yara_matches = count_fds(); /* the descriptors this worker holds now */
}

static void scan_nothing(int fd, void *ctx, struct ps_reply *rep) {
    (void)fd; (void)ctx; (void)rep;
}

static void scan_scribble(int fd, void *ctx, struct ps_reply *rep) {
    (void)fd; (void)ctx;
    rep->magic = 0; rep->version = 99; rep->request_id = 0xbad;
    rep->reserved = 0xffffffffu;
    rep->verdict = PS_VERDICT_MALICIOUS;
    rep->inconclusive = 0;
    memset(rep->rule_name, 'A', sizeof(rep->rule_name)); /* no NUL */
}

static pid_t start_worker(int *parent_end, ps_scan_fn fn, rlim_t nofile) {
    int sv[2];
    pid_t pid;

    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
    pid = fork();
    if (pid == 0) {
        struct rlimit rl = {nofile, nofile};
        close(sv[0]);
        if (nofile) setrlimit(RLIMIT_NOFILE, &rl);
        _exit(ps_worker_run(sv[1], fn, NULL) == 0 ? 0 : 7);
    }
    close(sv[1]);
    *parent_end = sv[0];
    return pid;
}

static int reap(pid_t pid) {
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static void test_run(void) {
    int s, evil, fine;
    pid_t pid;
    struct ps_verdict v;

    printf("\nthe request/reply loop:\n");
    evil = make_file("xxEVILxx");
    fine = make_file("nothing to see");

    pid = start_worker(&s, scan_cb, 0);
    send_req(s, 11, &evil, 1);
    CHECK(read_reply(s, 11, &v) && v.verdict == PS_VERDICT_MALICIOUS &&
          !v.inconclusive && !strcmp(v.rule_name, "Test:Evil") && v.score == 8,
          "a conviction comes back with its rule and the request id");
    send_req(s, 12, &fine, 1);
    CHECK(read_reply(s, 12, &v) && v.verdict == PS_VERDICT_CLEAN &&
          !v.inconclusive && v.score == 14, "a clean file comes back clean");
    close(s);
    CHECK(reap(pid) == 0, "closing the socket ends the worker with status 0");

    /* Descriptor lifetime across many requests with a tiny NOFILE. */
    pid = start_worker(&s, scan_fdcount, 24);
    {
        int ok = 1, first = -1, same = 1;
        for (int i = 0; i < 400; i++) {
            if (send_req(s, 1000 + (uint64_t)i, &fine, 1) < 0 ||
                !read_reply(s, 1000 + (uint64_t)i, &v) || v.inconclusive) {
                ok = 0;
                break;
            }
            if (first < 0) first = v.yara_matches;
            else if (v.yara_matches != first) same = 0;
        }
        CHECK(ok, "400 requests succeed with RLIMIT_NOFILE = 24");
        CHECK(same, "the worker holds the same number of descriptors throughout");
    }
    close(s);
    CHECK(reap(pid) == 0, "and still shuts down cleanly");

    /* A callback that does nothing yields the canonical failure result. */
    pid = start_worker(&s, scan_nothing, 0);
    send_req(s, 21, &fine, 1);
    CHECK(read_reply(s, 21, &v) && v.verdict == PS_VERDICT_CLEAN &&
          v.inconclusive && v.score == 0 && v.rule_name[0] == '\0',
          "an inert scan callback is reported CLEAN + inconclusive");
    close(s);
    reap(pid);

    /* A callback cannot forge the header or leave the name unterminated. */
    pid = start_worker(&s, scan_scribble, 0);
    send_req(s, 22, &fine, 1);
    CHECK(read_reply(s, 22, &v) && v.verdict == PS_VERDICT_MALICIOUS &&
          strlen(v.rule_name) == PS_RULE_NAME_SIZE - 1,
          "scribbled header fields are restored, the name is terminated");
    close(s);
    reap(pid);

    /* Protocol errors: failure reply if the id is known, then exit. */
    pid = start_worker(&s, scan_cb, 0);
    {
        int two[2] = {fine, evil};
        send_req(s, 31, two, 2);
        CHECK(read_reply(s, 31, &v) && v.inconclusive &&
              v.verdict == PS_VERDICT_CLEAN,
              "two descriptors: an echoed failure reply");
        CHECK(reap(pid) == 7, "and the worker exits non-zero");
        close(s);
    }
    pid = start_worker(&s, scan_cb, 0);
    {
        struct ps_request rq;
        struct ps_reply r;
        ps_request_init(&rq, 32);
        rq.magic = 0;
        send_msg(s, &rq, sizeof(rq), &fine, 1);
        CHECK(recv(s, &r, sizeof(r), 0) == 0,
              "a bad header gets no reply, only EOF");
        CHECK(reap(pid) == 7, "and the worker exits non-zero");
        close(s);
    }

    close(evil);
    close(fine);
}

int main(void) {
    alarm(120);
    printf("privsep worker: BPF program and IPC loop\n");
    test_bpf();
    test_close_all_but();
    test_recv();
    test_run();
    SUMMARY("privsep_worker (bpf + ipc)");
}
EOF

# ---------------------------------------------------------------------------
# Layer 3: real workers under the real kernel
# ---------------------------------------------------------------------------
cat > "$BUILD_DIR/hard.c" <<'EOF'
#define _GNU_SOURCE
#define PS_WORKER_TEST_HOOKS 1
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "privsep_worker.h"
#include "common.h"

#define WORKER_UID 65534
#define WORKER_NOFILE 16

/* What a child tells its parent over the IPC socket. Sent with sendmsg(),
 * which is the one send call the worker filter allows. */
struct report {
    int step;          /* ps_worker_harden() result: 0 = hardened */
    int err;           /* errno at failure */
    unsigned ran;      /* ps_test_ran */
    int seccomp_mode;  /* PR_GET_SECCOMP, read only if hardening failed */
    int pid;
};

static void send_report(int sock, const struct report *r) {
    struct iovec iov = {.iov_base = (void *)r, .iov_len = sizeof(*r)};
    struct msghdr m;

    memset(&m, 0, sizeof(m));
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    (void)sendmsg(sock, &m, MSG_NOSIGNAL);
}

static bool recv_report(int sock, struct report *r) {
    struct timeval tv = {10, 0};

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return recv(sock, r, sizeof(*r), 0) == (ssize_t)sizeof(*r);
}

/* Fork a worker. It runs the hardening sequence with `fail_step` injected,
 * reports, and (if hardened and `serve`) serves requests under the filter. */
static pid_t spawn_worker(int *parent_end, int fail_step, bool serve,
                          int ppid_skew, uid_t uid) {
    int sv[2];
    pid_t pid, me = getpid();

    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
    pid = fork();
    if (pid == 0) {
        struct ps_harden_cfg cfg = {
            .uid = uid, .gid = uid, .ipc_fd = sv[1], .log_fd = -1,
            .expect_ppid = me + ppid_skew,
            .as_bytes = 1ull << 30, .cpu_seconds = 60, .nofile = WORKER_NOFILE,
        };
        struct report r;
        int step, my_pid = getpid(); /* getpid() is not allowed once hardened */

        close(sv[0]);
        ps_test_fail_step = fail_step;
        errno = 0;
        step = ps_worker_harden(&cfg);
        memset(&r, 0, sizeof(r));
        r.step = step;
        r.err = errno;
        r.ran = ps_test_ran;
        r.pid = my_pid;
        if (step != 0) {
            r.seccomp_mode = prctl(PR_GET_SECCOMP);
            send_report(sv[1], &r);
            _exit(1);
        }
        send_report(sv[1], &r);
        if (!serve)
            _exit(0);
        _exit(ps_worker_run(sv[1], scan_cb, NULL) == 0 ? 0 : 9);
    }
    close(sv[1]);
    *parent_end = sv[0];
    return pid;
}

static int wait_exit(pid_t pid) {
    int st = 0;

    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

/* One "Key:\ta b c" line of /proc/<pid>/status, as the parent will read it. */
static bool status_line(pid_t pid, const char *key, char *out, size_t cap) {
    char path[64], line[256];
    FILE *f;
    size_t kl = strlen(key);
    bool found = false;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    f = fopen(path, "r");
    if (!f) return false;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, key, kl) && line[kl] == ':') {
            char *v = line + kl + 1;
            while (*v == ' ' || *v == '\t') v++;
            v[strcspn(v, "\n")] = '\0';
            snprintf(out, cap, "%s", v);
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

static bool status_is(pid_t pid, const char *key, const char *want) {
    char v[128];

    return status_line(pid, key, v, sizeof(v)) && !strcmp(v, want);
}

static long limit_of(pid_t pid, const char *name) {
    char path[64], line[256];
    FILE *f;
    long val = -2;

    snprintf(path, sizeof(path), "/proc/%d/limits", (int)pid);
    f = fopen(path, "r");
    if (!f) return -2;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, name, strlen(name))) {
            char *p = line + strlen(name);
            while (*p == ' ') p++;
            val = strncmp(p, "unlimited", 9) ? atol(p) : -1;
            break;
        }
    }
    fclose(f);
    return val;
}

/* ---- Seccomp, in a real kernel, without needing root ---- */

enum act {
    A_ALLOWED, A_OPEN, A_OPENAT, A_SOCKET, A_EXECVE, A_FORK, A_WRITE, A_KILL,
    A_PTRACE, A_SENDMSG_OTHER, A_RECVMSG_OTHER, A_STAT_BY_PATH, A_X32,
    A_I386, A_PRCTL, A_SETUID, A_CONNECT_UNIX, A_UNLINK,
};

static const struct { enum act a; const char *name; } acts[] = {
    {A_OPEN, "open()"}, {A_OPENAT, "openat()"}, {A_SOCKET, "socket()"},
    {A_EXECVE, "execve()"}, {A_FORK, "clone()/fork"}, {A_WRITE, "write()"},
    {A_KILL, "kill()"}, {A_PTRACE, "ptrace()"},
    {A_SENDMSG_OTHER, "sendmsg() on another descriptor"},
    {A_RECVMSG_OTHER, "recvmsg() on another descriptor"},
    {A_STAT_BY_PATH, "newfstatat() by path"}, {A_X32, "an x32-ABI syscall"},
    {A_I386, "an int 0x80 (32-bit ABI) syscall"}, {A_PRCTL, "prctl()"},
    {A_SETUID, "setuid()"}, {A_CONNECT_UNIX, "connect()"}, {A_UNLINK, "unlink()"},
};

/* Run `a` in a child that has only NO_NEW_PRIVS + the filter. Returns the
 * child's wait status; for A_ALLOWED the child also sends a report. */
static int seccomp_child(enum act a, int *report_ok) {
    int sv[2], other[2], st = 0;
    pid_t pid;
    struct report r;

    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, other);
    pid = fork();
    if (pid == 0) {
        int fd = make_file("scratch"), res = 0;
        struct stat sb;
        char buf[16];
        struct msghdr m;
        long rc = 0;
        int my_pid = getpid();

        close(sv[0]);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
            ps_seccomp_install(sv[1]) < 0)
            _exit(40);
        memset(&m, 0, sizeof(m));

        switch (a) {
        case A_ALLOWED: {
            void *p;
            struct timespec ts;
            int d;

            if (pread(fd, buf, 4, 0) != 4) _exit(41);
            if (lseek(fd, 0, SEEK_SET) != 0) _exit(42);
            if (read(fd, buf, 4) != 4) _exit(43);
            if (fstat(fd, &sb) < 0) _exit(44);
            if (syscall(SYS_newfstatat, fd, "", &sb, AT_EMPTY_PATH) < 0) _exit(45);
            p = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED) _exit(46);
            if (mprotect(p, 4096, PROT_READ) < 0) _exit(47);
            if (munmap(p, 1 << 20) < 0) _exit(48);
            if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) _exit(49);
            if (syscall(SYS_getrandom, buf, 8, 0) != 8) _exit(50);
            d = dup(fd);
            if (d < 0 || close(d) < 0) _exit(51);
            memset(&r, 0, sizeof(r));
            r.pid = my_pid;
            send_report(sv[1], &r);
            _exit(0);
        }
        case A_OPEN:    res = (int)syscall(SYS_open, "/etc/passwd", O_RDONLY); break;
        case A_OPENAT:  res = (int)syscall(SYS_openat, AT_FDCWD, "/etc/passwd", O_RDONLY); break;
        case A_SOCKET:  res = (int)syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0); break;
        case A_EXECVE:  res = (int)syscall(SYS_execve, "/bin/true", NULL, NULL); break;
        case A_FORK:    res = (int)syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0); break;
        case A_WRITE:   res = (int)syscall(SYS_write, 1, "x", 1); break;
        case A_KILL:    res = (int)syscall(SYS_kill, getppid(), 0); break;
        case A_PTRACE:  res = (int)syscall(SYS_ptrace, 0, 0, 0, 0); break;
        case A_SENDMSG_OTHER: res = (int)syscall(SYS_sendmsg, other[1], &m, 0); break;
        case A_RECVMSG_OTHER: res = (int)syscall(SYS_recvmsg, other[1], &m, MSG_DONTWAIT); break;
        case A_STAT_BY_PATH: res = (int)syscall(SYS_newfstatat, AT_FDCWD, "/etc/passwd", &sb, 0); break;
        case A_X32:     res = (int)syscall(SYS_getrandom | PS_X32_BIT, buf, 8, 0); break;
        case A_I386:
            __asm__ volatile("int $0x80" : "=a"(rc) : "0"(20L) : "memory"); /* getpid */
            res = (int)rc;
            break;
        case A_PRCTL:   res = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0); break;
        case A_SETUID:  res = (int)syscall(SYS_setuid, 0); break;
        case A_CONNECT_UNIX: res = (int)syscall(SYS_connect, sv[1], NULL, 0); break;
        case A_UNLINK:  res = (int)syscall(SYS_unlink, "/tmp/nonexistent-x"); break;
        }
        /* Survived a syscall that must have been fatal. */
        (void)res;
        _exit(99);
    }
    close(sv[1]);
    close(other[0]);
    close(other[1]);
    waitpid(pid, &st, 0);
    *report_ok = (a == A_ALLOWED) && recv_report(sv[0], &r);
    close(sv[0]);
    return st;
}

static void test_seccomp_kernel(void) {
    int ok = 0, st;
    bool i386_works;

    printf("\nthe seccomp filter in a real kernel (no root needed):\n");

    st = seccomp_child(A_ALLOWED, &ok);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0 && ok,
          "every syscall the scan needs works, and a report goes out");

    /* Is the 32-bit entry point usable here at all? Only then is the test
     * meaningful; without it the arch check has nothing to catch. */
    {
        pid_t pid = fork();
        if (pid == 0) {
            long rc;
            __asm__ volatile("int $0x80" : "=a"(rc) : "0"(20L) : "memory");
            _exit(rc > 0 ? 0 : 1);
        }
        waitpid(pid, &st, 0);
        i386_works = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    }

    for (size_t i = 0; i < sizeof(acts) / sizeof(acts[0]); i++) {
        char label[120];

        if (acts[i].a == A_I386 && !i386_works) {
            SKIPT("an int 0x80 syscall is killed (32-bit entry not available)");
            continue;
        }
        st = seccomp_child(acts[i].a, &ok);
        snprintf(label, sizeof(label), "%s kills the worker with SIGSYS",
                 acts[i].name);
        CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS, label);
    }
}

/* Whether this process may do what the spawner will do. Decided from the
 * capabilities themselves, never from whether hardening worked: a hardening
 * bug must show up as a FAIL, not hide behind a SKIP. */
static bool have_cap(int cap) {
    struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct d[2];

    if (syscall(SYS_capget, &h, d) < 0) return false;
    return (d[cap / 32].effective >> (cap % 32)) & 1u;
}

static bool can_spawn_hardened(void) {
    return geteuid() == 0 && have_cap(CAP_SETUID) && have_cap(CAP_SETGID) &&
           have_cap(CAP_SETPCAP);
}

/* ---- The full hardening sequence (root) ---- */

static void test_hardening(void) {
    int s;
    pid_t pid;
    struct report r;
    char v[128];

    memset(&r, 0, sizeof(r));
    printf("\nthe hardening sequence (root):\n");

    if (!can_spawn_hardened()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID and CAP_SETPCAP: "
              "credential, capability and rlimit steps not exercised");
        return;
    }

    /* From here on the environment can do it, so any failure is real. */
    pid = spawn_worker(&s, 0, false, 0, WORKER_UID);
    {
        char label[160];
        bool got = recv_report(s, &r);

        snprintf(label, sizeof(label),
                 "an uninjected worker hardens fully (step %d, errno %d)",
                 got ? r.step : -1, got ? r.err : 0);
        CHECK(got && r.step == 0, label);
        close(s);
        wait_exit(pid);
        if (!got || r.step != 0)
            return;
    }

    /* Failure injected at every step. */
    for (int k = 1; k < PS_H_STEP_COUNT; k++) {
        char label[160];
        unsigned want = (1u << (k + 1)) - 2; /* bits 1..k */
        bool got;

        pid = spawn_worker(&s, k, false, 0, WORKER_UID);
        got = recv_report(s, &r);
        snprintf(label, sizeof(label),
                 "step %d failing: that step is reported, later steps never start",
                 k);
        CHECK(got && r.step == k && r.err == EIO && r.ran == want, label);
        snprintf(label, sizeof(label),
                 "step %d failing: no filter is installed, the child exits 1", k);
        CHECK(got && r.seccomp_mode == 0 && wait_exit(pid) == 1, label);
        close(s);
    }

    /* The success path, read back the way the parent will. */
    pid = spawn_worker(&s, 0, true, 0, WORKER_UID);
    CHECK(recv_report(s, &r) && r.step == 0 && r.pid == pid,
          "an uninjected worker reports hardened");
    if (r.step == 0) {
        char want[64];

        snprintf(want, sizeof(want), "%d\t%d\t%d\t%d", WORKER_UID, WORKER_UID,
                 WORKER_UID, WORKER_UID);
        CHECK(status_is(pid, "Uid", want), "real, effective, saved and fs uid are the worker's");
        CHECK(status_is(pid, "Gid", want), "real, effective, saved and fs gid are the worker's");
        CHECK(status_line(pid, "Groups", v, sizeof(v)) && v[0] == '\0',
              "no supplementary groups");
        CHECK(status_is(pid, "CapInh", "0000000000000000"), "CapInh is empty");
        CHECK(status_is(pid, "CapPrm", "0000000000000000"), "CapPrm is empty");
        CHECK(status_is(pid, "CapEff", "0000000000000000"), "CapEff is empty");
        CHECK(status_is(pid, "CapBnd", "0000000000000000"), "CapBnd is empty");
        CHECK(status_is(pid, "CapAmb", "0000000000000000"), "CapAmb is empty");
        CHECK(status_is(pid, "NoNewPrivs", "1"), "NoNewPrivs is 1");
        CHECK(status_is(pid, "Seccomp", "2"), "Seccomp is 2 (filter mode)");
        CHECK(limit_of(pid, "Max file size") == 0, "RLIMIT_FSIZE is 0");
        CHECK(limit_of(pid, "Max open files") == WORKER_NOFILE,
              "RLIMIT_NOFILE is the small configured value");
        CHECK(limit_of(pid, "Max address space") == (1l << 30),
              "RLIMIT_AS is the configured value");
        CHECK(limit_of(pid, "Max cpu time") == 60, "RLIMIT_CPU is the configured value");
        {
            DIR *d;
            char path[64];
            struct dirent *e;
            int n = 0;

            snprintf(path, sizeof(path), "/proc/%d/fd", (int)pid);
            d = opendir(path);
            while (d && (e = readdir(d)))
                if (e->d_name[0] != '.') n++;
            if (d) closedir(d);
            CHECK(n == 1, "the IPC socket is the only open descriptor");
        }

        /* And it still does its job, hardened. */
        {
            struct ps_verdict ver;
            int evil = make_file("..EVIL.."), fine = make_file("harmless");
            int ok = 1;

            for (int i = 0; i < 200; i++) {
                send_req(s, 500 + (uint64_t)i, i % 2 ? &evil : &fine, 1);
                if (!read_reply(s, 500 + (uint64_t)i, &ver) || ver.inconclusive ||
                    (ver.verdict == PS_VERDICT_MALICIOUS) != (i % 2 == 1))
                    ok = 0;
            }
            CHECK(ok, "200 real scans succeed under the full hardening and filter "
                      "(RLIMIT_NOFILE=16)");
            close(evil);
            close(fine);
        }
    }
    close(s);
    CHECK(wait_exit(pid) == 0, "the hardened worker exits 0 when its socket closes");

    /* Wrong spawner pid: the handshake fails closed before the filter. */
    pid = spawn_worker(&s, 0, false, 1, WORKER_UID);
    CHECK(recv_report(s, &r) && r.step == PS_H_PDEATHSIG &&
          !(r.ran & (1u << PS_H_SECCOMP)) && r.seccomp_mode == 0,
          "a worker whose parent is not the expected pid stops before seccomp");
    close(s);
    wait_exit(pid);

    /* uid 0 is refused. */
    pid = spawn_worker(&s, 0, false, 0, 0);
    CHECK(recv_report(s, &r) && r.step == PS_H_CREDENTIALS && r.err == EINVAL,
          "hardening to uid 0 is refused at the credential step");
    close(s);
    wait_exit(pid);
}

/* ---- Parent death ---- */

static void test_pdeathsig(void) {
    int sv[2], st = 0;
    pid_t spawner, w;
    struct report r;

    memset(&r, 0, sizeof(r));
    printf("\nparent death (root):\n");
    if (!can_spawn_hardened()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID and CAP_SETPCAP");
        return;
    }
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);

    spawner = fork();
    if (spawner == 0) {
        pid_t sp = getpid();
        pid_t wk = fork();
        if (wk == 0) {
            struct ps_harden_cfg cfg = {
                .uid = WORKER_UID, .gid = WORKER_UID, .ipc_fd = sv[1],
                .log_fd = -1, .expect_ppid = sp, .as_bytes = 1ull << 30,
                .cpu_seconds = 60, .nofile = WORKER_NOFILE,
            };
            struct report rr;
            int my_pid = getpid();
            memset(&rr, 0, sizeof(rr));
            rr.step = ps_worker_harden(&cfg);
            rr.pid = my_pid;
            send_report(sv[1], &rr);
            if (rr.step != 0) _exit(1);
            _exit(ps_worker_run(sv[1], scan_cb, NULL) == 0 ? 0 : 9);
        }
        for (;;) pause();
    }
    close(sv[1]);
    if (!recv_report(sv[0], &r) || r.step != 0) {
        CHECK(false, "the worker under the spawner hardens fully");
        kill(spawner, SIGKILL);
        waitpid(spawner, NULL, 0);
        return;
    }
    w = r.pid;
    kill(spawner, SIGKILL);
    waitpid(spawner, NULL, 0);
    /* The worker is now our child (subreaper) and must have been killed. */
    {
        pid_t got = waitpid(w, &st, 0);
        CHECK(got == w && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL,
              "killing the spawner kills its hardened worker with SIGKILL");
    }
    close(sv[0]);
}

int main(void) {
    alarm(180);
    printf("privsep worker: hardening and seccomp against the real kernel\n");
    test_seccomp_kernel();
    test_hardening();
    test_pdeathsig();
    SUMMARY("privsep_worker (kernel)");
}
EOF

CC="${CC:-gcc}"
rc=0

echo "### building (ASan+UBSan: BPF program + IPC loop) ###"
"$CC" -std=gnu11 -Wall -Wextra -Werror -O1 -g -fno-omit-frame-pointer \
    -fsanitize=address,undefined -fno-sanitize-recover=undefined \
    -I"$SRC_DIR" -I"$BUILD_DIR" -o "$BUILD_DIR/ipc" "$BUILD_DIR/ipc.c" || exit 1

echo "### building (plain -O2: hardening + seccomp in the kernel) ###"
"$CC" -std=gnu11 -Wall -Wextra -Werror -O2 -fstack-protector-strong \
    -I"$SRC_DIR" -I"$BUILD_DIR" -o "$BUILD_DIR/hard" "$BUILD_DIR/hard.c" || exit 1

echo
"$BUILD_DIR/ipc" || rc=1
echo
"$BUILD_DIR/hard" || rc=1

exit $rc
