#!/usr/bin/env bash
#
# tests/test_privsep_lockdown.sh - coverage for userspace/avd/privsep_lockdown.h,
# the spawner's own lockdown (#103, Stage 1f; see docs/privilege-separation.md,
# "The spawner" and "Seccomp filters stack").
#
# Two binaries, both against the production header compiled standalone (same
# arrangement as test_privsep_worker.sh):
#
#   bpf     ASan+UBSan. The spawner's seccomp program, checked exhaustively
#           with a small classic-BPF interpreter against an independent
#           statement of what the spawner may do: every syscall number, every
#           argument-checked call (prctl options, kill signals, clone flags,
#           socketpair domains, prlimit64 target), the architecture and x32
#           checks, the superset property (everything the worker filter allows
#           is allowed here too), and the label assembler's failure modes.
#   kern    Plain build, real kernel. The same filter installed in forked
#           children (no root needed): the syscalls the spawner uses work,
#           including a real glibc fork(), and the ones it must never make
#           kill the process with SIGSYS. As root: a real spawner's state read
#           back from /proc/<pid>/status the way an auditor would, a failure
#           injected at every lockdown step, a spawner that cannot lock itself
#           down serving nothing, and the spawner dying with its parent. Without
#           root those print SKIP, never PASS:
#             sudo tests/test_privsep_lockdown.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${PS_SRC_DIR:-$REPO_ROOT/userspace/avd}"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_privsep_lockdown.XXXXXX")" || exit 1

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>

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
#endif
EOF

# ---------------------------------------------------------------------------
# bpf: the program, run in userspace (ASan+UBSan)
# ---------------------------------------------------------------------------
cat > "$BUILD_DIR/bpf.c" <<'EOF'
#define _GNU_SOURCE
#include "privsep_lockdown.h"
#include "common.h"

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
        case BPF_ALU | BPF_AND | BPF_K:
            A &= i->k;
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

static struct sock_filter SP[PS_ASM_MAX];
static size_t SPN;

static bool ok_args(const struct sock_filter *p, size_t n, uint32_t arch, int nr,
                    uint64_t a0, uint64_t a1, uint64_t a3) {
    struct seccomp_data d;

    memset(&d, 0, sizeof(d));
    d.arch = arch;
    d.nr = nr;
    d.args[0] = a0;
    d.args[1] = a1;
    d.args[3] = a3;
    return bpf_run(p, n, &d) == SECCOMP_RET_ALLOW;
}

static bool sp_ok(int nr, uint64_t a0, uint64_t a1, uint64_t a3) {
    return ok_args(SP, SPN, AUDIT_ARCH_X86_64, nr, a0, a1, a3);
}

/* An independent statement of what the spawner may do with NO argument
 * constraint, deliberately not derived from the header's tables: the worker's
 * twenty-one plus what only the spawner needs. */
static bool want_plain(int nr) {
    switch (nr) {
    /* the worker list */
    case SYS_read: case SYS_pread64: case SYS_lseek: case SYS_fstat:
    case SYS_fstatfs:
    case SYS_mmap: case SYS_munmap: case SYS_mprotect: case SYS_mremap:
    case SYS_brk: case SYS_madvise: case SYS_futex: case SYS_dup:
    case SYS_close: case SYS_clock_gettime: case SYS_clock_nanosleep:
    case SYS_rt_sigaction: case SYS_rt_sigprocmask: case SYS_rt_sigreturn:
    case SYS_getrandom: case SYS_exit_group:
    /* only the spawner */
    case SYS_poll: case SYS_wait4: case SYS_getpid: case SYS_getppid:
    case SYS_recvmsg: case SYS_sendmsg: case SYS_set_robust_list:
    case SYS_close_range:
    case SYS_setgroups: case SYS_setresgid: case SYS_setresuid:
    case SYS_setuid: case SYS_setgid:
    case SYS_getresuid: case SYS_getresgid: case SYS_getgroups:
    case SYS_capget: case SYS_capset:
        return true;
    default:
        return false;
    }
}

/* PR_SET_PDEATHSIG (1) only with SIGKILL, argument checked whole; the rest of
 * the options do not look at it. */
static bool want_prctl(uint32_t opt, uint64_t a1) {
    if (opt == 1) return a1 == 9;
    return opt == 2 /* PR_GET_PDEATHSIG */ ||
           opt == 22 /* PR_SET_SECCOMP */ || opt == 23 /* PR_CAPBSET_READ */ ||
           opt == 24 /* PR_CAPBSET_DROP */ || opt == 38 /* PR_SET_NO_NEW_PRIVS */ ||
           opt == 39 /* PR_GET_NO_NEW_PRIVS */;
}

/* fork() as glibc issues it, and nothing else. */
static bool want_clone(uint64_t flags) {
    if (flags >> 32) return false;
    return ((uint32_t)flags & ~(0x00200000u | 0x01000000u)) == 17u; /* SIGCHLD */
}

static void test_build(void) {
    struct ps_asm a;
    size_t n;
    int bad = 0;

    printf("\nthe spawner's seccomp program:\n");
    n = ps_seccomp_build_spawner(&a);
    memcpy(SP, a.prog, sizeof(SP));
    SPN = n;
    printf("  (%zu instructions of %d)\n", n, PS_ASM_MAX);
    CHECK(n > 0 && n <= PS_ASM_MAX, "builds, and fits the budget");
    if (n == 0) return;

    for (size_t i = 0; i < n; i++)
        if ((SP[i].code & 7) == BPF_JMP &&
            (i + 1 + SP[i].jt >= n || i + 1 + SP[i].jf >= n))
            bad++;
    CHECK(bad == 0, "every jump lands inside the program");
    CHECK(SP[n - 1].code == (BPF_RET | BPF_K) &&
              SP[n - 1].k == SECCOMP_RET_KILL_PROCESS,
          "the last instruction is KILL_PROCESS, so nothing falls off into ALLOW");
    CHECK(PS_SPAWNER_CAPS == 0x1e0ull,
          "the capabilities kept are exactly SETUID, SETGID, SETPCAP and KILL");
}

static void test_exhaustive(void) {
    struct sock_filter wk[PS_BPF_MAX];
    const int FD = 7;
    size_t wn = ps_seccomp_build(wk, FD);
    int bad = 0, plain = 0, super_bad = 0, super_seen = 0;
    static const uint64_t a0s[] = {0, FD, FD + 1, 3, ~0ull, (1ull << 32) | FD};
    static const uint64_t a1s[] = {0, 9, 15};
    static const uint64_t a3s[] = {0, AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW,
                                   AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW};

    printf("\nwhat the spawner may and may not do:\n");

    /* With every argument zero: the plain list, plus prlimit64 (pid 0 is
     * "myself"), and nothing else. */
    for (int nr = 0; nr < 1024; nr++) {
        bool want = want_plain(nr) || nr == SYS_prlimit64;
        if (want_plain(nr)) plain++;
        if (sp_ok(nr, 0, 0, 0) != want) bad++;
    }
    CHECK(bad == 0, "with zero arguments exactly the allowlist is allowed, for 0..1023");
    CHECK(plain == 39, "all thirty-nine unconditional entries are exercised");

    /* The unconditional ones stay allowed whatever the arguments. */
    bad = 0;
    for (int nr = 0; nr < 1024; nr++) {
        if (!want_plain(nr)) continue;
        for (size_t i = 0; i < sizeof(a0s) / sizeof(a0s[0]); i++)
            for (size_t j = 0; j < sizeof(a3s) / sizeof(a3s[0]); j++)
                if (!sp_ok(nr, a0s[i], 0, a3s[j])) bad++;
    }
    CHECK(bad == 0, "the unconditional entries do not depend on their arguments");

    /* The superset property: whatever the WORKER filter allows, with any of
     * these arguments, must be allowed here, or every worker is killed under
     * the spawner's filter before it can report ready. */
    CHECK(wn > 0, "the worker filter builds (for the comparison)");
    for (int nr = 0; nr < 1024; nr++)
        for (size_t i = 0; i < sizeof(a0s) / sizeof(a0s[0]); i++)
            for (size_t k = 0; k < sizeof(a1s) / sizeof(a1s[0]); k++)
                for (size_t j = 0; j < sizeof(a3s) / sizeof(a3s[0]); j++)
                    if (ok_args(wk, wn, AUDIT_ARCH_X86_64, nr, a0s[i], a1s[k], a3s[j])) {
                        super_seen++;
                        if (!sp_ok(nr, a0s[i], a1s[k], a3s[j])) super_bad++;
                    }
    CHECK(super_seen > 0 && super_bad == 0,
          "every call the worker filter allows is allowed here too (a superset)");

    /* Things a compromised spawner must not be able to do, with every
     * argument shape that might help. None of these has an argument check. */
    {
        static const int never[] = {
            SYS_open, SYS_openat, SYS_creat, SYS_socket, SYS_connect, SYS_bind,
            SYS_listen, SYS_accept, SYS_accept4, SYS_sendto, SYS_recvfrom,
            SYS_sendmmsg, SYS_recvmmsg, SYS_execve, SYS_execveat, SYS_clone3,
            SYS_fork, SYS_vfork, SYS_ptrace, SYS_tgkill, SYS_tkill, SYS_write,
            SYS_writev, SYS_pwrite64, SYS_unlink, SYS_unlinkat, SYS_rename,
            SYS_mkdir, SYS_chmod, SYS_chown, SYS_mount, SYS_umount2,
            SYS_truncate, SYS_ftruncate, SYS_fallocate, SYS_io_uring_setup,
            SYS_bpf, SYS_perf_event_open, SYS_process_vm_writev,
            SYS_process_vm_readv, SYS_memfd_create, SYS_userfaultfd,
            SYS_seccomp, SYS_chroot, SYS_unshare, SYS_setns, SYS_pivot_root,
            SYS_ioctl, SYS_pipe, SYS_dup2, SYS_dup3, SYS_fcntl, SYS_getdents64,
            SYS_readlink, SYS_stat, SYS_lstat, SYS_access, SYS_shutdown,
            SYS_signalfd, SYS_signalfd4, SYS_setreuid, SYS_setregid,
            SYS_setfsuid, SYS_setfsgid, SYS_setresuid + 1000, SYS_personality,
            SYS_init_module, SYS_finit_module, SYS_kexec_load, SYS_reboot,
            SYS_settimeofday, SYS_clock_settime, SYS_sethostname, SYS_syslog,
            SYS_acct, SYS_swapon, SYS_setrlimit, SYS_getrlimit, SYS_getuid,
            SYS_gettid, SYS_sched_setaffinity, SYS_keyctl, SYS_add_key,
            SYS_mknod, SYS_symlink, SYS_link, SYS_linkat, SYS_open_by_handle_at,
        };
        bad = 0;
        for (size_t i = 0; i < sizeof(never) / sizeof(never[0]); i++) {
            if (never[i] >= 1024) continue; /* the +1000 sentinel above */
            for (size_t a = 0; a < sizeof(a0s) / sizeof(a0s[0]); a++)
                for (size_t b = 0; b < sizeof(a1s) / sizeof(a1s[0]); b++)
                    for (size_t c = 0; c < sizeof(a3s) / sizeof(a3s[0]); c++)
                        if (sp_ok(never[i], a0s[a], a1s[b], a3s[c])) bad++;
        }
        CHECK(bad == 0, "no forbidden syscall is allowed, whatever the arguments");
    }

    /* Architecture and ABI. */
    bad = 0;
    for (int nr = 0; nr < 1024; nr++) {
        if (ok_args(SP, SPN, AUDIT_ARCH_I386, nr, 0, 0, AT_EMPTY_PATH)) bad++;
        if (ok_args(SP, SPN, AUDIT_ARCH_AARCH64, nr, 0, 0, AT_EMPTY_PATH)) bad++;
        if (ok_args(SP, SPN, 0, nr, 0, 0, AT_EMPTY_PATH)) bad++;
        if (sp_ok(nr | PS_X32_BIT, 0, 0, AT_EMPTY_PATH)) bad++;
    }
    CHECK(bad == 0, "other architectures and the x32 ABI are always killed");
}

static void test_arguments(void) {
    int bad;

    printf("\nthe argument checks:\n");

    /* newfstatat: the filter checks only the AT_EMPTY_PATH flag, as the
     * worker's does; it cannot see the pathname (docs, "Seccomp allowlist"). */
    CHECK(sp_ok(SYS_newfstatat, 5, 0, AT_EMPTY_PATH) &&
              sp_ok(SYS_newfstatat, 5, 0, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW),
          "newfstatat(AT_EMPTY_PATH) is allowed");
    CHECK(!sp_ok(SYS_newfstatat, 5, 0, 0) &&
              !sp_ok(SYS_newfstatat, 5, 0, AT_SYMLINK_NOFOLLOW),
          "newfstatat without AT_EMPTY_PATH is killed");

    /* prctl: exactly seven options, everything else killed. */
    bad = 0;
    for (uint32_t opt = 0; opt < 4096; opt++) {
        static const uint64_t a1s_prctl[] = {0, 1, 2, 9, 15, 64, 9ull | (1ull << 32),
                                             1ull << 32, ~0ull};
        for (size_t k = 0; k < sizeof(a1s_prctl) / sizeof(a1s_prctl[0]); k++)
            if (sp_ok(SYS_prctl, opt, a1s_prctl[k], 0) != want_prctl(opt, a1s_prctl[k])) bad++;
    }
    {
        static const uint32_t odd[] = {0x59616d61 /* PR_SET_PTRACER */, 0x80000000u,
                                       0xffffffffu, 0x7fffffffu, 4 /* DUMPABLE */,
                                       15 /* SET_NAME */, 35 /* SET_MM */,
                                       36 /* CHILD_SUBREAPER */, 8 /* KEEPCAPS */,
                                       28 /* SECUREBITS */, 47 /* CAP_AMBIENT */};
        for (size_t i = 0; i < sizeof(odd) / sizeof(odd[0]); i++)
            if (sp_ok(SYS_prctl, odd[i], 0, 0) != want_prctl(odd[i], 0)) bad++;
    }
    CHECK(bad == 0, "prctl is allowed for exactly the seven options in use");
    CHECK(sp_ok(SYS_prctl, 38, 1, 0) && sp_ok(SYS_prctl, 22, 2, 0) &&
              sp_ok(SYS_prctl, 24, 20, 0),
          "the options hardening uses pass: NO_NEW_PRIVS, SET_SECCOMP, CAPBSET_DROP");

    /* The parent-death signal can be set to SIGKILL (hardening does) and to
     * nothing else: clearing it would let a compromised spawner outlive avd. */
    bad = 0;
    for (uint64_t sig = 0; sig < 130; sig++)
        if (sp_ok(SYS_prctl, 1 /* PR_SET_PDEATHSIG */, sig, 0) != (sig == 9)) bad++;
    CHECK(bad == 0 && sp_ok(SYS_prctl, 1, 9, 0),
          "PR_SET_PDEATHSIG is allowed only with SIGKILL");
    CHECK(!sp_ok(SYS_prctl, 1, 0, 0) && !sp_ok(SYS_prctl, 1, 9ull | (1ull << 32), 0),
          "clearing the parent-death signal, or hiding a bit above SIGKILL, is killed");
    CHECK(sp_ok(SYS_prctl, 2 /* PR_GET_PDEATHSIG */, 0, 0),
          "reading it back (PR_GET_PDEATHSIG) is still allowed");

    /* kill: only SIGKILL, on any pid. */
    bad = 0;
    for (uint64_t sig = 0; sig < 130; sig++)
        for (uint64_t pid = 0; pid < 3; pid++)
            if (sp_ok(SYS_kill, pid * 1000, sig, 0) != (sig == 9)) bad++;
    CHECK(bad == 0, "kill is allowed only with SIGKILL");

    /* clone: fork's flags and nothing else. */
    bad = 0;
    {
        static const uint64_t f[] = {
            17, 17 | 0x00200000u, 17 | 0x01000000u, 17 | 0x00200000u | 0x01000000u,
            0, 0x00200000u, 0x01000000u, 18, 1, 16,
            17 | 0x00000100u,  /* CLONE_VM */
            17 | 0x00010000u,  /* CLONE_THREAD */
            17 | 0x00020000u,  /* CLONE_NEWNS */
            17 | 0x10000000u,  /* CLONE_NEWUSER */
            17 | 0x40000000u,  /* CLONE_NEWNET */
            17 | 0x00004000u,  /* CLONE_VFORK */
            17 | 0x00002000u,  /* CLONE_PTRACE */
            17 | 0x00008000u,  /* CLONE_PARENT */
            17ull | (1ull << 32), 17ull | (1ull << 33), (1ull << 32),
            0xffffffffffffffffull,
        };
        for (size_t i = 0; i < sizeof(f) / sizeof(f[0]); i++)
            if (sp_ok(SYS_clone, f[i], 0, 0) != want_clone(f[i])) bad++;
        for (int b = 0; b < 64; b++) /* every single bit added to a fork */
            if (sp_ok(SYS_clone, 17ull | (1ull << b), 0, 0) !=
                want_clone(17ull | (1ull << b)))
                bad++;
    }
    CHECK(bad == 0, "clone is allowed only with exactly fork()'s flags");
    CHECK(sp_ok(SYS_clone, 0x01200011u, 0, 0), "glibc's fork flags (0x1200011) pass");
    CHECK(!sp_ok(SYS_clone, 0x00010011u, 0, 0) && !sp_ok(SYS_clone, 0x10000011u, 0, 0),
          "a thread clone and a CLONE_NEWUSER clone are killed");

    /* socketpair: unix only. prlimit64: only on itself. */
    bad = 0;
    for (uint64_t d = 0; d < 64; d++)
        if (sp_ok(SYS_socketpair, d, 0, 0) != (d == 1)) bad++;
    CHECK(bad == 0, "socketpair is allowed only for AF_UNIX");
    bad = 0;
    for (uint64_t pid = 0; pid < 70000; pid += (pid < 70 ? 1 : 997))
        if (sp_ok(SYS_prlimit64, pid, 0, 0) != (pid == 0)) bad++;
    CHECK(bad == 0, "prlimit64 is allowed only with pid 0 (this process)");
}

/* The label assembler must fail closed. */
static void test_assembler(void) {
    struct ps_asm a;

    printf("\nthe label assembler:\n");

    ps_asm_init(&a);
    ps_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, 1, PSL_ALLOW, PSL_NONE);
    ps_asm_stmt(&a, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    ps_asm_stmt(&a, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    ps_asm_bind(&a, PSL_ALLOW);
    ps_asm_stmt(&a, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    CHECK(ps_asm_finish(&a) == 4 && a.prog[0].jt == 2 && a.prog[0].jf == 0,
          "a forward jump resolves to the right offset");

    ps_asm_init(&a);
    ps_asm_bind(&a, PSL_ALLOW);
    ps_asm_stmt(&a, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    ps_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, 1, PSL_ALLOW, PSL_NONE);
    CHECK(ps_asm_finish(&a) == 0, "a backward jump is refused");

    ps_asm_init(&a);
    ps_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, 1, PSL_KILL, PSL_NONE);
    ps_asm_stmt(&a, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    CHECK(ps_asm_finish(&a) == 0, "a jump to a label never bound is refused");

    ps_asm_init(&a);
    ps_asm_bind(&a, PSL_ALLOW);
    ps_asm_bind(&a, PSL_ALLOW);
    ps_asm_stmt(&a, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    CHECK(ps_asm_finish(&a) == 0, "binding a label twice is refused");

    ps_asm_init(&a);
    for (int i = 0; i < PS_ASM_MAX + 1; i++)
        ps_asm_stmt(&a, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    CHECK(a.n == PS_ASM_MAX && ps_asm_finish(&a) == 0, "overflowing the program is refused");

    ps_asm_init(&a);
    ps_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, 1, 99, PSL_NONE);
    ps_asm_stmt(&a, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    CHECK(ps_asm_finish(&a) == 0, "a label id that does not exist is refused");
}

int main(void) {
    printf("privsep lockdown: the spawner's seccomp program (ASan+UBSan)\n");
    test_build();
    if (SPN == 0) SUMMARY("privsep_lockdown (bpf)");
    test_exhaustive();
    test_arguments();
    test_assembler();
    SUMMARY("privsep_lockdown (bpf)");
}
EOF

# ---------------------------------------------------------------------------
# kern: the real kernel
# ---------------------------------------------------------------------------
cat > "$BUILD_DIR/kern.c" <<'EOF'
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include "privsep_spawner.h"
#include "common.h"

#define WORKER_UID 65534

static void scan_cb(int fd, void *ctx, struct ps_reply *rep) {
    char b[8];

    (void)ctx;
    rep->inconclusive = 0;
    rep->verdict = PS_VERDICT_CLEAN;
    if (pread(fd, b, sizeof(b), 0) >= 4 && memcmp(b, "EVIL", 4) == 0) {
        rep->verdict = PS_VERDICT_MALICIOUS;
        snprintf(rep->rule_name, sizeof(rep->rule_name), "%s", "Test:evil");
        rep->score = 5;
    }
}

/* ---- The filter in a real kernel (no root needed) ---- */

enum act {
    A_BASIC, A_FORK,
    A_OPEN, A_OPENAT, A_SOCKET, A_EXECVE, A_PTRACE, A_WRITE, A_THREAD_CLONE,
    A_NEWUSER_CLONE, A_KILL_TERM, A_PRCTL_DUMPABLE, A_SIGNALFD, A_MOUNT,
    A_UNSHARE, A_SOCKPAIR_INET, A_PRLIMIT_OTHER, A_CLONE3, A_MEMFD, A_BPF,
    A_PDEATHSIG_CLEAR,
};

static const struct { enum act a; const char *name; } forbidden[] = {
    {A_OPEN, "open()"}, {A_OPENAT, "openat()"}, {A_SOCKET, "socket(AF_INET)"},
    {A_EXECVE, "execve()"}, {A_PTRACE, "ptrace()"}, {A_WRITE, "write()"},
    {A_THREAD_CLONE, "a thread clone"}, {A_NEWUSER_CLONE, "clone(CLONE_NEWUSER)"},
    {A_KILL_TERM, "kill(pid, SIGTERM)"}, {A_PRCTL_DUMPABLE, "prctl(PR_SET_DUMPABLE)"},
    {A_SIGNALFD, "signalfd4()"}, {A_MOUNT, "mount()"}, {A_UNSHARE, "unshare()"},
    {A_SOCKPAIR_INET, "socketpair(AF_INET)"}, {A_PRLIMIT_OTHER, "prlimit64 on another pid"},
    {A_CLONE3, "clone3()"}, {A_MEMFD, "memfd_create()"}, {A_BPF, "bpf()"},
    {A_PDEATHSIG_CLEAR, "prctl(PR_SET_PDEATHSIG, 0) (clearing it)"},
};

/* Install the spawner's filter in a forked child, perform `a`, report. A
 * forbidden act never returns; an allowed one exits 0 only if every call
 * behaved. Exit 90 means the filter could not be installed. */
static int filter_child(enum act a) {
    pid_t pid = fork();
    int st = 0;

    if (pid < 0) return -1;
    if (pid == 0) {
        long r;

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) _exit(90);
        if (ps_seccomp_install_spawner() < 0) _exit(90);

        switch (a) {
        case A_BASIC: {
            struct rlimit rl;
            int sv[2], s2 = 0;
            sigset_t m;
            struct pollfd p = {.fd = -1};
            struct timespec ts;
            char c = 'x', got = 0;

            if (getpid() <= 0 || getppid() < 0) _exit(1);
            if (poll(&p, 1, 0) < 0) _exit(2);
            if (waitpid(-1, &s2, WNOHANG) != -1 || errno != ECHILD) _exit(3);
            if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) _exit(4);
            if (kill(999999999, SIGKILL) != -1 || errno != ESRCH) _exit(5); /* allowed, finds nobody */
            if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) _exit(6);
            if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0) _exit(13); /* what hardening sets */
            if (getrlimit(RLIMIT_NOFILE, &rl) < 0) _exit(7);   /* prlimit64 on itself */
            if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) _exit(8);
            /* sendmsg/recvmsg, which is what the spawner uses: glibc's send()
             * and recv() are sendto/recvfrom, which it never calls. */
            {
                struct iovec iv = {.iov_base = &got, .iov_len = 1};
                struct msghdr mh;

                memset(&mh, 0, sizeof(mh));
                mh.msg_iov = &iv;
                mh.msg_iovlen = 1;
                if (ps_sendmsg_fd(sv[0], &c, 1, -1, 0) < 0) _exit(9);
                if (recvmsg(sv[1], &mh, 0) != 1 || got != 'x') _exit(12);
            }
            close(sv[0]);
            close(sv[1]);
            if (sigprocmask(SIG_BLOCK, NULL, &m) < 0) _exit(10);
            (void)!setuid(0); /* hardening probes it; must be callable (it fails for a non-root caller) */
            _exit(0);
        }
        case A_FORK: {
            /* glibc's own fork(): the flags, the child's set_robust_list, the
             * parent's wait4. */
            pid_t c = fork();
            int s2 = 0;

            if (c < 0) _exit(1);
            if (c == 0) _exit(7);
            if (waitpid(c, &s2, 0) != c || !WIFEXITED(s2) || WEXITSTATUS(s2) != 7) _exit(2);
            _exit(0);
        }
        case A_OPEN:    r = syscall(SYS_open, "/dev/null", O_RDONLY); break;
        case A_OPENAT:  r = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY); break;
        case A_SOCKET:  r = syscall(SYS_socket, AF_INET, SOCK_STREAM, 0); break;
        case A_EXECVE:  r = syscall(SYS_execve, "/bin/true", NULL, NULL); break;
        case A_PTRACE:  r = syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0); break;
        case A_WRITE:   r = syscall(SYS_write, 1, "x", 1); break;
        case A_THREAD_CLONE:
            r = syscall(SYS_clone, CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                                       CLONE_THREAD | CLONE_SYSVSEM, 0, 0, 0, 0);
            break;
        case A_NEWUSER_CLONE:
            r = syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0);
            break;
        case A_KILL_TERM:    r = syscall(SYS_kill, 999999999, SIGTERM); break;
        case A_PRCTL_DUMPABLE: r = syscall(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0); break;
        case A_SIGNALFD:     r = syscall(SYS_signalfd4, -1, NULL, 8, 0); break;
        case A_MOUNT:        r = syscall(SYS_mount, "none", "/", "tmpfs", 0, NULL); break;
        case A_UNSHARE:      r = syscall(SYS_unshare, CLONE_NEWNS); break;
        case A_SOCKPAIR_INET: {
            int sv[2];
            r = syscall(SYS_socketpair, AF_INET, SOCK_STREAM, 0, sv);
            break;
        }
        case A_PRLIMIT_OTHER: r = syscall(SYS_prlimit64, 1, RLIMIT_NOFILE, NULL, NULL); break;
        case A_CLONE3:       r = syscall(SYS_clone3, NULL, 0); break;
        case A_MEMFD:        r = syscall(SYS_memfd_create, "x", 0); break;
        case A_BPF:          r = syscall(SYS_bpf, 0, NULL, 0); break;
        case A_PDEATHSIG_CLEAR: r = syscall(SYS_prctl, PR_SET_PDEATHSIG, 0, 0, 0, 0); break;
        default:             r = 0; break;
        }
        _exit(r == 0 ? 0 : 91); /* a forbidden call that returned: not killed */
    }
    if (waitpid(pid, &st, 0) != pid) return -1;
    return st;
}

static void test_filter_kernel(void) {
    int st;

    printf("\nthe spawner's filter in a real kernel (no root needed):\n");

    st = filter_child(A_BASIC);
    if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) {
        if (WIFSIGNALED(st))
            printf("    killed by signal %d (SIGSYS is %d)\n", WTERMSIG(st), SIGSYS);
        else
            printf("    exited %d (the step number in filter_child)\n", WEXITSTATUS(st));
    }
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "what the spawner's loop uses works (poll, wait4, kill, prlimit64, socketpair, sendmsg)");
    st = filter_child(A_FORK);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "a real glibc fork() works, child and wait included");

    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
        char label[120];

        st = filter_child(forbidden[i].a);
        snprintf(label, sizeof(label), "%s kills the spawner with SIGSYS",
                 forbidden[i].name);
        CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS, label);
    }
}

/* ---- Root: the real thing ---- */

static bool have_cap(int cap) {
    struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct d[2];

    if (syscall(SYS_capget, &h, d) < 0) return false;
    return (d[cap / 32].effective >> (cap % 32)) & 1u;
}

/* Decided from the capabilities themselves, never from whether the lockdown
 * worked: a lockdown bug must show up as a FAIL, not hide behind a SKIP. */
static bool can_lock_down(void) {
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

static struct ps_spawner_cfg base_cfg(void) {
    struct ps_spawner_cfg c;

    memset(&c, 0, sizeof(c));
    c.harden.uid = WORKER_UID;
    c.harden.gid = WORKER_UID;
    c.harden.as_bytes = 1ull << 30;
    c.harden.cpu_seconds = 60;
    c.harden.nofile = 16;
    c.scan = scan_cb;
    c.startup_timeout_ms = 5000;
    return c;
}

/* SPAWN and wait for the answer. True only for a READY with the right id. */
static bool spawn_one(int ctl, uint64_t rid, struct ps_ctl_msg *out, int *wfd) {
    struct ps_ctl_msg m;
    struct pollfd p = {.fd = ctl, .events = POLLIN};
    int fd = -1;

    ps_ctl_msg_init(&m, PS_MSG_SPAWN);
    m.request_id = rid;
    if (ps_ctl_send(ctl, &m, -1) < 0) return false;
    if (poll(&p, 1, 10000) <= 0) return false;
    if (ps_ctl_recv(ctl, PS_FROM_SPAWNER, 0, out, &fd) != PS_CTL_OK) return false;
    if (out->type != PS_MSG_READY || out->request_id != rid) {
        if (fd >= 0) close(fd);
        return false;
    }
    *wfd = fd;
    return true;
}

static bool roundtrip(int w, uint64_t rid, const char *content, struct ps_verdict *v) {
    char path[] = "/tmp/av_lockdown_XXXXXX";
    int fd = mkstemp(path);
    struct ps_request rq;
    unsigned char buf[sizeof(struct ps_reply) + 8];
    ssize_t n;

    if (fd < 0) return false;
    unlink(path);
    if (write(fd, content, strlen(content)) < 0) { close(fd); return false; }
    ps_request_init(&rq, rid);
    if (ps_sendmsg_fd(w, &rq, sizeof(rq), fd, 0) < 0) { close(fd); return false; }
    close(fd);
    n = recv(w, buf, sizeof(buf), 0);
    return n > 0 && ps_reply_validate(buf, (size_t)n, rid, v);
}

/* Close the channel, wait for the spawner and sweep up what it orphaned. */
static int stop_spawner(int ctl, pid_t sp) {
    int st = 0;

    close(ctl);
    if (waitpid(sp, &st, 0) != sp) st = -1;
    for (int i = 0; i < 20; i++) {
        while (waitpid(-1, NULL, WNOHANG) > 0) {
        }
        usleep(25 * 1000);
    }
    return st;
}

static void test_spawner_state(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    struct ps_ctl_msg r;
    struct ps_verdict v;
    char want[32];
    int ctl = -1, w = -1;
    pid_t sp = 0;
    bool started;

    printf("\na real spawner, read back from /proc (root):\n");
    if (!can_lock_down()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID, CAP_SETPCAP and CAP_KILL");
        return;
    }
    ps_test_fail_step = 0;
    ps_test_lock_fail_step = 0;
    started = ps_spawner_start(&cfg, &ctl, &sp) == 0;
    CHECK(started, "the spawner starts");
    if (!started) return; /* ctl and sp are not set on failure */
    /* A reply proves the spawner is past its lockdown and in its loop. */
    CHECK(spawn_one(ctl, 1, &r, &w), "a locked-down spawner still spawns a hardened worker");
    if (w < 0) { stop_spawner(ctl, sp); return; }

    snprintf(want, sizeof(want), "%016llx", (unsigned long long)PS_SPAWNER_CAPS);
    CHECK(field_is(sp, "Uid:", "0\t0\t0\t0"), "it still runs as root (it has to change uids)");
    CHECK(field_is(sp, "CapEff:", want) && field_is(sp, "CapPrm:", want),
          "effective and permitted: SETUID, SETGID, SETPCAP, KILL and nothing else");
    CHECK(field_is(sp, "CapInh:", "0000000000000000") &&
              field_is(sp, "CapAmb:", "0000000000000000"),
          "inheritable and ambient are empty");
    CHECK(field_is(sp, "CapBnd:", want), "the bounding set is cut to the same four");
    CHECK(field_is(sp, "NoNewPrivs:", "1") && field_is(sp, "Seccomp:", "2"),
          "NoNewPrivs is 1 and a seccomp filter is installed");

    /* And the worker it made is still fully hardened under the stacked
     * filters: nothing it inherited loosened anything. */
    {
        char ids[64];

        snprintf(ids, sizeof(ids), "%d\t%d\t%d\t%d", WORKER_UID, WORKER_UID, WORKER_UID, WORKER_UID);
        CHECK(field_is(r.pid, "Uid:", ids) && field_is(r.pid, "Gid:", ids),
              "the worker runs as the dedicated user");
        CHECK(field_is(r.pid, "CapEff:", "0000000000000000") &&
                  field_is(r.pid, "CapPrm:", "0000000000000000") &&
                  field_is(r.pid, "CapBnd:", "0000000000000000"),
              "the worker's capability sets are all empty");
        CHECK(field_is(r.pid, "NoNewPrivs:", "1") && field_is(r.pid, "Seccomp:", "2"),
              "the worker has NoNewPrivs and a filter");
    }
    CHECK(roundtrip(w, 77, "EVIL bytes", &v) && v.verdict == PS_VERDICT_MALICIOUS &&
              strcmp(v.rule_name, "Test:evil") == 0,
          "the worker convicts under both filters");
    CHECK(roundtrip(w, 78, "clean", &v) && v.verdict == PS_VERDICT_CLEAN && !v.inconclusive,
          "and clears under both filters");
    /* Close the channel first, with the worker's socket still open. The other
     * order lets the worker exit on EOF while the spawner reports it on a
     * channel main closes a moment later; a failed send ends the spawner with
     * status 1 by design, which would make this check racy, not wrong. */
    {
        int st = stop_spawner(ctl, sp);

        close(w);
        if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0))
            printf("    spawner status: %s %d\n", WIFSIGNALED(st) ? "signal" : "exit",
                   WIFSIGNALED(st) ? WTERMSIG(st) : WEXITSTATUS(st));
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
              "closing the channel ends the locked-down spawner in an orderly way");
    }
}

static void test_failure_injection(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    bool all = true;

    printf("\nlockdown failure at each step (root):\n");
    if (!can_lock_down()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID, CAP_SETPCAP and CAP_KILL");
        return;
    }
    for (int k = 1; k < PS_L_STEP_COUNT; k++) {
        struct ps_ctl_msg m;
        int ctl, fd = -1, st = 0;
        pid_t sp;
        bool good;

        ps_test_lock_fail_step = k; /* inherited by the spawner */
        if (ps_spawner_start(&cfg, &ctl, &sp) != 0) { all = false; continue; }
        ps_test_lock_fail_step = 0;

        /* It must exit with the step in its status and never answer a SPAWN. */
        if (waitpid(sp, &st, 0) != sp) st = -1;
        good = WIFEXITED(st) && WEXITSTATUS(st) == PS_SPAWNER_RC_LOCKDOWN_BASE + k;
        {
            enum ps_ctl_recv_result rr = ps_ctl_recv(ctl, PS_FROM_SPAWNER, MSG_DONTWAIT, &m, &fd);

            good = good && rr == PS_CTL_EOF;
            if (fd >= 0) { close(fd); good = false; }
        }
        if (!good) {
            printf("    step %d: spawner status %d (wanted exit %d), no READY and EOF\n", k, st,
                   PS_SPAWNER_RC_LOCKDOWN_BASE + k);
            all = false;
        }
        close(ctl);
    }
    CHECK(all, "a failure at each lockdown step ends the spawner with that step, before it serves anything");
}

/* Run `fn` in a forked child that has given up some capabilities first. */
static int in_child(int (*fn)(void), uint64_t drop_effective) {
    pid_t pid = fork();
    int st = 0;

    if (pid < 0) return -1;
    if (pid == 0) {
        struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3};
        struct __user_cap_data_struct d[2];

        if (syscall(SYS_capget, &h, d) < 0) _exit(95);
        d[0].effective &= ~(uint32_t)drop_effective;
        d[0].permitted &= ~(uint32_t)drop_effective;
        d[1].effective &= ~(uint32_t)(drop_effective >> 32);
        d[1].permitted &= ~(uint32_t)(drop_effective >> 32);
        if (syscall(SYS_capset, &h, d) < 0) _exit(96);
        _exit(fn());
    }
    if (waitpid(pid, &st, 0) != pid) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 200 + WTERMSIG(st);
}

static int lockdown_right_ppid(void) { return ps_spawner_lockdown(getppid()); }

/* Lock down for real, then do what a compromised spawner could: change the
 * effective gid, which the filter allows (workers do it under the same filter).
 * Under the filter only exit_group and a few others work, so the answer goes
 * out as the exit status: 10 = the signal was set and the credential change
 * cleared it, 11 = it survived, anything else = the setup went wrong. */
static int pdeathsig_after_credential_change(void) {
    int before = -1, after = -1;

    if (ps_spawner_lockdown(getppid()) != 0) return 1;
    if (prctl(PR_GET_PDEATHSIG, &before, 0, 0, 0) < 0) return 2;
    if (before != SIGKILL) return 3;
    if (syscall(SYS_setresgid, WORKER_UID, WORKER_UID, WORKER_UID) < 0) return 4;
    if (prctl(PR_GET_PDEATHSIG, &after, 0, 0, 0) < 0) return 5;
    return after == 0 ? 10 : 11;
}
static int lockdown_wrong_ppid(void) { return ps_spawner_lockdown(getppid() + 4242); }
static int lockdown_no_ppid(void) { return ps_spawner_lockdown(0); }

/* Which step refuses first when CAP_SETPCAP is gone. Emptying the bounding set
 * needs it, so with anything beyond the four kept capabilities still in the
 * set (the usual case) the bounding-set step fails. Started with the set
 * already cut to exactly the four (under the packaged unit's
 * CapabilityBoundingSet=, say) that step has nothing to drop and passes, and
 * the next one fails instead, because the permitted set cannot hold what
 * was just given up. Either way nothing has been changed yet. */
static int step_refusing_without_setpcap(void) {
    bool extra = false, missing = false;

    for (int cap = 0;; cap++) {
        int r = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        bool keep;

        if (r < 0) break; /* EINVAL: past the last capability */
        keep = cap < 64 && ((PS_SPAWNER_CAPS >> cap) & 1u);
        if (r == 1 && !keep) extra = true;
        if (r == 0 && keep) missing = true;
    }
    return (!extra && !missing) ? PS_L_CAPABILITIES : PS_L_BOUNDING_SET;
}

static void test_refuses(void) {
    int rc, want = step_refusing_without_setpcap();

    printf("\nthe lockdown refuses to run half-way:\n");

    /* Works as root and without: giving up CAP_SETPCAP (or never having it)
     * must be refused before anything is changed. */
    rc = in_child(lockdown_right_ppid, 1ull << CAP_SETPCAP);
    CHECK(rc == want,
          want == PS_L_BOUNDING_SET
              ? "without CAP_SETPCAP it fails at the bounding-set step, not later"
              : "without CAP_SETPCAP it fails at the capabilities step (the bounding set was already cut)");

    if (!can_lock_down()) {
        SKIPT("a wrong or missing parent pid is refused (needs root)");
        SKIPT("a full lockdown in a child succeeds (needs root)");
        return;
    }
    rc = in_child(lockdown_wrong_ppid, 0);
    CHECK(rc == PS_L_PDEATHSIG, "a parent pid that is not the real parent is refused");
    rc = in_child(lockdown_no_ppid, 0);
    CHECK(rc == PS_L_PDEATHSIG, "no parent pid at all is refused");
    rc = in_child(lockdown_right_ppid, 0);
    CHECK(rc == 0, "with the real parent pid the whole sequence succeeds");
}

/* KNOWN GAP, deliberately recorded (docs/privilege-separation.md, "Residual
 * risk: a compromised spawner can outlive avd"). The spawner keeps CAP_SETGID
 * and its filter has to allow the credential calls its workers make, so it can
 * still clear its own parent-death signal. This asserts the gap is there. When
 * the spawner stops holding those capabilities and the calls leave its filter,
 * this check will fail: flip it to expect 11 and update that section. */
static void test_known_gap(void) {
    int rc;

    printf("\nknown gap: the parent-death signal and credential changes (root):\n");
    if (!can_lock_down()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID, CAP_SETPCAP and CAP_KILL");
        return;
    }
    rc = in_child(pdeathsig_after_credential_change, 0);
    /* 1-3 are setup errors. 4, 5 or a SIGSYS death (231) mean the credential
     * change itself no longer works, i.e. the gap may have been closed. */
    CHECK(rc != 1 && rc != 2 && rc != 3,
          "the lockdown ran and the parent-death signal was SIGKILL before the credential change");
    CHECK(rc == 10,
          "KNOWN GAP: setresgid() after the lockdown clears the parent-death signal (see the docs)");
}

static void test_dies_with_parent(void) {
    struct ps_spawner_cfg cfg = base_cfg();
    int p[2], st = 0;
    pid_t mid, spawner = 0;
    bool gone = false;

    printf("\nthe locked-down spawner dies with avd (root):\n");
    if (!can_lock_down()) {
        SKIPT("needs root with CAP_SETUID, CAP_SETGID, CAP_SETPCAP and CAP_KILL");
        return;
    }
    if (pipe(p) < 0) { CHECK(false, "pipe"); return; }
    mid = fork();
    if (mid < 0) { /* never go on to kill(mid): kill(-1) signals everything */
        close(p[0]);
        close(p[1]);
        CHECK(false, "fork");
        return;
    }
    if (mid == 0) {
        struct ps_ctl_msg r;
        int c, w = -1;
        pid_t s2;

        close(p[0]);
        if (ps_spawner_start(&cfg, &c, &s2) != 0) _exit(2);
        /* READY proves the spawner is locked down and in its loop. Only then
         * does this "avd" report in and wait to be killed. */
        if (!spawn_one(c, 1, &r, &w)) _exit(3);
        if (write(p[1], &s2, sizeof(s2)) != sizeof(s2)) _exit(4);
        pause();
        _exit(0);
    }
    close(p[1]);
    if (read(p[0], &spawner, sizeof(spawner)) != sizeof(spawner)) spawner = 0;
    close(p[0]);
    CHECK(spawner > 0, "a short-lived main started a locked-down spawner");
    if (spawner <= 0) { kill(mid, SIGKILL); waitpid(mid, NULL, 0); return; }

    kill(mid, SIGKILL);
    waitpid(mid, NULL, 0);
    /* This process is a subreaper, so the orphaned spawner comes to us. */
    for (int i = 0; i < 100 && !gone; i++) {
        if (waitpid(spawner, &st, WNOHANG) == spawner) gone = true;
        else usleep(50 * 1000);
    }
    CHECK(gone && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL,
          "killing avd kills the spawner with SIGKILL, after the capability drop");
    if (!gone) { kill(spawner, SIGKILL); waitpid(spawner, NULL, 0); }
    for (int i = 0; i < 20; i++) {
        while (waitpid(-1, NULL, WNOHANG) > 0) {
        }
        usleep(25 * 1000);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(120);
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    printf("privsep lockdown: the spawner against the real kernel\n");
    test_filter_kernel();
    test_refuses();
    test_spawner_state();
    test_failure_injection();
    test_known_gap();
    test_dies_with_parent();
    SUMMARY("privsep_lockdown (kernel)");
}
EOF

CC="${CC:-gcc}"
rc=0

# The test hooks must not exist in a production build.
echo "### checking the production headers carry no test hooks ###"
if "$CC" -std=gnu11 -E -I"$SRC_DIR" -x c - <<< '#include "privsep_spawner.h"' 2>/dev/null |
    grep -q 'ps_test_lock_\|ps_spawner_test_'; then
    echo "  FAIL: a lockdown or spawner test hook is present in a production build"
    rc=1
else
    echo "  PASS: no ps_test_lock_* or ps_spawner_test_* symbols in a production build"
fi

echo "### building (ASan+UBSan: the seccomp program) ###"
"$CC" -std=gnu11 -Wall -Wextra -Werror -O1 -g -fno-omit-frame-pointer \
    -fsanitize=address,undefined -fno-sanitize-recover=undefined \
    -I"$SRC_DIR" -I"$BUILD_DIR" -o "$BUILD_DIR/bpf" "$BUILD_DIR/bpf.c" || exit 1

echo "### building (plain -O2: the real kernel) ###"
"$CC" -std=gnu11 -Wall -Wextra -Werror -O2 -fstack-protector-strong \
    -DPS_WORKER_TEST_HOOKS -I"$SRC_DIR" -I"$BUILD_DIR" \
    -o "$BUILD_DIR/kern" "$BUILD_DIR/kern.c" || exit 1

echo
"$BUILD_DIR/bpf" || rc=1
echo
"$BUILD_DIR/kern" || rc=1

exit $rc
