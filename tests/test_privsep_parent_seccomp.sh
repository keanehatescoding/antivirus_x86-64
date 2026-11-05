#!/usr/bin/env bash
#
# tests/test_privsep_parent_seccomp.sh - coverage for the main avd process's
# seccomp filter, ps_seccomp_build_parent() / ps_seccomp_install_parent() in
# userspace/avd/privsep_parent.h (#103, Stage 2 step 3; see
# docs/privilege-separation.md).
#
# Two parts, both runnable without root (a seccomp filter needs only
# NO_NEW_PRIVS):
#   bpf     the program run through a small BPF interpreter in userspace
#           (ASan+UBSan): every syscall number 0..1023 against an independent
#           statement of what the main process may do, every argument check,
#           log mode, missing descriptors, the architecture and x32 checks.
#   kernel  the filter installed for real in forked children (no sanitizers,
#           whose runtime makes syscalls the filter denies): threads still
#           start through glibc's clone3 -> clone fallback, TSYNC reaches a
#           thread that already existed, fork/socket/execve/prctl kill the
#           process, PROT_EXEC is refused with EPERM, and the argument checks
#           hold on a real kernel.
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${PS_SRC_DIR:-$REPO_ROOT/userspace/avd}"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_privsep_pseccomp.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
# False positive: cleanup() IS invoked via `trap` on the next line.
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

cat > "$BUILD_DIR/common.h" <<'EOF'
#ifndef T_COMMON_H
#define T_COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int PASS, FAIL;
#define CHECK(cond, label) do { \
    if (cond) { printf("  PASS: %s\n", label); PASS++; } \
    else { printf("  FAIL: %s\n", label); FAIL++; } \
} while (0)
#define SUMMARY(name) do { \
    printf("\n===================================\n"); \
    printf("%s: %d passed, %d failed\n", name, PASS, FAIL); \
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
#include "privsep_parent.h"
#include "common.h"

#define BAD 0xdeadbeefu
#define R_ALLOW SECCOMP_RET_ALLOW
#define R_KILL SECCOMP_RET_KILL_PROCESS
#define R_LOG SECCOMP_RET_LOG
#define R_EPERM (SECCOMP_RET_ERRNO | EPERM)
#define R_EBADF (SECCOMP_RET_ERRNO | EBADF)
#define R_ENOSYS (SECCOMP_RET_ERRNO | ENOSYS)

static uint32_t bpf_run(const struct sock_filter *p, size_t n,
                        const struct seccomp_data *d) {
    uint32_t A = 0;
    size_t pc = 0;
    const unsigned char *raw = (const unsigned char *)d;

    while (pc < n) {
        const struct sock_filter *i = &p[pc];
        switch (i->code) {
        case BPF_LD | BPF_W | BPF_ABS:
            if (i->k > sizeof(*d) - 4) return BAD;
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
            return BAD; /* an opcode the filter should never use */
        }
    }
    return BAD; /* ran off the end */
}

static struct sock_filter P[PS_ASM_MAX];
static size_t PN;

static size_t build(const struct ps_parent_filter *f) {
    struct ps_asm a;
    size_t n = ps_seccomp_build_parent(&a, f);

    if (n) memcpy(P, a.prog, n * sizeof(P[0]));
    PN = n;
    return n;
}

static uint32_t run6(uint32_t arch, int nr, uint64_t a0, uint64_t a1,
                     uint64_t a2) {
    struct seccomp_data d;

    memset(&d, 0, sizeof(d));
    d.arch = arch;
    d.nr = nr;
    d.args[0] = a0;
    d.args[1] = a1;
    d.args[2] = a2;
    return bpf_run(P, PN, &d);
}

static uint32_t run(int nr, uint64_t a0, uint64_t a1, uint64_t a2) {
    return run6(AUDIT_ARCH_X86_64, nr, a0, a1, a2);
}

#define SELF 4242
#define SPAWNER 4343
#define WAKE 17
#define FAN 9
#define FLAGS_OK (PS_FAN_MARK_ADD | PS_FAN_MARK_FILESYSTEM)

/* An independent statement of what the main process may call with no
 * argument constraint, deliberately not derived from the header's table:
 * strace of avd's own threads across the socket and fanotify suites, plus the
 * neighbours glibc may pick instead (readv/writev, *at forms, ppoll, statx,
 * accept4, the time and id getters), plus brk/mremap/rseq/sched_yield. */
static bool want_plain(int nr) {
    switch (nr) {
    case SYS_read: case SYS_write: case SYS_readv: case SYS_writev:
    case SYS_pread64: case SYS_lseek: case SYS_close: case SYS_dup:
    case SYS_fcntl: case SYS_fstat: case SYS_newfstatat: case SYS_statx:
    case SYS_getdents64: case SYS_readlink: case SYS_readlinkat:
    case SYS_open: case SYS_openat: case SYS_mkdir: case SYS_mkdirat:
    case SYS_chmod: case SYS_fchmod: case SYS_fchmodat: case SYS_fchown:
    case SYS_linkat: case SYS_rename: case SYS_renameat: case SYS_renameat2:
    case SYS_unlink: case SYS_unlinkat: case SYS_fsync: case SYS_fdatasync:
    case SYS_poll: case SYS_ppoll: case SYS_accept: case SYS_accept4:
    case SYS_recvmsg: case SYS_sendmsg: case SYS_getsockopt:
    case SYS_setsockopt: case SYS_shutdown:
    case SYS_munmap: case SYS_mremap: case SYS_brk: case SYS_madvise:
    case SYS_futex: case SYS_sched_yield: case SYS_set_robust_list:
    case SYS_rseq: case SYS_clock_gettime: case SYS_clock_getres:
    case SYS_gettimeofday: case SYS_time: case SYS_nanosleep:
    case SYS_clock_nanosleep: case SYS_rt_sigaction: case SYS_rt_sigprocmask:
    case SYS_rt_sigreturn: case SYS_restart_syscall: case SYS_getpid:
    case SYS_gettid: case SYS_getuid: case SYS_geteuid: case SYS_getgid:
    case SYS_getegid: case SYS_getrandom: case SYS_wait4: case SYS_exit:
    case SYS_exit_group:
        return true;
    }
    return false;
}

/* The syscalls with an argument check; each is tested on its own below. */
static bool conditional(int nr) {
    return nr == SYS_mmap || nr == SYS_mprotect || nr == SYS_clone ||
           nr == SYS_clone3 || nr == SYS_connect || nr == SYS_kill ||
           nr == SYS_tgkill || nr == SYS_fanotify_mark;
}

/* Every number 0..1023 with zero arguments: the plain list allowed, the rest
 * (the conditional ones aside) answered with `deny`, never a stray value. */
static int sweep(uint32_t deny) {
    int bad = 0;

    for (int nr = 0; nr < 1024; nr++) {
        uint32_t r;

        if (conditional(nr)) continue;
        r = run(nr, 0, 0, 0);
        if (r != (want_plain(nr) ? R_ALLOW : deny)) {
            printf("    nr %d -> 0x%x\n", nr, r);
            bad++;
        }
    }
    return bad;
}

int main(void) {
    struct ps_parent_filter f = {SELF, SPAWNER, WAKE, FAN, false};
    struct ps_parent_filter g;
    size_t n;
    int bad;

    printf("### bpf ###\n");
    n = build(&f);
    printf("  program: %zu instructions (limit %d)\n", n, PS_ASM_MAX);
    CHECK(n > 0 && n <= PS_ASM_MAX, "the full filter assembles within PS_ASM_MAX");
    {
        size_t plain = 0;

        for (int nr = 0; nr < 1024; nr++) plain += want_plain(nr);
        CHECK(plain == PS_ALLOW_PARENT_N,
              "the header's plain list is exactly as long as the independent one");
    }
    CHECK(sweep(R_KILL) == 0,
          "every syscall 0..1023 (conditional ones aside): the plain list allowed, all else KILL_PROCESS");

    {
        static const int never[] = {
            SYS_socket, SYS_socketpair, SYS_bind, SYS_listen, SYS_getsockname,
            SYS_sendto, SYS_recvfrom, SYS_fanotify_init, SYS_capset,
            SYS_prctl, SYS_execve, SYS_execveat, SYS_fork, SYS_vfork,
            SYS_setuid, SYS_setresuid, SYS_setgid, SYS_ptrace, SYS_mount,
            SYS_umount2, SYS_bpf, SYS_seccomp, SYS_unshare, SYS_setns,
            SYS_init_module, SYS_finit_module, SYS_kexec_load,
            SYS_open_by_handle_at, SYS_process_vm_writev, SYS_memfd_create,
            SYS_ioctl, SYS_pipe, SYS_pipe2, SYS_chown, SYS_lchown,
            SYS_fchownat, SYS_symlink, SYS_link, SYS_mknod, SYS_chroot,
            SYS_pivot_root, SYS_reboot, SYS_tkill, SYS_rt_sigqueueinfo,
            SYS_rt_tgsigqueueinfo, SYS_pidfd_open, SYS_pidfd_send_signal,
            SYS_io_uring_setup, SYS_userfaultfd, SYS_perf_event_open,
            SYS_personality, SYS_modify_ldt, SYS_arch_prctl, SYS_iopl,
            SYS_ioperm,
        };
        bad = 0;
        for (size_t i = 0; i < sizeof(never) / sizeof(never[0]); i++)
            if (run(never[i], 0, 0, 0) != R_KILL) {
                printf("    never-list nr %d allowed\n", never[i]);
                bad++;
            }
        CHECK(bad == 0, "socket, bind, listen, fanotify_init, capset, prctl, execve, fork, setuid, ptrace, ... kill");
    }

    /* mmap(addr, len, prot) / mprotect(addr, len, prot) */
    bad = 0;
    for (uint64_t prot = 0; prot < 16; prot++) {
        uint32_t want = (prot & 4) ? R_EPERM : R_ALLOW;

        if (run(SYS_mmap, 0, 4096, prot) != want) bad++;
        if (run(SYS_mprotect, 0, 4096, prot) != want) bad++;
        if (run(SYS_mmap, 0, 4096, prot | 0xffffffff00000000ull) != want) bad++;
    }
    CHECK(bad == 0, "mmap/mprotect: any prot allowed, PROT_EXEC refused with EPERM");

    /* clone(flags, ...) */
    CHECK(run(SYS_clone, PS_CLONE_THREAD_FLAGS, 0, 0) == R_ALLOW,
          "clone with exactly pthread_create()'s flags is allowed");
    bad = 0;
    for (int b = 0; b < 64; b++) {
        uint64_t fl = (uint64_t)PS_CLONE_THREAD_FLAGS ^ (1ull << b);

        if (run(SYS_clone, fl, 0, 0) != R_KILL) bad++;
    }
    if (run(SYS_clone, 0x01200011ull, 0, 0) != R_KILL) bad++; /* fork() */
    if (run(SYS_clone, 0, 0, 0) != R_KILL) bad++;
    CHECK(bad == 0, "clone with any one flag bit different (all 64), fork()'s flags or none: kill");
    CHECK(run(SYS_clone3, 0, 0, 0) == R_ENOSYS &&
          run(SYS_clone3, 0x1234, 88, 0) == R_ENOSYS,
          "clone3 answers ENOSYS (glibc then uses clone)");

    /* connect(fd, ...) */
    CHECK(run(SYS_connect, WAKE, 0, 0) == R_ALLOW, "connect on the wake-up descriptor is allowed");
    CHECK(run(SYS_connect, WAKE + 1, 0, 0) == R_KILL && run(SYS_connect, 0, 0, 0) == R_KILL,
          "connect on any other descriptor kills");

    /* kill(pid, sig) */
    CHECK(run(SYS_kill, SPAWNER, SIGKILL, 0) == R_ALLOW, "kill(spawner, SIGKILL) is allowed");
    CHECK(run(SYS_kill, SPAWNER, 0, 0) == R_KILL &&
          run(SYS_kill, SPAWNER, SIGTERM, 0) == R_KILL &&
          run(SYS_kill, SPAWNER + 1, SIGKILL, 0) == R_KILL &&
          run(SYS_kill, (uint32_t)-1, SIGKILL, 0) == R_KILL &&
          run(SYS_kill, 0, SIGKILL, 0) == R_KILL &&
          run(SYS_kill, (uint32_t)-SPAWNER, SIGKILL, 0) == R_KILL,
          "kill with another signal, another pid, -1, 0 or the spawner's group kills");

    /* tgkill(tgid, tid, sig) */
    CHECK(run(SYS_tgkill, SELF, 5, SIGABRT) == R_ALLOW, "tgkill on this process is allowed");
    CHECK(run(SYS_tgkill, SPAWNER, 5, SIGKILL) == R_KILL && run(SYS_tgkill, 1, 1, SIGKILL) == R_KILL,
          "tgkill on any other process kills");

    /* fanotify_mark(fd, flags, ...) */
    CHECK(run(SYS_fanotify_mark, FAN, FLAGS_OK, 0) == R_ALLOW,
          "fanotify_mark(fan_fd, ADD|FILESYSTEM) is allowed");
    CHECK(run(SYS_fanotify_mark, FAN + 1, FLAGS_OK, 0) == R_EBADF,
          "fanotify_mark(ADD|FILESYSTEM) on another descriptor answers EBADF");
    CHECK(run(SYS_fanotify_mark, FAN, 0x2 | 0x100, 0) == R_KILL &&  /* REMOVE */
          run(SYS_fanotify_mark, FAN, 0x1, 0) == R_KILL &&          /* inode */
          run(SYS_fanotify_mark, FAN, 0x1 | 0x10, 0) == R_KILL &&   /* MOUNT */
          run(SYS_fanotify_mark, FAN, 0x80, 0) == R_KILL &&         /* FLUSH */
          run(SYS_fanotify_mark, FAN + 1, 0x80, 0) == R_KILL,
          "fanotify_mark with any other flags kills, on any descriptor");

    /* architecture and x32 */
    bad = 0;
    for (int nr = 0; nr < 512; nr++) {
        if (run6(AUDIT_ARCH_I386, nr, 0, 0, 0) != R_KILL) bad++;
        if (run6(AUDIT_ARCH_AARCH64, nr, 0, 0, 0) != R_KILL) bad++;
        if (run(nr | 0x40000000, 0, 0, 0) != R_KILL) bad++;
    }
    CHECK(bad == 0, "other architectures and the x32 ABI are always killed");

    /* log mode */
    g = f;
    g.log_only = true;
    build(&g);
    CHECK(sweep(R_LOG) == 0, "log mode: the same plain list, everything else SECCOMP_RET_LOG");
    CHECK(run(SYS_mmap, 0, 1, 7) == R_EPERM && run(SYS_clone3, 0, 0, 0) == R_ENOSYS &&
          run(SYS_fanotify_mark, FAN + 1, FLAGS_OK, 0) == R_EBADF &&
          run(SYS_kill, SPAWNER, 0, 0) == R_LOG && run(SYS_clone, 0x01200011ull, 0, 0) == R_LOG,
          "log mode keeps the errno answers and logs the argument-check failures");
    bad = 0;
    for (int nr = 0; nr < 512; nr++) {
        if (run6(AUDIT_ARCH_I386, nr, 0, 0, 0) != R_KILL) bad++;
        if (run(nr | 0x40000000, 0, 0, 0) != R_KILL) bad++;
    }
    CHECK(bad == 0, "log mode still kills other architectures and x32");

    /* missing descriptors / pids */
    g = f;
    g.wake_fd = -1;
    g.spawner_pid = 0;
    g.fan_fd = -1;
    n = build(&g);
    CHECK(n > 0, "builds with no wake-up descriptor, spawner or fanotify descriptor");
    CHECK(run(SYS_connect, WAKE, 0, 0) == R_KILL && run(SYS_connect, (uint32_t)-1, 0, 0) == R_KILL,
          "no wake-up descriptor: no connect at all");
    CHECK(run(SYS_kill, 0, SIGKILL, 0) == R_KILL && run(SYS_kill, SPAWNER, SIGKILL, 0) == R_KILL,
          "no spawner: no kill at all (not even pid 0)");
    CHECK(run(SYS_fanotify_mark, FAN, FLAGS_OK, 0) == R_KILL &&
          run(SYS_fanotify_mark, (uint32_t)-1, FLAGS_OK, 0) == R_KILL,
          "no fanotify descriptor: no fanotify_mark at all");
    CHECK(sweep(R_KILL) == 0 && run(SYS_tgkill, SELF, 1, 6) == R_ALLOW,
          "the rest of the filter is unchanged without them");
    g.log_only = true;
    build(&g);
    CHECK(run(SYS_connect, WAKE, 0, 0) == R_LOG && run(SYS_kill, SPAWNER, SIGKILL, 0) == R_LOG &&
          run(SYS_fanotify_mark, FAN, FLAGS_OK, 0) == R_LOG,
          "... and in log mode those are logged");

    {
        struct ps_asm a;

        g = f;
        g.self_pid = 0;
        CHECK(ps_seccomp_build_parent(&a, &g) == 0, "self_pid 0 does not build");
        g.self_pid = -1;
        CHECK(ps_seccomp_build_parent(&a, &g) == 0, "self_pid -1 does not build");
    }

    SUMMARY("privsep_parent_seccomp bpf");
}
EOF

# ---------------------------------------------------------------------------
# kernel: the filter installed for real, in forked children
# ---------------------------------------------------------------------------
cat > "$BUILD_DIR/kern.c" <<'EOF'
#define _GNU_SOURCE
#include "privsep_parent.h"
#include "common.h"
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *sock_path;

/* Run fn in a forked child; 0 = ok, 1.. = the check that failed, 100 + n =
 * killed by signal n. Core dumps are switched off (SIGSYS would dump). */
static int in_child(int (*fn)(void)) {
    int st;
    pid_t p;

    fflush(NULL);
    p = fork();
    if (p == 0) {
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        _exit(fn());
    }
    if (p < 0 || waitpid(p, &st, 0) != p)
        return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 100 + WTERMSIG(st);
}

#define KILLED_SIGSYS (100 + SIGSYS)

static pid_t sleeper(void) {
    pid_t p = fork();

    if (p == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0); /* dies with the child */
        if (getppid() == 1) _exit(0);
        pause();
        _exit(0);
    }
    return p;
}

static int wake_fd = -1;
static pid_t spawner = -1;

/* NO_NEW_PRIVS, a wake-up socket and a stand-in spawner, then the filter. */
static int install(bool log_only) {
    struct ps_parent_filter f;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 90;
    wake_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (wake_fd < 0) return 91;
    spawner = sleeper();
    if (spawner < 0) return 92;
    memset(&f, 0, sizeof(f));
    f.self_pid = getpid();
    f.spawner_pid = spawner;
    f.wake_fd = wake_fd;
    f.fan_fd = -1;
    f.log_only = log_only;
    if (ps_seccomp_install_parent(&f) != 0) return 93;
    return 0;
}

#define INSTALL(lo) do { int r_ = install(lo); if (r_) return r_; } while (0)

static int c_needs_nnp(void) {
    struct ps_parent_filter f = {getpid(), 0, -1, -1, false};

    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 0) return 1;
    errno = 0;
    if (ps_seccomp_install_parent(&f) != -1 || errno != EPERM) return 2;
    return 0;
}

static int c_bad_self(void) {
    struct ps_parent_filter f = {0, 0, -1, -1, false};

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 1;
    errno = 0;
    if (ps_seccomp_install_parent(&f) != -1 || errno != E2BIG) return 2;
    if (socket(AF_UNIX, SOCK_STREAM, 0) < 0) return 3; /* nothing installed */
    return 0;
}

static void *th_noop(void *arg) { return arg; }

static int c_pthread(void) {
    pthread_t t;
    void *out = NULL;

    INSTALL(false);
    if (pthread_create(&t, NULL, th_noop, (void *)0x5a) != 0) return 1;
    if (pthread_join(t, &out) != 0 || out != (void *)0x5a) return 2;
    return 0;
}

static int c_clone3_enosys(void) {
    INSTALL(false);
    errno = 0;
    if (syscall(SYS_clone3, NULL, 0) != -1 || errno != ENOSYS) return 1;
    return 0;
}

static volatile int th_stop;

static void *th_spin(void *arg) {
    while (!th_stop) sched_yield();
    return arg;
}

/* "Seccomp:\t2" for every thread in /proc/self/task. */
static int all_threads_filtered(int *count) {
    DIR *d = opendir("/proc/self/task");
    struct dirent *e;
    int bad = 0;

    *count = 0;
    if (!d) return -1;
    while ((e = readdir(d))) {
        char path[300], buf[4096];
        int fd;
        ssize_t n;

        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/status", e->d_name);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) { bad++; continue; }
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) { bad++; continue; }
        buf[n] = 0;
        if (!strstr(buf, "\nSeccomp:\t2\n")) bad++;
        (*count)++;
    }
    closedir(d);
    return bad;
}

static int c_tsync(void) {
    pthread_t t;
    int count;

    if (pthread_create(&t, NULL, th_spin, NULL) != 0) return 1;
    INSTALL(false);
    if (all_threads_filtered(&count) != 0) return 2;
    if (count != 2) return 3;
    th_stop = 1;
    pthread_join(t, NULL);
    return 0;
}

static void *th_socket(void *arg) {
    (void)arg;
    syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    return NULL;
}

static int c_tsync_kills(void) {
    pthread_t t;

    INSTALL(false);
    if (pthread_create(&t, NULL, th_socket, NULL) != 0) return 1;
    pthread_join(t, NULL);
    return 2; /* not reached: the whole process dies */
}

static int c_fork(void) { INSTALL(false); syscall(SYS_fork); return 1; }
static int c_socket(void) { INSTALL(false); syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0); return 1; }
static int c_execve(void) {
    char *argv[] = {"/bin/true", NULL};

    INSTALL(false);
    syscall(SYS_execve, "/bin/true", argv, NULL);
    return 1;
}
static int c_prctl(void) { INSTALL(false); syscall(SYS_prctl, PR_GET_DUMPABLE, 0, 0, 0, 0); return 1; }
static int c_bind(void) {
    struct sockaddr_un a = {.sun_family = AF_UNIX};

    INSTALL(false);
    syscall(SYS_bind, wake_fd, &a, sizeof(sa_family_t));
    return 1;
}

static int c_exec_mem(void) {
    void *p;

    INSTALL(false);
    p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 1;
    errno = 0;
    if (mprotect(p, 4096, PROT_READ | PROT_EXEC) != -1 || errno != EPERM) return 2;
    errno = 0;
    if (mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != MAP_FAILED ||
        errno != EPERM) return 3;
    if (mprotect(p, 4096, PROT_READ) != 0) return 4;
    if (munmap(p, 4096) != 0) return 5;
    return 0;
}

/* connect() on the wake-up socket reaches the kernel (a listener answers);
 * connect() on another descriptor kills. */
static int c_connect_wake(void) {
    struct sockaddr_un a;

    INSTALL(false);
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", sock_path);
    if (connect(wake_fd, (struct sockaddr *)&a, sizeof(a)) != 0) return 1;
    return 0;
}

static int c_connect_other(void) {
    int other = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a;

    if (other < 0) return 1;
    INSTALL(false);
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", sock_path);
    connect(other, (struct sockaddr *)&a, sizeof(a));
    return 2;
}

static int c_kill_spawner(void) {
    int st;

    INSTALL(false);
    if (kill(spawner, SIGKILL) != 0) return 1;
    if (waitpid(spawner, &st, 0) != spawner) return 2;
    if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGKILL) return 3;
    return 0;
}

static int c_kill_probe(void) { INSTALL(false); kill(spawner, 0); return 1; }
static int c_kill_parent(void) { INSTALL(false); kill(getppid(), SIGKILL); return 1; }

/* abort() is tgkill(getpid(), gettid(), SIGABRT): SIGABRT, not SIGSYS. */
static int c_abort(void) { INSTALL(false); abort(); }

static int c_log_mode(void) {
    int s;
    struct ps_parent_filter g;

    INSTALL(true);
    s = (int)syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return 1;
    if (syscall(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 2;
    if (kill(spawner, 0) != 0) return 3;
    /* errno answers are kept */
    errno = 0;
    if (mmap(NULL, 4096, PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != MAP_FAILED ||
        errno != EPERM) return 4;
    errno = 0;
    if (syscall(SYS_clone3, NULL, 0) != -1 || errno != ENOSYS) return 5;
    /* a second filter is allowed under log mode (seccomp is logged), and
     * filters only stack: the enforcing one now kills socket() */
    memset(&g, 0, sizeof(g));
    g.self_pid = getpid();
    g.wake_fd = -1;
    g.fan_fd = -1;
    if (ps_seccomp_install_parent(&g) != 0) return 6;
    syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    return 7;
}

/* Printing, time, randomness, files: the ordinary work still goes through. */
static int c_ordinary(void) {
    char tmpl[256], buf[8];
    struct timespec ts;
    int fd;

    INSTALL(false);
    snprintf(tmpl, sizeof(tmpl), "%s.f", sock_path);
    fd = open(tmpl, O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return 1;
    if (write(fd, "abc", 3) != 3 || fsync(fd) != 0) return 2;
    if (pread(fd, buf, 3, 0) != 3 || memcmp(buf, "abc", 3)) return 3;
    if (fchmod(fd, 0640) != 0) return 4;
    close(fd);
    if (unlink(tmpl) != 0) return 5;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 6;
    if (getrandom(buf, sizeof(buf), 0) != sizeof(buf)) return 7;
    {
        void *big = malloc(8 << 20); /* mmap, then munmap on free */

        if (!big) return 8;
        memset(big, 1, 8 << 20);
        free(big);
    }
    printf("    (printing from a filtered child)\n");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    struct { const char *label; int (*fn)(void); int want; } t[] = {
        {"installing without NO_NEW_PRIVS fails with EPERM", c_needs_nnp, 0},
        {"self_pid 0 fails with E2BIG and installs nothing", c_bad_self, 0},
        {"pthread_create() and pthread_join() still work (clone3 -> ENOSYS -> clone)", c_pthread, 0},
        {"clone3 itself answers ENOSYS", c_clone3_enosys, 0},
        {"TSYNC: a thread that existed before the call reports Seccomp: 2 too", c_tsync, 0},
        {"a denied call in another thread kills the whole process with SIGSYS", c_tsync_kills, KILLED_SIGSYS},
        {"fork() is killed with SIGSYS", c_fork, KILLED_SIGSYS},
        {"socket() is killed with SIGSYS", c_socket, KILLED_SIGSYS},
        {"execve() is killed with SIGSYS", c_execve, KILLED_SIGSYS},
        {"prctl() is killed with SIGSYS", c_prctl, KILLED_SIGSYS},
        {"bind() is killed with SIGSYS", c_bind, KILLED_SIGSYS},
        {"PROT_EXEC is refused with EPERM by mmap and mprotect, other mappings work", c_exec_mem, 0},
        {"connect() on the wake-up descriptor reaches a listener", c_connect_wake, 0},
        {"connect() on another descriptor is killed with SIGSYS", c_connect_other, KILLED_SIGSYS},
        {"kill(spawner, SIGKILL) works", c_kill_spawner, 0},
        {"kill(spawner, 0) is killed with SIGSYS", c_kill_probe, KILLED_SIGSYS},
        {"kill() of another process is killed with SIGSYS", c_kill_parent, KILLED_SIGSYS},
        {"abort() still raises SIGABRT (tgkill on itself)", c_abort, 100 + SIGABRT},
        {"log mode lets denied calls through, keeps the errno answers, and stacks under an enforcing filter", c_log_mode, KILLED_SIGSYS},
        {"files, time, randomness, malloc and stdio still work under the filter", c_ordinary, 0},
    };
    struct sockaddr_un a;
    int lfd;

    printf("### kernel ###\n");
    if (argc < 2) return 2;
    sock_path = argv[1];
    lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", sock_path);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(lfd, 16) != 0) {
        printf("  FAIL: could not listen on %s\n", sock_path);
        return 1;
    }
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        int r = in_child(t[i].fn);

        if (r != t[i].want) printf("    (child returned %d, wanted %d)\n", r, t[i].want);
        CHECK(r == t[i].want, t[i].label);
    }
    close(lfd);
    unlink(sock_path);
    SUMMARY("privsep_parent_seccomp kernel");
}
EOF

rc=0
echo "### privsep_parent.h seccomp filter: bpf (ASan+UBSan) ###"
gcc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$SRC_DIR" -I"$BUILD_DIR" -o "$BUILD_DIR/bpf" "$BUILD_DIR/bpf.c" || { echo "FAIL: bpf build"; exit 1; }
"$BUILD_DIR/bpf" || rc=1

echo "### privsep_parent.h seccomp filter: kernel ###"
gcc -std=gnu11 -O2 -Wall -Wextra -Werror -I"$SRC_DIR" -I"$BUILD_DIR" \
    -o "$BUILD_DIR/kern" "$BUILD_DIR/kern.c" -lpthread || { echo "FAIL: kernel build"; exit 1; }
"$BUILD_DIR/kern" "$BUILD_DIR/s" || rc=1
exit $rc
