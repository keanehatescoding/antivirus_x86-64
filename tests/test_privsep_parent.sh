#!/usr/bin/env bash
#
# tests/test_privsep_parent.sh - coverage for userspace/avd/privsep_parent.h,
# the main avd process shrinking itself once the spawner exists (#103, Stage 2
# step 2; see docs/privilege-separation.md, "Stage 2: shrink the parent").
#
# The production header is compiled standalone (same arrangement as
# test_privsep_lockdown.sh), with ASan+UBSan, and every check runs in a forked
# child so the real capability state of this process is never touched. It needs
# root (the bounding-set drop needs CAP_SETPCAP); without root every check
# prints SKIP, never PASS:
#     sudo tests/test_privsep_parent.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${PS_SRC_DIR:-$REPO_ROOT/userspace/avd}"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_privsep_parent.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
# False positive: cleanup() IS invoked via `trap` on the next line.
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

cat > "$BUILD_DIR/t.c" <<'EOF'
#define _GNU_SOURCE
#define PS_WORKER_TEST_HOOKS 1
#include "privsep_parent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

static int PASS, FAIL, SKIP;
#define CHECK(cond, label) do { \
    if (cond) { printf("  PASS: %s\n", label); PASS++; } \
    else { printf("  FAIL: %s\n", label); FAIL++; } \
} while (0)

static const char *dir;

/* Run fn in a forked child; its exit code is the result (0 = ok). */
static int in_child(int (*fn)(void)) {
    int st;
    pid_t p;

    fflush(NULL);
    p = fork();
    if (p == 0)
        _exit(fn());
    if (p < 0 || waitpid(p, &st, 0) != p)
        return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 100 + WTERMSIG(st);
}

static int status_hex(const char *key, uint64_t *out) {
    char line[256];
    size_t n = strlen(key);
    FILE *f = fopen("/proc/self/status", "re");

    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f))
        if (!strncmp(line, key, n) && line[n] == ':') {
            fclose(f);
            *out = strtoull(line + n + 1, NULL, 16);
            return 0;
        }
    fclose(f);
    return -1;
}

static int status_int(const char *key, long *out) {
    char line[256];
    size_t n = strlen(key);
    FILE *f = fopen("/proc/self/status", "re");

    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f))
        if (!strncmp(line, key, n) && line[n] == ':') {
            fclose(f);
            *out = strtol(line + n + 1, NULL, 10);
            return 0;
        }
    fclose(f);
    return -1;
}

/* ---- the state after a successful lockdown, as an auditor reads it ---- */
static int c_state(void) {
    uint64_t eff, prm, inh, bnd, amb;
    long nnp;

    if (ps_parent_lockdown() != 0)
        return 1;
    if (status_hex("CapEff", &eff) || status_hex("CapPrm", &prm) ||
        status_hex("CapInh", &inh) || status_hex("CapBnd", &bnd) ||
        status_hex("CapAmb", &amb) || status_int("NoNewPrivs", &nnp))
        return 2;
    if (eff != PS_PARENT_CAPS) return 3;
    if (prm != PS_PARENT_CAPS) return 4;
    if (bnd != PS_PARENT_CAPS) return 5;
    if (inh != 0) return 6;
    if (amb != 0) return 7;
    if (nnp != 1) return 8;
    if (getuid() != 0 || geteuid() != 0) return 9; /* still root */
    return 0;
}

/* ---- what it must still be able to do ---- */
static int c_keeps(void) {
    char p[512], q[512];
    int fd;
    struct stat sb;

    if (ps_parent_lockdown() != 0)
        return 1;
    snprintf(p, sizeof(p), "%s/keeps", dir);
    fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return 2;
    close(fd);
    if (chown(p, 65534, 65534) != 0) return 3;       /* CAP_CHOWN */
    if (chmod(p, 0000) != 0) return 4;               /* CAP_FOWNER (not owner) */
    fd = open(p, O_RDONLY);                          /* CAP_DAC_OVERRIDE */
    if (fd < 0) return 5;
    close(fd);
    snprintf(q, sizeof(q), "%s/keeps_link", dir);
    fd = open(p, O_RDONLY);
    if (fd < 0) return 6;
    if (linkat(fd, "", AT_FDCWD, q, AT_EMPTY_PATH) != 0) { /* DAC_READ_SEARCH */
        close(fd);
        return 7;
    }
    close(fd);
    if (stat(q, &sb) != 0 || sb.st_uid != 65534) return 8;
    if (unlink(q) != 0) return 9;                    /* CAP_FOWNER-ish, dir is ours */
    return 0;
}

/* ---- what it must no longer be able to do ---- */
static int c_loses(void) {
    struct __user_cap_header_struct hdr = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct d[2];

    if (ps_parent_lockdown() != 0)
        return 1;
    errno = 0;
    if (setuid(65534) == 0 || errno != EPERM) return 2;   /* no CAP_SETUID */
    errno = 0;
    if (setgid(65534) == 0 || errno != EPERM) return 3;   /* no CAP_SETGID */
    errno = 0;
    if (prctl(PR_CAPBSET_DROP, CAP_CHOWN, 0, 0, 0) == 0 ||
        errno != EPERM) return 4;                         /* no CAP_SETPCAP */
    if (prctl(PR_CAPBSET_READ, CAP_SETUID, 0, 0, 0) != 0) return 6;
    if (prctl(PR_CAPBSET_READ, CAP_KILL, 0, 0, 0) != 0) return 7;
    if (prctl(PR_CAPBSET_READ, CAP_SYS_PTRACE, 0, 0, 0) != 0) return 8;
    if (prctl(PR_CAPBSET_READ, CAP_SYS_MODULE, 0, 0, 0) != 0) return 9;
    /* A capability that left the bounding set cannot be put back. */
    memset(d, 0, sizeof(d));
    d[0].permitted = d[0].effective = (uint32_t)(PS_PARENT_CAPS | (1ULL << CAP_SETUID));
    d[0].inheritable = 0;
    errno = 0;
    if (syscall(SYS_capset, &hdr, d) == 0 || errno != EPERM) return 10;
    return 0;
}

/* ---- ps_client_stop() SIGKILLs the spawner: root to root needs no CAP_KILL ---- */
static int c_kills_spawner(void) {
    pid_t g = fork();
    int st;

    if (g < 0) return 90;
    if (g == 0) {
        for (;;)
            pause();
    }
    if (ps_parent_lockdown() != 0) { kill(g, SIGKILL); waitpid(g, &st, 0); return 1; }
    if (kill(g, SIGKILL) != 0) { kill(g, SIGKILL); waitpid(g, &st, 0); return 2; }
    if (waitpid(g, &st, 0) != g || !WIFSIGNALED(st) || WTERMSIG(st) != SIGKILL) return 3;
    return 0;
}

/* ---- idempotent: a second call on an already-locked process succeeds ---- */
static int c_twice(void) {
    return ps_parent_lockdown() == 0 && ps_parent_lockdown() == 0 ? 0 : 1;
}

/* ---- a bounding set that lacks a needed capability fails step 1 ---- */
static int c_bnd_short(void) {
    int r;

    if (prctl(PR_CAPBSET_DROP, CAP_CHOWN, 0, 0, 0) != 0) return 90;
    errno = 0;
    r = ps_parent_lockdown();
    if (r != PS_P_BOUNDING_SET) return 1;
    if (errno != EPERM) return 2;
    return 0;
}

/* ---- failure injected at each step, and nothing after it ran ---- */
static int inject(int step) {
    uint64_t bnd = 0;
    long nnp = -1;
    int r;

    ps_test_parent_fail_step = step;
    errno = 0;
    r = ps_parent_lockdown();
    if (r != step) return 1;
    if (errno != EIO) return 2;
    status_hex("CapBnd", &bnd);
    status_int("NoNewPrivs", &nnp);
    /* step 1 failing means nothing was dropped; step 3 failing means the
     * capabilities were already cut but NO_NEW_PRIVS was not set */
    if (step == PS_P_BOUNDING_SET && bnd == PS_PARENT_CAPS) return 3;
    if (step == PS_P_NO_NEW_PRIVS && (bnd != PS_PARENT_CAPS || nnp != 0)) return 4;
    if (step != PS_P_NO_NEW_PRIVS && nnp != 0) return 5;
    return 0;
}
static int c_inj1(void) { return inject(PS_P_BOUNDING_SET); }
static int c_inj2(void) { return inject(PS_P_CAPABILITIES); }
static int c_inj3(void) { return inject(PS_P_NO_NEW_PRIVS); }

int main(int argc, char **argv) {
    int root = geteuid() == 0;
    struct { const char *label; int (*fn)(void); } t[] = {
        {"state read back from /proc: caps, bounding set, inheritable, ambient, NO_NEW_PRIVS, still uid 0", c_state},
        {"still able to chown, chmod, read a mode-0000 file and linkat(AT_EMPTY_PATH) on another uid's file", c_keeps},
        {"no longer able to setuid, setgid, drop bounding caps, or regain CAP_SETUID", c_loses},
        {"can still SIGKILL a root process of its own uid (the spawner) without CAP_KILL", c_kills_spawner},
        {"calling it twice succeeds", c_twice},
        {"a bounding set missing CAP_CHOWN fails step 1 with EPERM", c_bnd_short},
        {"failure at step 1 leaves the bounding set untouched", c_inj1},
        {"failure at step 2 returns step 2 and sets no NO_NEW_PRIVS", c_inj2},
        {"failure at step 3 returns step 3 with the capabilities already cut", c_inj3},
    };

    if (argc < 2) return 2;
    dir = argv[1];
    printf("PS_PARENT_CAPS = 0x%llx\n", (unsigned long long)PS_PARENT_CAPS);
    CHECK(PS_PARENT_CAPS == 0x20100fULL, "mask is NET_ADMIN|SYS_ADMIN|DAC_READ_SEARCH|DAC_OVERRIDE|FOWNER|CHOWN (0x20100f)");
    CHECK(!(PS_PARENT_CAPS & PS_SPAWNER_CAPS), "parent and spawner capability sets are disjoint");
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        int r;

        if (!root) {
            printf("  SKIP: %s (needs root)\n", t[i].label);
            SKIP++;
            continue;
        }
        r = in_child(t[i].fn);
        if (r != 0) printf("    (child returned %d)\n", r);
        CHECK(r == 0, t[i].label);
    }
    printf("\n===================================\n");
    printf("privsep_parent: %d passed, %d failed, %d skipped\n", PASS, FAIL, SKIP);
    printf("===================================\n");
    return FAIL ? 1 : 0;
}
EOF

echo "### privsep_parent.h (ASan+UBSan) ###"
gcc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$SRC_DIR" -o "$BUILD_DIR/t" "$BUILD_DIR/t.c" || { echo "FAIL: build"; exit 1; }
mkdir -p "$BUILD_DIR/work"
"$BUILD_DIR/t" "$BUILD_DIR/work"
