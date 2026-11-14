/*
 * tests/avd_unit_seccomp.c - apply a SystemCallFilter= allowlist the way
 * systemd does, then exec a command:
 *
 *     avd_unit_seccomp NAME... --known KNOWN... -- PROG [ARG...]
 *
 * The end-to-end tests run avd in virtme-ng, which has no systemd as init, so
 * tests/avd_unit_caps.sh expands packaging/avd.service's SystemCallFilter=
 * lines into syscall names (systemd-analyze syscall-filter) and starts avd
 * under this. KNOWN is systemd's @known group, expanded the same way.
 *
 * Like systemd 262 with SystemCallArchitectures=native and no
 * SystemCallErrorNumber= (seccomp_load_syscall_filter_set_raw()):
 *   - NAME... and the calls systemd always allows (execve, exit, exit_group,
 *     getrlimit, rt_sigreturn, sigreturn, and the ones that read the time or
 *     sleep) are allowed;
 *   - every other call in KNOWN kills the process (SIGSYS);
 *   - anything else, a call newer than systemd knows, fails with ENOSYS, so
 *     libc can fall back as it would under the installed unit;
 *   - any other architecture and the x32 ABI kill the process. systemd does
 *     this in a separate filter; here it is the same filter's bad-arch
 *     action, which only changes the Seccomp_filters count.
 * Names this architecture does not have are skipped, as systemd skips them.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_NR 4096 /* x86-64 numbers are well under this */

static const char *const implicit[] = {
    "execve", "exit", "exit_group", "getrlimit", "rt_sigreturn", "sigreturn",
    "clock_getres", "clock_gettime", "clock_nanosleep", "gettimeofday",
    "nanosleep", "time",
};

static bool allowed[MAX_NR];

/* Adds `action` for `name` unless the name is not a syscall here, or (for
 * the kill rules) it is already allowed. Returns -1 on a real error. */
static int add(scmp_filter_ctx ctx, const char *name, uint32_t action) {
  int nr = seccomp_syscall_resolve_name(name);
  int r;

  if (nr == __NR_SCMP_ERROR || nr < 0) /* not a syscall on x86-64 */
    return 0;
  if (nr >= MAX_NR) {
    fprintf(stderr, "avd_unit_seccomp: %s: number %d too large\n", name, nr);
    return -1;
  }
  if (allowed[nr]) return 0;
  r = seccomp_rule_add(ctx, action, nr, 0);
  if (r != 0 && r != -EEXIST) {
    fprintf(stderr, "avd_unit_seccomp: %s: %s\n", name, strerror(-r));
    return -1;
  }
  if (action == SCMP_ACT_ALLOW) allowed[nr] = true;
  return 0;
}

int main(int argc, char **argv) {
  scmp_filter_ctx ctx;
  int known = -1, sep = -1, r;

  for (int i = 1; i < argc; i++) {
    if (known < 0 && strcmp(argv[i], "--known") == 0) {
      known = i;
    } else if (strcmp(argv[i], "--") == 0) {
      sep = i;
      break;
    }
  }
  if (known < 0 || sep < 0 || known + 1 >= sep || sep >= argc - 1) {
    fprintf(stderr,
            "usage: avd_unit_seccomp NAME... --known KNOWN... -- PROG "
            "[ARG...]\n");
    return 2;
  }
  ctx = seccomp_init(SCMP_ACT_ERRNO(ENOSYS));
  if (!ctx) {
    fprintf(stderr, "avd_unit_seccomp: seccomp_init failed\n");
    return 1;
  }
  /* The native architecture only (seccomp_init's default); everything else,
   * x32 included, kills the process rather than the thread. */
  if (seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS)) {
    fprintf(stderr, "avd_unit_seccomp: cannot set the bad-arch action\n");
    return 1;
  }
  /* Allow rules first, so the kill rules below can skip what they allow. */
  for (size_t k = 0; k < sizeof(implicit) / sizeof(implicit[0]); k++)
    if (add(ctx, implicit[k], SCMP_ACT_ALLOW)) return 1;
  for (int k = 1; k < known; k++)
    if (add(ctx, argv[k], SCMP_ACT_ALLOW)) return 1;
  for (int k = known + 1; k < sep; k++)
    if (add(ctx, argv[k], SCMP_ACT_KILL_PROCESS)) return 1;
  r = seccomp_load(ctx);
  if (r != 0) {
    fprintf(stderr, "avd_unit_seccomp: seccomp_load: %s\n", strerror(-r));
    return 1;
  }
  /* no seccomp_release(): the filter is on, and exec frees it anyway */
  execvp(argv[sep + 1], argv + sep + 1);
  fprintf(stderr, "avd_unit_seccomp: exec %s: %s\n", argv[sep + 1],
          strerror(errno));
  return 127;
}
