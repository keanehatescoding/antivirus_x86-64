/*
 * tests/avd_unit_seccomp.c - apply a SystemCallFilter= allowlist the way
 * systemd does, then exec a command:
 *
 *     avd_unit_seccomp NAME... -- PROG [ARG...]
 *
 * The end-to-end tests run avd in virtme-ng, which has no systemd as init, so
 * tests/avd_unit_caps.sh expands packaging/avd.service's SystemCallFilter=
 * lines into syscall names (systemd-analyze syscall-filter) and starts avd
 * under this. Like systemd with SystemCallArchitectures=native and no
 * SystemCallErrorNumber=: anything not listed, any other architecture and the
 * x32 ABI kill the process (SIGSYS), and the calls systemd always allows
 * (execve, exit, exit_group, getrlimit, rt_sigreturn, sigreturn, and the ones
 * that read the time or sleep) are allowed as well. Names this architecture
 * does not have are skipped, as systemd skips them.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *const implicit[] = {
    "execve", "exit", "exit_group", "getrlimit", "rt_sigreturn", "sigreturn",
    "clock_getres", "clock_gettime", "clock_nanosleep", "gettimeofday",
    "nanosleep", "time",
};

static int allow(scmp_filter_ctx ctx, const char *name, int *skipped) {
  int nr = seccomp_syscall_resolve_name(name);
  int r;

  if (nr == __NR_SCMP_ERROR || nr < 0) { /* not a syscall on x86-64 */
    (*skipped)++;
    return 0;
  }
  r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0);
  if (r != 0 && r != -EEXIST) {
    fprintf(stderr, "avd_unit_seccomp: %s: %s\n", name, strerror(-r));
    return -1;
  }
  return 0;
}

int main(int argc, char **argv) {
  scmp_filter_ctx ctx;
  int i, skipped = 0, r;

  for (i = 1; i < argc && strcmp(argv[i], "--") != 0; i++)
    ;
  if (i >= argc - 1) {
    fprintf(stderr, "usage: avd_unit_seccomp NAME... -- PROG [ARG...]\n");
    return 2;
  }
  ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
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
  for (size_t k = 0; k < sizeof(implicit) / sizeof(implicit[0]); k++)
    if (allow(ctx, implicit[k], &skipped)) return 1;
  for (int k = 1; k < i; k++)
    if (allow(ctx, argv[k], &skipped)) return 1;
  r = seccomp_load(ctx);
  if (r != 0) {
    fprintf(stderr, "avd_unit_seccomp: seccomp_load: %s\n", strerror(-r));
    return 1;
  }
  /* no seccomp_release(): the filter is on, and exec frees it anyway */
  execvp(argv[i + 1], argv + i + 1);
  fprintf(stderr, "avd_unit_seccomp: exec %s: %s\n", argv[i + 1],
          strerror(errno));
  return 127;
}
