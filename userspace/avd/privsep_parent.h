/*
 * privsep_parent.h - the main avd process shrinks itself once the spawner
 * exists (#103, Stage 2 step 2; see docs/privilege-separation.md, "Stage 2:
 * shrink the parent").
 *
 * Until now the main process stayed root with every capability. It does not
 * need them: it never changes credentials, signals a worker (the spawner does
 * that) or executes anything. What it does need, and what this header keeps:
 *
 *   CAP_NET_ADMIN        the genl ops are GENL_ADMIN_PERM (verdicts, policy)
 *   CAP_SYS_ADMIN        fanotify permission events, and the module's trust-
 *                        list writes
 *   CAP_DAC_READ_SEARCH  linkat(AT_EMPTY_PATH) into quarantine
 *   CAP_DAC_OVERRIDE     reading a mode-0000 quarantined file back
 *   CAP_FOWNER           chmod/unlink of a file owned by someone else
 *   CAP_CHOWN            restoring a quarantined file's original owner
 *
 * Dropped: everything else, in particular CAP_SETUID, CAP_SETGID, CAP_SETPCAP,
 * CAP_KILL, CAP_SYS_PTRACE, CAP_SYS_MODULE, CAP_SYS_RAWIO and CAP_MKNOD.
 * The audit behind this list is in the design doc; it was made by reading
 * every path-, owner- and credential-affecting call in avd.c, not by tracing a
 * run, so the list is conservative on purpose (nothing was removed that a
 * reading could not clear) and the first real run is what confirms it.
 *
 * Steps, same fail-closed shape as the spawner's lockdown: the first failing
 * step is returned with errno as that step left it, and avd refuses to start.
 *
 *   1. bounding set   cut to PS_PARENT_CAPS and read back
 *   2. capabilities   effective and permitted = PS_PARENT_CAPS, inheritable
 *                     (and so ambient) empty, read back
 *   3. NO_NEW_PRIVS   set and read back
 *
 * MUST be called after the spawner was forked: the spawner inherits its
 * capabilities from the process that forks it, and the bounding set only ever
 * shrinks. Needs CAP_SETPCAP effective for step 1, so it also must run before
 * anything drops that. A bounding set that lacks one of PS_PARENT_CAPS (a
 * systemd unit with a too-small CapabilityBoundingSet=) fails step 1.
 *
 * Header-only and dependency-free like the others; compiled standalone by
 * tests/test_privsep_parent.sh. x86-64 only.
 */

#ifndef AV_PRIVSEP_PARENT_H
#define AV_PRIVSEP_PARENT_H

#include "privsep_lockdown.h"

#define PS_PARENT_CAPS                                                         \
  ((1ULL << CAP_NET_ADMIN) | (1ULL << CAP_SYS_ADMIN) |                         \
   (1ULL << CAP_DAC_READ_SEARCH) | (1ULL << CAP_DAC_OVERRIDE) |                \
   (1ULL << CAP_FOWNER) | (1ULL << CAP_CHOWN))

enum ps_parent_step {
  PS_P_BOUNDING_SET = 1,
  PS_P_CAPABILITIES,
  PS_P_NO_NEW_PRIVS,
  PS_P_STEP_COUNT /* not a step */
};

#ifdef PS_WORKER_TEST_HOOKS
/* Test builds only, like ps_test_lock_fail_step. */
static int ps_test_parent_fail_step;
#define PS_PARENT_HOOK(step)                                                   \
  do {                                                                         \
    if (ps_test_parent_fail_step == (step)) {                                  \
      errno = EIO;                                                             \
      return (step);                                                           \
    }                                                                          \
  } while (0)
#else
#define PS_PARENT_HOOK(step) ((void)0)
#endif

/* Returns 0, or the number of the step that failed (errno as it left it). */
static inline int ps_parent_lockdown(void) {
  PS_PARENT_HOOK(PS_P_BOUNDING_SET);
  if (ps_bounding_set_to(PS_PARENT_CAPS) < 0)
    return PS_P_BOUNDING_SET;

  PS_PARENT_HOOK(PS_P_CAPABILITIES);
  if (ps_set_capabilities_to(PS_PARENT_CAPS) < 0)
    return PS_P_CAPABILITIES;

  PS_PARENT_HOOK(PS_P_NO_NEW_PRIVS);
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
    return PS_P_NO_NEW_PRIVS;

  return 0;
}

#endif /* AV_PRIVSEP_PARENT_H */
