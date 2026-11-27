/*
 * netlink_chan.h - kernel-side Generic Netlink channel to the userspace
 * avd daemon. See docs/netlink-protocol.md for the protocol design.
 */

#ifndef AV_NETLINK_CHAN_H
#define AV_NETLINK_CHAN_H

#include <linux/types.h>

int av_netlink_init(void);
void av_netlink_exit(void);

/* Identity of the file the kernel hashed, forwarded so the daemon can
 * verify that what it opens is that same file (issue #227). Values are
 * what userspace fstat() reports: major()/minor() of st_dev, st_ino. */
struct av_scan_ident {
    u32 dev_major;
    u32 dev_minor;
    u64 ino;
};

/*
 * Sends a scan request to the registered daemon and blocks (sleepable
 * context only - call from the workqueue, never from the kprobe atomic
 * path) until a verdict arrives or timeout_ms elapses.
 *
 * ident is required. Every request this module sends carries the
 * hashed file's identity, so avd only ever scans that file (or answers
 * AV_VERDICT_UNAVAILABLE). An identity-free request is what a module
 * from before #227 sends, and avd scans it by path for compatibility;
 * sending one from here would opt back into that unchecked scan. A
 * caller without an identity must not ask the daemon at all - see
 * av_work_fn().
 *
 * Returns:
 *   0          - verdict received; *verdict_out and rule_out are valid
 *                (*verdict_out may be AV_VERDICT_UNAVAILABLE - treat it
 *                like a missing verdict)
 *   -ENOTCONN  - no daemon currently registered
 *   -ETIMEDOUT - daemon didn't reply in time
 *   <0         - other error (message build/send failure)
 */
int av_netlink_scan_request(const char *path, const char *sha256_hex,
                             pid_t pid, const struct av_scan_ident *ident,
                             int *verdict_out,
                             char *rule_out, size_t rule_out_len,
                             unsigned int timeout_ms);

#endif /* AV_NETLINK_CHAN_H */
