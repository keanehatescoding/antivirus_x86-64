/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * netlink_chan.h - kernel-side Generic Netlink channel to the userspace
 * avd daemon. See docs/netlink-protocol.md for the protocol design.
 */

#ifndef AV_NETLINK_CHAN_H
#define AV_NETLINK_CHAN_H

#include <linux/types.h>

int av_netlink_init(void);
void av_netlink_exit(void);

/*
 * Sends a scan request to the registered daemon and blocks (sleepable
 * context only - call from the workqueue, never from the kprobe atomic
 * path) until a verdict arrives or timeout_ms elapses.
 *
 * Returns:
 *   0          - verdict received; *verdict_out and rule_out are valid
 *   -ENOTCONN  - no daemon currently registered
 *   -ETIMEDOUT - daemon didn't reply in time
 *   <0         - other error (message build/send failure)
 */
int av_netlink_scan_request(const char *path, const char *sha256_hex,
                             pid_t pid, int *verdict_out,
                             char *rule_out, size_t rule_out_len,
                             unsigned int timeout_ms);

#endif /* AV_NETLINK_CHAN_H */
