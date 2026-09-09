/*
 * netlink_chan.c - kernel-side Generic Netlink channel to avd.
 * See docs/netlink-protocol.md for the full protocol design/rationale.
 *
 * UNTESTED AGAINST REAL KERNEL HEADERS AT TIME OF WRITING - the genl
 * API (particularly where .policy lives on struct genl_family vs.
 * struct genl_ops) has moved across kernel versions. This targets the
 * layout used in 5.10+ kernels (covers all three CI targets: 6.12,
 * 6.18, 7.1.4). Build and test this carefully in your VM before
 * trusting it - see the testing checklist in the PR/commit this ships
 * with.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include <linux/notifier.h>
#include <net/genetlink.h>

#include "netlink_proto.h"
#include "netlink_chan.h"

/* ---- daemon registration state ---- */

static u32 daemon_portid;
static bool daemon_registered;
static DEFINE_SPINLOCK(daemon_lock);

/* Fires on NETLINK_URELEASE (any unicast netlink socket closing,
 * system-wide) - the only way this module learns a registered daemon
 * is gone if it dies (SIGKILL, crash) instead of exiting cleanly.
 * Without this, daemon_registered stays stuck true after an unclean
 * daemon death: every scan request keeps trying to unicast to a dead
 * portid until genlmsg_unicast() itself starts failing (fast, since
 * the kernel's own netlink core already knows that portid is gone -
 * no hang, no wait for DAEMON_TIMEOUT_MS), but the registration state
 * stays stale and misleading (e.g. to a future av_sigtable_count()-
 * style status readout) until a new daemon happens to register and
 * overwrite it. Checked against NETLINK_GENERIC specifically since
 * this notifier fires for every protocol's netlink sockets releasing
 * system-wide, not just this module's own family. */
/* data cannot be const void * - notifier_call must match the kernel's
 * fixed int (*)(struct notifier_block *, unsigned long, void *)
 * signature exactly, same class of false positive as the other
 * cppcheck-suppress comments in this codebase (see sigtable.c/
 * behavior.c) - a real constraint cppcheck cannot see from this
 * file alone, not a genuinely fixable style issue. */
/* cppcheck-suppress constParameterCallback */
static int av_netlink_notify(struct notifier_block *nb, unsigned long event, void *data)
{
    const struct netlink_notify *n = data;

    if (event != NETLINK_URELEASE || n->protocol != NETLINK_GENERIC)
        return NOTIFY_DONE;

    spin_lock(&daemon_lock);
    if (daemon_registered && n->portid == daemon_portid) {
        daemon_registered = false;
        spin_unlock(&daemon_lock);
        pr_info("kernel-av: netlink daemon (portid=%u) disconnected - "
                "fail-open on scans until it re-registers\n", n->portid);
        return NOTIFY_DONE;
    }
    spin_unlock(&daemon_lock);

    return NOTIFY_DONE;
}

static struct notifier_block av_netlink_notifier = {
    .notifier_call = av_netlink_notify,
};
/* ---- pending scan requests, correlated by REQID ---- */

struct av_pending_scan {
    struct list_head list;
    u64 reqid;
    struct completion done;
    int verdict;                       /* -1 until a verdict arrives */
    char rule_name[AV_RULE_NAME_MAXLEN + 1];
};

static LIST_HEAD(pending_list);
static DEFINE_SPINLOCK(pending_lock);
static atomic64_t reqid_counter = ATOMIC64_INIT(0);

/* ---- policy: validates attributes on incoming messages ---- */

static const struct nla_policy av_genl_policy[AV_A_MAX + 1] = {
    [AV_A_REQID]     = { .type = NLA_U64 },
    [AV_A_PID]       = { .type = NLA_U32 },
    [AV_A_PATH]      = { .type = NLA_NUL_STRING, .len = AV_PATH_ATTR_MAXLEN - 1 },
    [AV_A_SHA256]    = { .type = NLA_NUL_STRING, .len = AV_SHA256_ATTR_MAXLEN },
    [AV_A_VERDICT]   = { .type = NLA_U8 },
    [AV_A_RULE_NAME] = { .type = NLA_NUL_STRING, .len = AV_RULE_NAME_MAXLEN },
};

/* ---- AV_C_REGISTER: daemon announces itself ---- */

static int av_nl_register_doit(struct sk_buff *skb, struct genl_info *info)
{
    /* GENL_ADMIN_PERM on this op (see av_genl_ops below) already
     * requires CAP_NET_ADMIN, so any caller that reaches this point is
     * privileged - but a second privileged process could still hijack
     * the scan channel by overwriting daemon_portid, redirecting all
     * future SCAN_REQUEST unicasts (and the power to answer them) to
     * itself. Reject a second REGISTER while one is live with -EBUSY
     * and log the attempt at pr_alert level. A re-REGISTER from the
     * already-pinned portid stays idempotent (returns 0): avd
     * restarting on the same socket, or a duplicate REGISTER, is not
     * a hijack. A genuinely new daemon after a crash is also safe:
     * av_netlink_notify() clears daemon_registered on NETLINK_URELEASE
     * when the old socket closes, so by the time its replacement
     * registers the slot is already free. */
    spin_lock(&daemon_lock);
    if (daemon_registered && info->snd_portid != daemon_portid) {
        u32 old_portid = daemon_portid;
        u32 new_portid = info->snd_portid;

        spin_unlock(&daemon_lock);
        pr_alert("kernel-av: AV_C_REGISTER from portid %u rejected "
                 "(daemon %u already registered)\n",
                 new_portid, old_portid);
        return -EBUSY;
    }
    daemon_portid = info->snd_portid;
    daemon_registered = true;
    spin_unlock(&daemon_lock);

    pr_info("kernel-av: netlink daemon registered (portid=%u)\n",
            info->snd_portid);
    return 0;
}

/* ---- AV_C_VERDICT: daemon's reply to a scan request ---- */

static int av_nl_verdict_doit(struct sk_buff *skb, struct genl_info *info)
{
    /* p is initialized to NULL only to satisfy static analyzers that
     * can't expand list_for_each_entry() (a nested kernel macro
     * requiring full kernel headers to resolve) - the macro itself
     * always assigns p via list_entry()/container_of() before the loop
     * body runs, so this has no effect on actual behavior. Same
     * false-positive class as get_or_create_entry() in behavior.c. */
    struct av_pending_scan *p = NULL, *found = NULL;
    u64 reqid;
    u8 verdict;
    char rule_name[AV_RULE_NAME_MAXLEN + 1] = "";

    if (!info->attrs[AV_A_REQID] || !info->attrs[AV_A_VERDICT])
        return -EINVAL;

    /* Only the currently-registered daemon's portid may answer a scan
     * request. GENL_ADMIN_PERM (see av_genl_ops) already restricts who
     * can reach this handler at all, but that alone isn't enough: any
     * two CAP_NET_ADMIN processes could otherwise race to answer each
     * other's requests. Binding to the specific registered portid closes
     * that gap without needing anything fancier. */
    spin_lock(&daemon_lock);
    if (!daemon_registered || info->snd_portid != daemon_portid) {
        spin_unlock(&daemon_lock);
        pr_warn("kernel-av: AV_C_VERDICT from portid %u ignored (not the "
                "registered daemon)\n", info->snd_portid);
        return -EPERM;
    }
    spin_unlock(&daemon_lock);

    reqid = nla_get_u64(info->attrs[AV_A_REQID]);
    verdict = nla_get_u8(info->attrs[AV_A_VERDICT]);
    /* Only AV_VERDICT_CLEAN (0) and AV_VERDICT_MALICIOUS (1) are
     * defined (netlink_proto.h) - anything else is a malformed or
     * malicious verdict. Reject it here with -EINVAL rather than
     * letting av_work_fn() treat every non-MALICIOUS value as clean
     * by omission, which would silently mask daemon bugs and widen
     * the accepted input space for a compromised/buggy sender. */
    if (verdict != AV_VERDICT_CLEAN && verdict != AV_VERDICT_MALICIOUS) {
        pr_warn("kernel-av: AV_C_VERDICT with invalid verdict %u "
                "(reqid %llu) rejected\n", verdict,
                (unsigned long long)reqid);
        return -EINVAL;
    }
    if (info->attrs[AV_A_RULE_NAME])
        nla_strscpy(rule_name, info->attrs[AV_A_RULE_NAME], sizeof(rule_name));

    spin_lock(&pending_lock);
    list_for_each_entry(p, &pending_list, list) {
        if (p->reqid == reqid) {
            list_del_init(&p->list);
            found = p;
            break;
        }
    }
    spin_unlock(&pending_lock);

    if (!found) {
        /* Stale or duplicate reply (e.g. we already timed out and gave
         * up) - not an error worth failing the netlink call over. */
        pr_debug("kernel-av: verdict for unknown/expired reqid %llu\n",
                 (unsigned long long)reqid);
        return 0;
    }

    found->verdict = verdict;
    strscpy(found->rule_name, rule_name, sizeof(found->rule_name));
    complete(&found->done); /* waiter frees `found` after this returns */

    return 0;
}

static const struct genl_ops av_genl_ops[] = {
    {
        .cmd = AV_C_REGISTER,
        .doit = av_nl_register_doit,
        .flags = GENL_ADMIN_PERM, /* CAP_NET_ADMIN only - see the
                                    * netlink-auth note in
                                    * docs/netlink-protocol.md */
    },
    {
        .cmd = AV_C_VERDICT,
        .doit = av_nl_verdict_doit,
        .flags = GENL_ADMIN_PERM,
    },
};

static struct genl_family av_genl_family = {
    .name    = AV_GENL_FAMILY_NAME,
    .version = AV_GENL_VERSION,
    .maxattr = AV_A_MAX,
    .policy  = av_genl_policy,
    .ops     = av_genl_ops,
    .n_ops   = ARRAY_SIZE(av_genl_ops),
    .module  = THIS_MODULE, /* Without this, generic netlink has no way
                              * to pin this module while av_nl_register_doit()
                              * or av_nl_verdict_doit() is actively running
                              * on another CPU - an rmmod racing an
                              * in-flight callback from avd would then
                              * be a genuine use-after-free of module
                              * code, not just a theoretical one. */
};

/* ---- sending a scan request and waiting for the verdict ---- */

int av_netlink_scan_request(const char *path, const char *sha256_hex,
                             pid_t pid, int *verdict_out,
                             char *rule_out, size_t rule_out_len,
                             unsigned int timeout_ms)
{
    struct av_pending_scan *p;
    struct sk_buff *skb;
    void *hdr;
    u32 portid;
    bool registered;
    int ret;
    size_t payload_size;

    spin_lock(&daemon_lock);
    registered = daemon_registered;
    portid = daemon_portid;
    spin_unlock(&daemon_lock);

    if (!registered)
        return -ENOTCONN;

    p = kzalloc(sizeof(*p), GFP_KERNEL);
    if (!p)
        return -ENOMEM;

    p->reqid = atomic64_inc_return(&reqid_counter);
    p->verdict = -1;
    init_completion(&p->done);

    spin_lock(&pending_lock);
    list_add(&p->list, &pending_list);
    spin_unlock(&pending_lock);

    /* Size the skb from the actual attributes being written rather than
     * guessing with NLMSG_DEFAULT_SIZE - AV_A_PATH alone can be up to
     * PATH_MAX, which doesn't fit in NLMSG_DEFAULT_SIZE's ~3.7-3.8KB of
     * usable space. Undersizing here makes nla_put_string() below fail
     * with -EMSGSIZE, which av_work_fn() can't distinguish from "daemon
     * unreachable" and so falls through to fail-open, silently skipping
     * the daemon-side scan for long paths even though the daemon is up
     * and would have answered.
     *
     * AV_A_REQID is written with nla_put_u64_64bit(), which - on
     * architectures without CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS -
     * inserts an extra padding attribute to 8-byte-align the u64
     * payload. Sizing it with plain nla_total_size() misses that pad
     * attribute's space on those architectures, so use
     * nla_total_size_64bit() to match. */
    payload_size = nla_total_size_64bit(sizeof(u64)) +
                   nla_total_size(sizeof(u32)) +
                   nla_total_size(strlen(path) + 1) +
                   nla_total_size(strlen(sha256_hex) + 1);

    skb = genlmsg_new(payload_size, GFP_KERNEL);
    if (!skb) {
        ret = -ENOMEM;
        goto err_remove_pending;
    }

    hdr = genlmsg_put(skb, 0, 0, &av_genl_family, 0, AV_C_SCAN_REQUEST);
    if (!hdr) {
        ret = -EMSGSIZE;
        goto err_free_skb;
    }

    ret = nla_put_u64_64bit(skb, AV_A_REQID, p->reqid, 0);
    ret = ret ?: nla_put_u32(skb, AV_A_PID, pid);
    ret = ret ?: nla_put_string(skb, AV_A_PATH, path);
    ret = ret ?: nla_put_string(skb, AV_A_SHA256, sha256_hex);
    if (ret)
        goto err_free_skb;

    genlmsg_end(skb, hdr);

    /* genlmsg_unicast() consumes skb regardless of return value. */
    ret = genlmsg_unicast(&init_net, skb, portid);
    if (ret) {
        pr_warn("kernel-av: netlink unicast to daemon failed: %d\n", ret);
        goto err_remove_pending;
    }

    if (!wait_for_completion_timeout(&p->done, msecs_to_jiffies(timeout_ms))) {
        bool still_pending;

        spin_lock(&pending_lock);
        still_pending = !list_empty(&p->list);
        if (still_pending)
            list_del_init(&p->list);
        spin_unlock(&pending_lock);

        if (still_pending) {
            kfree(p);
            return -ETIMEDOUT;
        }
        /* Verdict handler already dequeued p right as our timeout
         * fired (raced at the boundary) and is about to complete it -
         * wait unconditionally, it'll be immediate. */
        wait_for_completion(&p->done);
    }

    *verdict_out = p->verdict;
    if (rule_out)
        strscpy(rule_out, p->rule_name, rule_out_len);
    kfree(p);
    return 0;

err_free_skb:
    nlmsg_free(skb);
err_remove_pending:
    spin_lock(&pending_lock);
    list_del(&p->list);
    spin_unlock(&pending_lock);
    kfree(p);
    return ret;
}

int av_netlink_init(void)
{
    int ret;

    /* Notifier registered BEFORE the genl_family, and unregistered
     * AFTER it below (reverse order) - this is the only ordering that
     * closes the race entirely: once genl_register_family() returns,
     * avd can immediately resolve the family and send AV_C_REGISTER.
     * If the notifier weren't already listening at that exact moment,
     * a daemon that registers and then crashes within that narrow
     * window would leave daemon_registered stuck true with nothing
     * left listening for its NETLINK_URELEASE. Registering the
     * notifier first means no registration can ever happen before
     * we're already watching for its release. */
    ret = netlink_register_notifier(&av_netlink_notifier);
    if (ret)
        return ret;

    ret = genl_register_family(&av_genl_family);
    if (ret) {
        netlink_unregister_notifier(&av_netlink_notifier);
        return ret;
    }

    return 0;
}

void av_netlink_exit(void)
{
    struct av_pending_scan *p, *tmp;

    /* Reverse of av_netlink_init()'s registration order - see its
     * comment. Unregistering the family first means no new
     * AV_C_REGISTER can land after this point, so there is nothing
     * left for the notifier to meaningfully catch by the time it goes
     * too. */
    genl_unregister_family(&av_genl_family);
    netlink_unregister_notifier(&av_netlink_notifier);

    /* Wake up (with a "no verdict" result) anything still waiting - by
     * this point the kprobe is already unregistered and the workqueue
     * is being flushed, so this is defensive rather than expected to
     * fire in normal operation. */
    spin_lock(&pending_lock);
    list_for_each_entry_safe(p, tmp, &pending_list, list) {
        list_del(&p->list);
        complete(&p->done);
    }
    spin_unlock(&pending_lock);
}
