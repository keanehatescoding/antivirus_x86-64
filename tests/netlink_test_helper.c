/* SPDX-License-Identifier: MIT */
/*
 * netlink_test_helper.c - throwaway client for tests/test_netlink.sh.
 *
 * avd (userspace/avd/avd.c) only ever sends AV_C_REGISTER/AV_C_VERDICT
 * via nl_send_auto() (fire-and-forget, no ack, no error reporting) -
 * fine for avd itself, which always runs as root and only ever talks
 * to a module it trusts, but useless for a test that needs to observe
 * *rejections* (wrong privilege, wrong portid, malformed attributes).
 * This is a minimal standalone genl client, built only for tests, that
 * requests an ack via nl_send_sync() and reports exactly what the
 * kernel said - never linked into avd or any shipped binary.
 *
 * Usage:
 *   netlink_test_helper resolve
 *   netlink_test_helper register
 *   netlink_test_helper verdict <reqid> <0|1> [rule_name]
 *   netlink_test_helper malformed-verdict
 *   netlink_test_helper oversized-verdict
 *   netlink_test_helper batch
 *   netlink_test_helper drain      (batch mode: discard queued input - see below)
 * Every mode above but `batch` is single-shot: connect, do one thing,
 * exit - which also closes the socket, so its kernel-assigned netlink
 * portid is gone by the time the next invocation runs (a *different*
 * process = a *different* portid). That's fine for "is a portid that
 * was never registered rejected" (any fresh single-shot process proves
 * that), but it can't prove "did registering daemon Y actually replace
 * *this specific* previously-registered daemon X's portid", since
 * proving that needs to send from X's portid again *after* Y
 * registers - which needs X's process, and therefore its socket, to
 * still be alive at that point. `batch` reads one command per line
 * from stdin (same verbs as above, minus the program name - e.g.
 * "verdict 1 0"), runs each on the *same* connection, and prints one
 * "OK"/"ERR ..." reply line per command - so a caller (the shell
 * script, via `coproc`) can hold two of these open at once and
 * interleave commands between them.
 *
 * Prints "OK" and exits 0 on success. On failure prints "ERR <errno>
 * <strerror>" and exits 1, so the calling shell script can grep for
 * the specific errno it expects (e.g. "ERR -1 Operation not
 * permitted") rather than just pass/fail on exit status alone.
 */
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../av/netlink_proto.h"

static struct nl_sock *sock;
static int family_id;

static int connect_and_resolve(void)
{
    sock = nl_socket_alloc();
    if (!sock) {
        fprintf(stderr, "ERR -1 nl_socket_alloc failed\n");
        return -1;
    }
    if (genl_connect(sock) < 0) {
        fprintf(stderr, "ERR -1 genl_connect failed (is av.ko loaded?)\n");
        return -1;
    }
    family_id = genl_ctrl_resolve(sock, AV_GENL_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "ERR %d family '%s' not found (is av.ko loaded?)\n",
                family_id, AV_GENL_FAMILY_NAME);
        return -1;
    }
    return 0;
}

/* Builds and synchronously sends one genl message, requesting an ack
 * so nl_send_sync() actually blocks for and reports the kernel's real
 * verdict (0 on an ack, negative errno on an NLMSG_ERROR) instead of
 * just "did the local send() syscall succeed" like avd's own
 * fire-and-forget nl_send_auto() calls. fill() returns 0 on success,
 * negative on attribute-build failure - a failed build frees the
 * partially-built message and reports without sending, rather than
 * transmitting a truncated message the kernel would then have to
 * interpret. */
static int send_and_report(uint8_t cmd, int (*fill)(struct nl_msg *, void *),
                            void *ctx)
{
    struct nl_msg *msg;
    int ret;

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "ERR -1 nlmsg_alloc failed\n");
        return 1;
    }
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0,
                      NLM_F_ACK, cmd, AV_GENL_VERSION)) {
        fprintf(stderr, "ERR -1 genlmsg_put failed\n");
        nlmsg_free(msg);
        return 1;
    }
    if (fill && fill(msg, ctx) < 0) {
        nlmsg_free(msg);
        return 1;
    }

    ret = nl_send_sync(sock, msg); /* consumes msg regardless of result */
    if (ret < 0) {
        fprintf(stderr, "ERR %d %s\n", ret, nl_geterror(ret));
        return 1;
    }
    printf("OK\n");
    return 0;
}

struct verdict_args {
    uint64_t reqid;
    uint8_t verdict;
    const char *rule_name;
    int skip_reqid;   /* malformed-verdict: omit AV_A_REQID entirely */
    size_t rule_len;  /* oversized-verdict: force an over-limit string */
};

static int fill_verdict(struct nl_msg *msg, void *ctx)
{
    struct verdict_args *a = ctx;
    char *big = NULL;
    int rc = 0;

    if (!a->skip_reqid)
        NLA_PUT_U64(msg, AV_A_REQID, a->reqid);
    NLA_PUT_U8(msg, AV_A_VERDICT, a->verdict);
    if (a->rule_len) {
        big = malloc(a->rule_len + 1);
        if (!big) {
            fprintf(stderr, "ERR -1 malloc failed building verdict message\n");
            rc = -1;
            goto out;
        }
        memset(big, 'A', a->rule_len);
        big[a->rule_len] = '\0';
        NLA_PUT_STRING(msg, AV_A_RULE_NAME, big);
    } else if (a->rule_name && a->rule_name[0]) {
        NLA_PUT_STRING(msg, AV_A_RULE_NAME, a->rule_name);
    }
    goto out;

nla_put_failure:
    fprintf(stderr, "ERR -1 NLA_PUT failed building verdict message\n");
    rc = -1;
out:
    free(big);
    return rc;
}

/* argv[0] is the verb itself here (no program name) - shared by
 * main()'s single-shot dispatch and batch mode's per-line dispatch,
 * both running on whatever connection connect_and_resolve() already
 * set up. */
static int run_command(int argc, char **argv)
{
    if (!strcmp(argv[0], "resolve")) {
        printf("OK family_id=%d\n", family_id);
        return 0;
    }

    if (!strcmp(argv[0], "register")) {
        return send_and_report(AV_C_REGISTER, NULL, NULL);
    }

    if (!strcmp(argv[0], "verdict")) {
        struct verdict_args a = {0};

        if (argc < 3) {
            fprintf(stderr, "ERR -1 usage: verdict <reqid> <0|1> [rule_name]\n");
            return 1;
        }
        a.reqid = strtoull(argv[1], NULL, 10);
        a.verdict = (uint8_t)strtoul(argv[2], NULL, 10);
        a.rule_name = argc > 3 ? argv[3] : NULL;
        return send_and_report(AV_C_VERDICT, fill_verdict, &a);
    }

    if (!strcmp(argv[0], "malformed-verdict")) {
        /* Missing AV_A_REQID - av_nl_verdict_doit() requires it and
         * returns -EINVAL, but only after genl's own generic attribute
         * validation against av_genl_policy has already passed (an
         * absent optional-looking attribute isn't itself a policy
         * violation - the field-level "is this actually present"
         * check is on avctl/kernel side). */
        struct verdict_args a = {.verdict = AV_VERDICT_CLEAN, .skip_reqid = 1};
        return send_and_report(AV_C_VERDICT, fill_verdict, &a);
    }

    if (!strcmp(argv[0], "oversized-verdict")) {
        /* AV_A_RULE_NAME's declared policy length is
         * AV_RULE_NAME_MAXLEN (63) - well past that should be rejected
         * by genl's own nla_policy length check before av_nl_verdict_
         * doit() ever runs, regardless of privilege/portid. */
        struct verdict_args a = {
            .reqid = 1, .verdict = AV_VERDICT_CLEAN,
            .rule_len = AV_RULE_NAME_MAXLEN + 128,
        };
        return send_and_report(AV_C_VERDICT, fill_verdict, &a);
    }

    if (!strcmp(argv[0], "drain")) {
        /* Discard every datagram currently queued on this connection's
         * socket, then report OK. Only meaningful in batch mode (a
         * single-shot connection starts with an empty buffer by
         * construction), where the socket stays open across shell
         * commands: while this connection's portid is the registered
         * daemon, *every* exec on the system - including the test
         * script's own external commands - makes the kernel unicast an
         * async SCAN_REQUEST at it, and a queued upcall makes the next
         * synchronous nl_send_sync() fail with NLE_SEQ_MISMATCH (plus
         * stale replies corrupting later reads). Draining immediately
         * before a register/verdict, with builtins only in between,
         * keeps each exchange exact. Raw recv(), not libnl dispatch:
         * consumption is all that matters here, and bypassing libnl
         * keeps its sequence/callback state untouched for the real
         * exchanges that follow. */
        static char buf[8192];
        for (;;) {
            ssize_t n = recv(nl_socket_get_fd(sock), buf, sizeof(buf),
                             MSG_DONTWAIT);
            if (n >= 0)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            fprintf(stderr, "ERR -1 drain recv failed: %s\n",
                    strerror(errno));
            return 1;
        }
        printf("OK\n");
        return 0;
    }

    fprintf(stderr, "ERR -1 unknown verb: %s\n", argv[0]);
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s resolve|register|verdict|malformed-verdict|oversized-verdict|batch|drain\n",
                argv[0]);
        return 2;
    }

    /* Line-buffer stdout: batch mode's caller reads one reply per
     * line over a pipe as each command completes, which needs each
     * reply flushed immediately rather than sitting in libc's default
     * full-buffering-on-a-non-tty until exit. Harmless for the
     * single-shot verbs below, which print once and exit anyway. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (connect_and_resolve())
        return 1;

    if (!strcmp(argv[1], "batch")) {
        char line[512];

        while (fgets(line, sizeof(line), stdin)) {
            char *tokens[8];
            int ntok = 0;
            char *save = NULL;
            char *tok = strtok_r(line, " \t\r\n", &save);

            while (tok && ntok < 8) {
                tokens[ntok++] = tok;
                tok = strtok_r(NULL, " \t\r\n", &save);
            }
            if (ntok == 0)
                continue;
            run_command(ntok, tokens);
        }
        return 0;
    }

    return run_command(argc - 1, argv + 1);
}
