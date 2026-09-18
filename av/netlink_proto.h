/*
 * netlink_proto.h - shared Generic Netlink protocol definitions between
 * the av kernel module and the userspace avd daemon. Deliberately kept
 * free of kernel-only or userspace-only types so both sides can include
 * it unmodified - see docs/netlink-protocol.md for the full design.
 */

#ifndef AV_NETLINK_PROTO_H
#define AV_NETLINK_PROTO_H

#define AV_GENL_FAMILY_NAME "av_genl" /* must fit GENL_NAMSIZ (16 incl NUL) */
#define AV_GENL_VERSION     1

enum av_genl_command {
    AV_C_UNSPEC = 0,
    AV_C_REGISTER,      /* daemon -> kernel: announce presence */
    AV_C_SCAN_REQUEST,  /* kernel -> daemon: please analyze this file */
    AV_C_VERDICT,       /* daemon -> kernel: analysis result */
    __AV_C_MAX,
};
#define AV_C_MAX (__AV_C_MAX - 1)

enum av_genl_attr {
    AV_A_UNSPEC = 0,
    AV_A_REQID,     /* u64  - correlates SCAN_REQUEST with its VERDICT */
    AV_A_PID,       /* u32  - pid of the process executing the file */
    AV_A_PATH,      /* string - absolute path to the file */
    AV_A_SHA256,    /* string - 64 hex chars */
    AV_A_VERDICT,   /* u8   - 0 = clean, 1 = malicious */
    AV_A_RULE_NAME, /* string - which rule/heuristic matched (may be empty) */
    __AV_A_MAX,
};
#define AV_A_MAX (__AV_A_MAX - 1)

#define AV_VERDICT_CLEAN     0
#define AV_VERDICT_MALICIOUS 1

/*
 * Closed verdict set shared by the kernel handler
 * (av/netlink_chan.c av_nl_verdict_doit()) and the adversarial test
 * (tests/test_parser_robustness.sh, issue #105). Anything outside
 * CLEAN/MALICIOUS is malformed - rejecting with -EINVAL rather than
 * falling through to clean. Plain-C, no includes, so both the kernel
 * module and a dependency-free userspace harness can use it.
 */
static inline int av_verdict_valid(unsigned int v) {
    return v == AV_VERDICT_CLEAN || v == AV_VERDICT_MALICIOUS;
}

#define AV_PATH_ATTR_MAXLEN   4096 /* matches PATH_MAX */
#define AV_SHA256_ATTR_MAXLEN 64
#define AV_RULE_NAME_MAXLEN   63

#endif /* AV_NETLINK_PROTO_H */
