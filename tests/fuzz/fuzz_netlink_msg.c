/*
 * fuzz_netlink_msg.c - libFuzzer target for avd's netlink receive callback,
 * msg_handler() (#105). Includes userspace/avd/avd.c itself (main renamed), so
 * the real genlmsg_parse() + av_policy validation and the attribute handling
 * behind it run under ASan/UBSan, with no daemon, socket or kernel module.
 *
 * What is fuzzed, and what is not. This is the one netlink parser in the
 * repository that is avd's own code: it takes kernel -> daemon SCAN_REQUEST
 * messages and turns their attributes into a queued scan task. The other
 * direction (daemon -> kernel VERDICT, av/netlink_chan.c) is validated by the
 * kernel's own nla_policy machinery before the module's handler runs, which is
 * kernel code outside this tree and cannot be fuzzed from userspace; the
 * verdict value check it adds is av_verdict_valid(), covered by
 * tests/test_parser_robustness.sh.
 *
 * Input: byte 0 is a flags byte (bit 0: the message arrived from the kernel,
 * source portid 0; otherwise from another process), byte 1 chooses that
 * process's portid (1 + the byte), and the rest is the message exactly as it
 * would sit on the wire: nlmsghdr, genlmsghdr, attributes. The real source
 * portid is deliberately independent of the nlmsg_pid field inside the
 * message, which a forger controls (see msg_handler()). nlmsg_len is overwritten with
 * the real size: libnl's receive path only calls the callback once nlmsg_ok()
 * has established that, so a length that disagrees with the buffer is not a
 * state this callback can be in. The copy is exactly that size, on the heap,
 * so ASan sees any read past the end of the message.
 *
 * Contracts checked after every call, each one aborting on a violation:
 *
 *   - the callback returns NL_OK or NL_SKIP and nothing else;
 *   - a message queues at most one task, and only if it is a SCAN_REQUEST
 *     that came from the kernel. A SCAN_REQUEST from any other portid must
 *     never queue (that is the spoofing guard described above msg_handler());
 *   - a queued task carries exactly the attributes of the message, read back
 *     independently (reqid, pid, the device and inode identity only when all
 *     three were present, path, sha256), with NUL-terminated strings inside
 *     the task's fixed buffers.
 *
 * The queue is drained after every call, so nothing accumulates and the real
 * scan workers (never started here) are not needed. A known-good message and
 * its spoofed twin are checked at startup, so a harness that quietly rejects
 * everything cannot pass as a clean run.
 *
 * avd's own log lines go to /dev/null (a malformed message logs one per
 * input); contract violations and the sanitizers still reach fd 2.
 *
 * Build and run through tests/fuzz/Makefile.
 */
#define _GNU_SOURCE
#define main avd_real_main
#include "avd.c"
#undef main

#include <stdlib.h>

static FILE *diag;

#define REQUIRE(cond)                                                          \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(diag, "contract violated: %s (%s:%d)\n", #cond, __FILE__,        \
              __LINE__);                                                       \
      abort();                                                                 \
    }                                                                          \
  } while (0)

#define F_FROM_KERNEL 0x01u

/* Pop every queued task and hand them back as a list; the queue is empty
 * afterwards. */
static struct scan_task *take_queue(void) {
  struct scan_task *t;

  pthread_mutex_lock(&queue_lock);
  t = queue_head;
  queue_head = queue_tail = NULL;
  queue_len = 0;
  pthread_mutex_unlock(&queue_lock);
  return t;
}

static void free_tasks(struct scan_task *t) {
  while (t) {
    struct scan_task *next = t->next;

    free(t);
    t = next;
  }
}

/* The message's attributes, read without av_policy and without
 * genlmsg_parse(): a plain walk, last occurrence of a type wins (what libnl's
 * parse does too). Only the lengths the policy guarantees are relied on. */
struct seen {
  const struct nlattr *a[AV_A_MAX + 1];
};

static void walk_attrs(const struct nlmsghdr *nlh, struct seen *s) {
  const struct nlattr *pos;
  int rem;

  memset(s, 0, sizeof(*s));
  if (nlmsg_datalen(nlh) < (int)GENL_HDRLEN)
    return;
  /* genlmsg_attrdata()/genlmsg_attrlen() take a non-const header. */
  struct genlmsghdr *g = nlmsg_data((struct nlmsghdr *)nlh);
  nla_for_each_attr(pos, genlmsg_attrdata(g, 0), genlmsg_attrlen(g, 0), rem) {
    int type = nla_type(pos);

    if (type > 0 && type <= AV_A_MAX)
      s->a[type] = pos;
  }
}

static void check_task(const struct scan_task *t, const struct nlmsghdr *nlh,
                       unsigned flags) {
  const struct genlmsghdr *g;
  struct seen s;

  REQUIRE(nlmsg_datalen(nlh) >= (int)GENL_HDRLEN);
  g = nlmsg_data((struct nlmsghdr *)nlh);
  REQUIRE(g->cmd == AV_C_SCAN_REQUEST);
  REQUIRE(flags & F_FROM_KERNEL);
  REQUIRE(!t->on_demand && t->fd == -1 && t->completion == NULL &&
          t->fan == NULL);

  walk_attrs(nlh, &s);
  REQUIRE(s.a[AV_A_REQID] && s.a[AV_A_PATH]);
  REQUIRE(nla_len(s.a[AV_A_REQID]) >= (int)sizeof(uint64_t));
  REQUIRE(t->reqid == nla_get_u64((struct nlattr *)s.a[AV_A_REQID]));

  if (s.a[AV_A_PID]) {
    REQUIRE(nla_len(s.a[AV_A_PID]) >= (int)sizeof(uint32_t));
    REQUIRE(t->pid == nla_get_u32((struct nlattr *)s.a[AV_A_PID]));
  } else {
    REQUIRE(t->pid == 0);
  }

  /* All three or none. */
  if (s.a[AV_A_DEV_MAJOR] && s.a[AV_A_DEV_MINOR] && s.a[AV_A_INO]) {
    REQUIRE(t->ident.present);
    REQUIRE(t->ident.dev_major ==
            nla_get_u32((struct nlattr *)s.a[AV_A_DEV_MAJOR]));
    REQUIRE(t->ident.dev_minor ==
            nla_get_u32((struct nlattr *)s.a[AV_A_DEV_MINOR]));
    REQUIRE(t->ident.ino == nla_get_u64((struct nlattr *)s.a[AV_A_INO]));
  } else {
    REQUIRE(!t->ident.present);
  }

  /* The task's strings are NUL-terminated inside their buffers, within the
   * bounds the protocol promises, and are a prefix of what the message said. */
  REQUIRE(memchr(t->path, '\0', sizeof(t->path)) != NULL);
  REQUIRE(memchr(t->sha256_hex, '\0', sizeof(t->sha256_hex)) != NULL);
  REQUIRE(strlen(t->path) <= AV_PATH_ATTR_MAXLEN);
  REQUIRE(strlen(t->sha256_hex) <= AV_SHA256_ATTR_MAXLEN);
  {
    const char *p = nla_data((struct nlattr *)s.a[AV_A_PATH]);
    size_t n = strnlen(p, (size_t)nla_len(s.a[AV_A_PATH]));

    REQUIRE(strlen(t->path) == (n < sizeof(t->path) ? n : sizeof(t->path) - 1));
    REQUIRE(memcmp(t->path, p, strlen(t->path)) == 0);
  }
  if (s.a[AV_A_SHA256]) {
    const char *h = nla_data((struct nlattr *)s.a[AV_A_SHA256]);
    size_t n = strnlen(h, (size_t)nla_len(s.a[AV_A_SHA256]));

    REQUIRE(strlen(t->sha256_hex) ==
            (n < sizeof(t->sha256_hex) ? n : sizeof(t->sha256_hex) - 1));
    REQUIRE(memcmp(t->sha256_hex, h, strlen(t->sha256_hex)) == 0);
  } else {
    REQUIRE(t->sha256_hex[0] == '\0');
  }
}

/* Run one message through msg_handler() the way libnl would deliver it, and
 * check the contracts. `raw` is nlmsghdr + genlmsghdr + attributes. Returns the
 * number of tasks queued. */
static size_t deliver(const uint8_t *raw, size_t size, unsigned flags,
                      uint32_t foreign_portid) {
  struct nlmsghdr *copy = malloc(size);
  struct nl_msg *msg;
  struct sockaddr_nl src;
  struct scan_task *tasks;
  size_t queued = 0;
  int rc;

  if (!copy)
    return 0;
  memcpy(copy, raw, size);
  copy->nlmsg_len = (uint32_t)size; /* what nlmsg_ok() guarantees */
  msg = nlmsg_convert(copy);
  if (!msg) {
    free(copy);
    return 0;
  }
  memset(&src, 0, sizeof(src));
  src.nl_family = AF_NETLINK;
  src.nl_pid = (flags & F_FROM_KERNEL) ? 0 : (foreign_portid ? foreign_portid : 1);
  nlmsg_set_src(msg, &src);

  rc = msg_handler(msg, NULL);
  REQUIRE(rc == NL_OK || rc == NL_SKIP);

  tasks = take_queue();
  for (struct scan_task *t = tasks; t; t = t->next)
    queued++;
  REQUIRE(queued <= 1);
  if (tasks)
    check_task(tasks, nlmsg_hdr(msg), flags);

  free_tasks(tasks);
  nlmsg_free(msg);
  free(copy);
  return queued;
}

/* A well-formed SCAN_REQUEST, as the kernel module builds it. */
static size_t build_request(uint8_t *out, size_t cap, bool with_ident) {
  struct nl_msg *m = nlmsg_alloc();
  size_t n;

  REQUIRE(m);
  REQUIRE(genlmsg_put(m, 0, 0, 0x1234, 0, 0, AV_C_SCAN_REQUEST, AV_GENL_VERSION));
  REQUIRE(nla_put_u64(m, AV_A_REQID, 0x1122334455667788ull) == 0);
  REQUIRE(nla_put_u32(m, AV_A_PID, 4242) == 0);
  REQUIRE(nla_put_string(m, AV_A_PATH, "/usr/bin/true") == 0);
  REQUIRE(nla_put_string(m, AV_A_SHA256,
                         "00112233445566778899aabbccddeeff"
                         "00112233445566778899aabbccddeeff") == 0);
  if (with_ident) {
    REQUIRE(nla_put_u32(m, AV_A_DEV_MAJOR, 8) == 0);
    REQUIRE(nla_put_u32(m, AV_A_DEV_MINOR, 1) == 0);
    REQUIRE(nla_put_u64(m, AV_A_INO, 99999) == 0);
  }
  n = nlmsg_hdr(m)->nlmsg_len;
  REQUIRE(n <= cap);
  memcpy(out, nlmsg_hdr(m), n);
  nlmsg_free(m);
  return n;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  uint8_t buf[512];
  size_t n;

  (void)argc;
  (void)argv;
  /* Keep a stream for our own messages, then send avd's logging nowhere. This
   * replaces the FILE*, not fd 2, so libFuzzer and ASan still print. */
  diag = fdopen(dup(2), "w");
  setvbuf(diag, NULL, _IONBF, 0);
  stderr = fopen("/dev/null", "w");
  stdout = fopen("/dev/null", "w");
  if (!diag || !stderr || !stdout)
    abort();

  /* The harness itself must work: a valid request from the kernel queues one
   * task (both with and without the device identity), and the same message
   * from another portid queues nothing. */
  n = build_request(buf, sizeof(buf), true);
  REQUIRE(deliver(buf, n, F_FROM_KERNEL, 0) == 1);
  REQUIRE(deliver(buf, n, 0, 0) == 0);
  REQUIRE(deliver(buf, n, 0, 12345) == 0);
  n = build_request(buf, sizeof(buf), false);
  REQUIRE(deliver(buf, n, F_FROM_KERNEL, 0) == 1);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned flags;
  uint32_t portid;

  if (size < 2 + NLMSG_HDRLEN)
    return 0;
  flags = data[0];
  portid = 1u + data[1];
  data += 2;
  size -= 2;
  (void)deliver(data, size, flags, portid);
  return 0;
}
