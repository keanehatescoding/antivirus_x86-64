/*
 * avd.c - userspace daemon: registers with the av kernel module over
 * Generic Netlink, receives scan requests, and replies with a verdict
 * based on YARA rule matching and fuzzy-hash similarity against the
 * file at the given path.
 *
 * v0.3.0: netlink plumbing + YARA rule matching (rules directory)
 * v0.7.0: fuzzy hashing (ssdeep/libfuzzy) - runs when no YARA rule
 *         matched, comparing the file's fuzzy hash against a corpus
 *         of known-bad hashes (default: ./corpus/fuzzy_hashes.txt,
 *         override with argv[2] or AVD_CORPUS_FILE). Catches
 *         near-identical variants that would evade exact hash
 *         matching (av/sigtable.c) entirely - verified in this
 *         sandbox: a file with a few bytes appended scores 100
 *         similarity against the original, while an unrelated file
 *         scores 0.
 * v1.0.0-merge: quarantine (on any MALICIOUS verdict, the file is
 *         moved to /var/lib/av-quarantine/ and chmod 0000'd - see
 *         quarantine_file() below) and an `override` meta tier on top
 *         of the v0.9.1 scoring system - a small set of rules convict
 *         on their own regardless of aggregate score. Added after
 *         discovering the pure-additive scoring model let the
 *         v0.9.0 entropy-dilution evasion finding through the WHOLE
 *         pipeline once Entry_Point_Outside_Text's weight was reduced
 *         - see elf_analysis.yar and docs/evasion-findings.md.
 *         SCOPE LIMIT: quarantine only covers detections that go
 *         through avd (YARA, heuristics, fuzzy hash) - kernel-only
 *         detections (exact signature match, behavioral heuristics)
 *         still only kill, since file rename/unlink from KERNEL space
 *         needs vfs_rename()/vfs_unlink(), genuinely risky and
 *         version-fragile kernel API territory. Userspace rename()/
 *         chmod() has none of that risk.
 * (post-v1.0.0): TLSH as a second fuzzy-hash algorithm alongside
 *         ssdeep - runs when ssdeep didn't match either (default:
 *         ./corpus/tlsh_hashes.txt, override with argv[4] or
 *         AVD_TLSH_CORPUS_FILE). Complementary, not redundant: the two
 *         algorithms fingerprint files differently, so this is real
 *         defense in depth, not the same check twice - see
 *         check_tlsh_corpus()'s comment. TLSH itself is vendored, pure
 *         C, in tlsh_core.{h,c} (a from-scratch port of upstream
 *         trendmicro/tlsh's algorithm, not a system library binding -
 *         upstream's only public API is a C++ class with no external
 *         "C" surface, which is why this used to need a small C++
 *         shim; that dependency is gone). tlsh_shim.{h,c} is now just
 *         the small plain-C bridge from that core algorithm to this
 *         file's fd-hashing/corpus-comparison usage. See tlsh_shim.h
 *         and tlsh_core.h for the full story.
 *
 * Compile-verified against real libnl-genl-3.0, libyara, and libfuzzy
 * headers (clean build, -Wall -Wextra, no warnings; TLSH has no
 * external header/library dependency at all anymore). The YARA rules
 * and fuzzy-hash comparison logic (both ssdeep and TLSH) were verified
 * against real samples (see README testing sections) using the exact
 * scan/compare patterns used here. NOT yet runtime-tested end-to-end
 * against the actual kernel module together with this - see
 * docs/netlink-protocol.md and the top-level README's netlink testing
 * section.
 *
 * Dependencies (Arch/CachyOS):  sudo pacman -S libnl yara ssdeep
 * Dependencies (Debian/Ubuntu): sudo apt install libnl-genl-3-dev libyara-dev
 * libfuzzy-dev
 * (TLSH fuzzy hashing is vendored pure C - no libtlsh/libtlsh-dev
 * package needed.)
 *
 * See docs/netlink-protocol.md for the full protocol design.
 *
 * (post-v1.0.0, GUI backend): a Unix domain control socket
 * (AVD_CONTROL_SOCK_PATH) for the avctl/GUI management path - status,
 * recent verdict history, quarantine list/restore/delete, and
 * on-demand scan. Separate from the kernel netlink channel above;
 * see docs/avd-socket-protocol.md for the wire protocol and
 * docs/netlink-protocol.md for why this couldn't just reuse that
 * channel (kernel-initiated only, CAP_NET_ADMIN, single daemon slot).
 */

/* struct ucred (SO_PEERCRED) is only visible with _GNU_SOURCE defined
 * before any system header pulls in <bits/socket.h> - must come first. */
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <fuzzy.h>
#include <yara.h>

#include "../../av/netlink_proto.h"
#include "sha256.h"
#include "tlsh_shim.h"

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000 /* glibc's plain <fcntl.h> doesn't define this
                              * (only <linux/fcntl.h> does, which risks
                              * conflicting struct/macro redefinitions if
                              * included alongside <fcntl.h> on some glibc
                              * versions) - the value itself is kernel UAPI,
                              * ABI-stable, safe to hardcode. Used by
                              * quarantine_file()'s linkat() call below. */
#endif

#define DEFAULT_RULES_DIR "rules"
#define DEFAULT_CORPUS_FILE "corpus/fuzzy_hashes.txt"
#define DEFAULT_TLSH_CORPUS_FILE "corpus/tlsh_hashes.txt"
#define DEFAULT_QUARANTINE_DIR "/var/lib/av-quarantine"
/* Matches packaging/avd.service's RuntimeDirectory=avd, which systemd
 * creates/cleans as /run/avd for us. Overridable (argv[5] or
 * AVD_SOCK_PATH) mainly for tests/manual runs outside systemd - see
 * ensure_parent_dir()'s use in start_control_socket() for the
 * non-systemd case, where avd creates the directory itself. */
#define DEFAULT_CONTROL_SOCK_PATH "/run/avd/control.sock"
/* Bounds one control-socket request/response line - generous enough
 * for a full PATH_MAX path plus the small fixed fields alongside it
 * (see docs/avd-socket-protocol.md). Defense in depth, same posture as
 * av_policy's maxlen fields below: nothing legitimate needs more than
 * this, so reject rather than silently truncate. */
#define AVD_SOCK_LINE_MAX (PATH_MAX + 256)
/* Bounds one QUARANTINE LIST / VERDICTS row: two PATH_MAX-sized fields at
 * most (id + original_path) plus the small fixed fields alongside them
 * (timestamps, 64-char sha256, rule name, tabs/NUL). Named so the
 * PATH_MAX*2 headroom is a documented bound, not a magic buffer size. */
#define AVD_ROW_MAX (PATH_MAX * 2 + 256)
/* Caps how many control-socket connections avd will service at once -
 * the socket is 0666 (see start_control_socket()'s comment), so
 * without this any local user could open connections without limit,
 * each spawning its own detached thread, and exhaust the daemon's
 * threads/fds. Deliberately generous relative to real concurrent
 * avctl/GUI usage (a handful at most) rather than tightly tuned. */
#define AVD_CONTROL_MAX_CONNS 32
/* Caps how many of AVD_CONTROL_MAX_CONNS's slots a single uid may hold at
 * once. Without this, the global cap alone doesn't stop one unprivileged
 * local user from opening AVD_CONTROL_MAX_CONNS connections and sitting on
 * them for AVD_CONTROL_RECV_TIMEOUT_SECS each (repeating indefinitely) -
 * every *other* user's avctl/GUI use gets "too many concurrent control
 * connections" for as long as that lasts, on a 0666 socket every local user
 * can reach. A quarter of the global cap is generous for one user's real
 * concurrent avctl/GUI usage while leaving room for others. */
#define AVD_CONTROL_MAX_CONNS_PER_UID (AVD_CONTROL_MAX_CONNS / 4)
/* Caps how many control-socket SCAN commands may run at once, separately
 * from AVD_CONTROL_MAX_CONNS. SCAN is the one control verb that runs
 * perform_scan() (bounded by SCAN_TIMEOUT_SECS, not
 * AVD_CONTROL_RECV_TIMEOUT_SECS) directly on its own connection's thread
 * rather than sharing the kernel-triggered scan queue's worker pool - see
 * docs/avd-socket-protocol.md's SCAN section. Without a cap of its own, a
 * root-authenticated client issuing AVD_CONTROL_MAX_CONNS concurrent SCANs
 * would occupy every control connection slot for up to SCAN_TIMEOUT_SECS
 * each, starving ordinary STATUS/VERDICTS/QUARANTINE LIST use by every
 * other local user for that whole window - left well under
 * AVD_CONTROL_MAX_CONNS so those verbs always have room regardless of how
 * many SCANs are in flight. */
#define AVD_CONTROL_MAX_SCAN_CONNS 4
/* Bounds how long a single control connection may sit idle waiting for
 * its request line - without this, a client that connects and never
 * sends a newline (or a slow/hostile one trickling bytes) would block
 * that connection's thread, and therefore one of AVD_CONTROL_MAX_CONNS
 * slots, indefinitely. */
#define AVD_CONTROL_RECV_TIMEOUT_SECS 5
/* Bounded, in-memory, ring-buffered verdict history for the control
 * socket's VERDICTS command - deliberately NOT persisted to disk (lost
 * on daemon restart). This is an explicit, documented limitation, not
 * an oversight - see docs/avd-socket-protocol.md's "Known limitations"
 * section: it matches this codebase's existing convention that
 * kernel/avd runtime state is memory-only unless a save/load mechanism
 * was added as its own deliberate feature (see avctl's save/load). */
#define AVD_VERDICT_HISTORY_MAX 500
#define SCAN_TIMEOUT_SECS 10

/* Cap on what check_fuzzy_corpus()/check_tlsh_corpus() will read.
 * yr_rules_scan_fd() (the YARA path, see SCAN_TIMEOUT_SECS above) is
 * bounded by a timeout; libfuzzy's fuzzy_hash_file() and
 * av_tlsh_hash_fd() have no equivalent of their own and read to EOF
 * with nothing else stopping them. Only avd_scan_threads (default
 * AVD_SCAN_THREADS_DEFAULT) workers exist, so a handful of very large
 * files - kernel-triggered or a control-socket SCAN - can tie up the
 * whole pool for as long as the read takes; kernel-side scans then
 * queue past avd_scan_queue_max and fail open. Same 256MB value as
 * the kernel side's MAX_HASH_FILE_SIZE (av/main.c) for consistency,
 * though the two caps guard unrelated code paths. */
#define MAX_FUZZY_TLSH_FILE_SIZE (256 * 1024 * 1024)
#define MALICIOUS_SCORE_THRESHOLD 100
/* handle_scan_request() (YARA scan, up to SCAN_TIMEOUT_SECS, plus the
 * fuzzy-hash pass) used to run synchronously inside msg_handler(),
 * called directly from the single nl_recvmsgs_default() loop in
 * main(). A second SCAN_REQUEST arriving while a scan was in
 * progress got no verdict at all until the first one finished - the
 * kernel side's own DAEMON_TIMEOUT_MS would then fire and fail open,
 * so any burst of concurrent execs (or an attacker deliberately
 * racing many at once) silently dropped detection to zero for
 * everything but the first. Fixed by moving the scan itself onto a
 * worker pool (avd_scan_threads workers, default/compile-time-fallback
 * AVD_SCAN_THREADS_DEFAULT) fed by a bounded queue (capacity
 * avd_scan_queue_max, default AVD_SCAN_QUEUE_MAX_DEFAULT) -
 * msg_handler() now only copies the request and enqueues it, keeping
 * the netlink recv loop free to keep accepting new requests while
 * scans run in parallel.
 *
 * Both pool sizes are runtime-tunable via the AVD_SCAN_THREADS/
 * AVD_SCAN_QUEUE_MAX environment variables (see parse_tunable_env() in
 * main()) rather than fixed at compile time - operators can raise
 * scan concurrency (more CPU cores, a bigger exec/open burst to
 * absorb) or lower it (constrained/embedded deployment) without a
 * rebuild. Clamped to [AVD_SCAN_THREADS_MIN, AVD_SCAN_THREADS_MAX] /
 * [AVD_SCAN_QUEUE_MIN, AVD_SCAN_QUEUE_MAX_MAX] - an unbounded operator
 * value would otherwise size a calloc()/pthread_create() loop (worker
 * count) or a producer/consumer backlog (queue depth) directly off an
 * environment variable. */
#define AVD_SCAN_THREADS_DEFAULT 8
#define AVD_SCAN_THREADS_MIN 1
#define AVD_SCAN_THREADS_MAX 256
#define AVD_SCAN_QUEUE_MAX_DEFAULT 256
#define AVD_SCAN_QUEUE_MIN 1
#define AVD_SCAN_QUEUE_MAX_MAX 65536
/* Sum of every matching rule's `weight` meta (see the .yar files under rules/)
 * has to clear this before avd convicts. Added after real testing killed
 * /usr/bin/zsh, /bin/sh, and /usr/bin/uwsm - all legitimate binaries that each
 * matched exactly one low/medium-confidence rule. Any single weak import
 * heuristic (weight 5-15) or even a "verified" structural rule alone (weight
 * 30-55) now stays below threshold; conviction requires corroboration across
 * rules, which is what the documented real UPX-packed test sample actually
 * produces (No_Section_Headers + Entry_Point_Outside_Text +
 * High_Overall_Entropy firing together comfortably clears this). */
#define FUZZY_MATCH_THRESHOLD                                                  \
  60 /* 0-100; see corpus/fuzzy_hashes.txt                                     \
      * and the README's v0.7.0 testing                                        \
      * section for how this was picked -                                      \
      * a starting point, not a final tuned                                    \
      * value, and worth revisiting once                                       \
      * you have a real sample corpus. */
/* TLSH's totalDiff() is a DISTANCE, not a similarity score - the
 * OPPOSITE direction from FUZZY_MATCH_THRESHOLD above (lower diff
 * means MORE similar; 0 = identical). Calibrated against real
 * samples the same way FUZZY_MATCH_THRESHOLD was: a small compiled
 * test binary vs. that same binary with a few trailing bytes appended
 * (the near-identical-variant case this whole feature exists to
 * catch) measured diff=10; an unrelated small binary measured
 * diff=43. 30 sits with real margin on both sides of that gap - a
 * starting point, not a final tuned value, same caveat as
 * FUZZY_MATCH_THRESHOLD. See the README's TLSH testing section for
 * the exact repro. */
#define TLSH_MATCH_MAX_DIFF 30

struct fuzzy_corpus_entry {
  char hash[FUZZY_MAX_RESULT];
  char name[128];
};

/* Hash field NOT compile-time sized off av_tlsh_hash_maxlen() -
 * avd.c never includes tlsh_core.h itself (see tlsh_shim.h), so it has
 * no compile-time knowledge of the vendored TLSH implementation's
 * exact digest length (TLSH_DIGEST_HEXLEN, tlsh_core.h - currently a
 * fixed 70 hex chars for the BUCKETS_128/CHECKSUM_1B config this
 * project implements, see tlsh_core.h). AV_TLSH_HASH_BUFSZ below is a
 * fixed, generously-sized upper bound - this MUST stay >=
 * av_tlsh_hash_maxlen() + 1, checked at runtime in load_tlsh_corpus()
 * below rather than assumed to match forever. */
#define AV_TLSH_HASH_BUFSZ 200

struct tlsh_corpus_entry {
  char hash[AV_TLSH_HASH_BUFSZ];
  char name[128];
};

static struct fuzzy_corpus_entry *fuzzy_corpus;
static size_t fuzzy_corpus_count;
static struct tlsh_corpus_entry *tlsh_corpus;
static size_t tlsh_corpus_count;
static const char *quarantine_dir = DEFAULT_QUARANTINE_DIR;

static struct nl_sock *sock;
static int family_id;
static volatile sig_atomic_t running = 1;
static YR_RULES *compiled_rules;

/* Runtime-tunable pool sizes - see AVD_SCAN_THREADS_DEFAULT's comment
 * above and parse_tunable_env() below. Set once in main() before any
 * worker thread or the netlink recv loop starts, read-only from
 * every other thread from then on - same "populated once at startup,
 * read-only after" reasoning as compiled_rules/fuzzy_corpus below, so
 * no lock guards them. */
static int avd_scan_threads = AVD_SCAN_THREADS_DEFAULT;
static int avd_scan_queue_max = AVD_SCAN_QUEUE_MAX_DEFAULT;

/* nl_send_auto() touches `sock`'s internal sequence-number/port state,
 * which libnl does not guarantee is safe for concurrent callers - so
 * every send_verdict() call (now potentially from any of the
 * avd_scan_threads worker threads) takes this around the actual send.
 * Held only around message construction+send, never around the scan
 * itself, so contention is negligible. compiled_rules and
 * fuzzy_corpus need no such lock: both are populated once at startup
 * (load_rules()/load_fuzzy_corpus()) before any worker thread exists
 * and are read-only from then on - yr_rules_scan_fd() (or
 * yr_rules_scan_file()) against a shared, unmodified YR_RULES is
 * documented as safe for concurrent callers on that basis. */
static pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;

/* Bounded producer/consumer queue between msg_handler() (the single
 * netlink recv thread - producer) and the avd_scan_threads scan
 * workers (consumers). A linked list rather than a ring buffer since
 * depth is small and this isn't a hot path relative to the scan
 * itself. `shutting_down` lets both a full queue's producer-side wait
 * and an empty queue's consumer-side wait unblock cleanly on
 * SIGINT/SIGTERM instead of hanging the process past `running = 0`. */
struct scan_task {
  struct scan_task *next;
  uint64_t reqid;
  uint32_t pid;
  char path[PATH_MAX];
  char sha256_hex[65];
};

static struct scan_task *queue_head, *queue_tail;
static size_t queue_len;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t queue_not_full = PTHREAD_COND_INITIALIZER;
static bool shutting_down;

static time_t start_time;

/* One completed scan, kernel-triggered or on-demand (via the control
 * socket's SCAN command - see cmd_scan()). Written by
 * record_verdict_history(), called once from the single exit path of
 * perform_scan() so every completed scan gets an entry regardless of
 * which branch produced the verdict. */
struct verdict_record {
  uint64_t id;
  time_t timestamp;
  uint32_t pid; /* 0 for on-demand scans - no owning process */
  uid_t uid;    /* owner of the scanned file (fstat() at scan time), or
                 * (uid_t)-1 if that fstat() failed - see perform_scan().
                 * Used by cmd_verdicts_recent() to keep one user's scan
                 * history (paths, hashes) from leaking to another. */
  char path[PATH_MAX];
  char sha256_hex[65];
  uint8_t verdict; /* AV_VERDICT_CLEAN / AV_VERDICT_MALICIOUS */
  char rule_name[AV_RULE_NAME_MAXLEN + 1];
  int score;
  bool on_demand;
};

/* Fixed-size ring buffer, not a linked list like the scan queue above -
 * this one is bounded by design (AVD_VERDICT_HISTORY_MAX) rather than
 * needing backpressure, so there's no unbounded-growth case to guard
 * against and a plain array avoids the malloc/free churn of a list for
 * something written on every single scan. verdict_history_next is the
 * slot the NEXT record will be written to; the most recent entry is
 * therefore at (verdict_history_next - 1) mod MAX. */
static struct verdict_record verdict_history[AVD_VERDICT_HISTORY_MAX];
static size_t verdict_history_count;
static size_t verdict_history_next;
static uint64_t verdict_history_next_id = 1;
static pthread_mutex_t verdict_history_lock = PTHREAD_MUTEX_INITIALIZER;

/* Durable quarantine sidecar - see write_quarantine_meta()'s comment on
 * quarantine_file() for why this exists and read_quarantine_meta() for
 * the parse side. */
struct quarantine_meta {
  char original_path[PATH_MAX];
  mode_t original_mode;
  uid_t original_uid;
  gid_t original_gid;
  time_t timestamp;
  char rule_name[AV_RULE_NAME_MAXLEN + 1];
  char sha256_hex[65];
};

static const char *control_sock_path = DEFAULT_CONTROL_SOCK_PATH;
static int control_sock_fd = -1;

static void handle_sigint(int signum) {
  (void)signum;
  running = 0;
}

/*
 * Sends AV_C_VERDICT back to the kernel for the given request.
 * verdict: AV_VERDICT_CLEAN or AV_VERDICT_MALICIOUS.
 * rule_name: may be NULL/empty for a clean verdict.
 */
static int send_verdict(uint64_t reqid, uint8_t verdict,
                        const char *rule_name) {
  struct nl_msg *msg;
  int ret;

  msg = nlmsg_alloc();
  if (!msg) {
    fprintf(stderr, "avd: nlmsg_alloc failed\n");
    return -1;
  }

  if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                   AV_C_VERDICT, AV_GENL_VERSION)) {
    fprintf(stderr, "avd: genlmsg_put failed\n");
    nlmsg_free(msg);
    return -1;
  }

  NLA_PUT_U64(msg, AV_A_REQID, reqid);
  NLA_PUT_U8(msg, AV_A_VERDICT, verdict);
  if (rule_name && rule_name[0])
    NLA_PUT_STRING(msg, AV_A_RULE_NAME, rule_name);

  pthread_mutex_lock(&send_lock);
  ret = nl_send_auto(sock, msg);
  pthread_mutex_unlock(&send_lock);
  nlmsg_free(msg);

  if (ret < 0) {
    fprintf(stderr, "avd: failed to send verdict: %s\n", nl_geterror(ret));
    return -1;
  }
  return 0;

nla_put_failure:
  fprintf(stderr, "avd: NLA_PUT failed building verdict message\n");
  nlmsg_free(msg);
  return -1;
}

/*
 * Loads every *.yar or *.yara file in `dir`, compiles them together, and
 * stores the result in compiled_rules. Continues past individual file
 * compile errors (reporting them) rather than failing the whole daemon
 * over one bad rule file - a malformed rule shouldn't take detection
 * offline entirely.
 */
static int load_rules(const char *dir) {
  YR_COMPILER *compiler = NULL;
  DIR *d;
  struct dirent *entry;
  int loaded = 0;
  int total_errors = 0;

  if (yr_initialize() != ERROR_SUCCESS) {
    fprintf(stderr, "avd: yr_initialize failed\n");
    return -1;
  }

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
    fprintf(stderr, "avd: yr_compiler_create failed\n");
    yr_finalize();
    return -1;
  }

  d = opendir(dir);
  if (!d) {
    fprintf(stderr, "avd: could not open rules directory \"%s\": %s\n", dir,
            strerror(errno));
    yr_compiler_destroy(compiler);
    yr_finalize();
    return -1;
  }

  while ((entry = readdir(d)) != NULL) {
    char filepath[PATH_MAX];
    size_t len = strlen(entry->d_name);
    FILE *fp;
    int errors;
    int fn;
    bool is_yar = len >= 4 && !strcmp(entry->d_name + len - 4, ".yar");
    bool is_yara = len >= 5 && !strcmp(entry->d_name + len - 5, ".yara");

    if (!is_yar && !is_yara)
      continue;

    /* Fail closed on truncation: a silently-truncated path could open
     * (and compile in) a different, unintended rule file with no error -
     * same "reject, don't quietly reinterpret" stance as everywhere else
     * in this codebase that builds a path with snprintf(). */
    fn = snprintf(filepath, sizeof(filepath), "%s/%s", dir, entry->d_name);
    if (fn < 0 || (size_t)fn >= sizeof(filepath)) {
      fprintf(stderr, "avd: rule path too long, skipping: \"%s/%s\"\n", dir,
              entry->d_name);
      total_errors++;
      continue;
    }

    fp = fopen(filepath, "r");
    if (!fp) {
      fprintf(stderr, "avd: could not open rule file %s: %s\n", filepath,
              strerror(errno));
      continue;
    }

    errors = yr_compiler_add_file(compiler, fp, NULL, filepath);
    fclose(fp);

    if (errors > 0) {
      fprintf(stderr, "avd: %d error(s) compiling %s - skipping\n", errors,
              filepath);
      total_errors += errors;
    } else {
      printf("avd: loaded rules from %s\n", filepath);
      loaded++;
    }
  }
  closedir(d);

  if (loaded == 0)
    fprintf(stderr,
            "avd: no valid rule files loaded from \"%s\" - "
            "all scans will report clean\n",
            dir);
  if (total_errors > 0)
    fprintf(stderr,
            "avd: %d total compile error(s) across all rule "
            "files - continuing with whatever DID compile\n",
            total_errors);

  if (yr_compiler_get_rules(compiler, &compiled_rules) != ERROR_SUCCESS) {
    fprintf(stderr, "avd: yr_compiler_get_rules failed\n");
    yr_compiler_destroy(compiler);
    yr_finalize();
    return -1;
  }

  yr_compiler_destroy(compiler); /* rules are now owned by compiled_rules */
  return 0;
}

/*
 * Loads the fuzzy-hash corpus from `path` (format: see
 * corpus/fuzzy_hashes.txt). Missing file or empty corpus is not fatal -
 * the daemon just won't have anything to fuzzy-match against, and logs
 * a warning once at startup rather than failing every scan silently.
 */
/*
 * Parses one raw corpus line of the shared "<hash>,<name>" format used
 * by both the ssdeep and TLSH corpus files. Mutates `line` in place
 * (strips the trailing newline, splits at the comma) and points
 * hash_part_out/name_part_out into it. `kind` ("fuzzy"/"TLSH") is
 * only used to label the malformed-line warning so callers stay
 * distinguishable in the log. Returns 1 with the out-params set on a
 * usable line, 0 to skip the line (comment/blank, or malformed -
 * already warned about in the latter case).
 */
static int parse_corpus_line(char *line, char **hash_part_out,
                             char **name_part_out, const char *kind) {
  char *comma;
  char *newline;

  /* strpbrk(), not strchr(line, '\n') alone: corpus files edited on
   * Windows can carry CRLF line endings, and stripping only '\n'
   * would leave a trailing '\r' stuck on name_part (and, for a
   * CRLF-only blank line, fail the blank-line check below since
   * line[0] would be '\r', not '\n' or '\0'). */
  newline = strpbrk(line, "\r\n");
  if (newline)
    *newline = '\0';

  if (line[0] == '#' || line[0] == '\0')
    return 0;

  comma = strchr(line, ',');
  if (!comma) {
    fprintf(stderr,
            "avd: skipping malformed %s corpus line "
            "(no comma): %s\n",
            kind, line);
    return 0;
  }
  *comma = '\0';
  if (line[0] == '\0' || comma[1] == '\0') {
    fprintf(stderr,
            "avd: skipping malformed %s corpus line "
            "(empty hash or name)\n",
            kind);
    return 0;
  }
  *hash_part_out = line;
  *name_part_out = comma + 1;
  return 1;
}

static int load_fuzzy_corpus(const char *path) {
  FILE *fp;
  char line[512];
  size_t capacity = 16;

  fp = fopen(path, "r");
  if (!fp) {
    fprintf(stderr,
            "avd: could not open fuzzy corpus \"%s\": %s - "
            "fuzzy matching disabled\n",
            path, strerror(errno));
    return 0; /* not fatal - YARA rules still work without this */
  }

  fuzzy_corpus = malloc(capacity * sizeof(*fuzzy_corpus));
  if (!fuzzy_corpus) {
    fclose(fp);
    return -1;
  }

  while (fgets(line, sizeof(line), fp)) {
    char *hash_part, *name_part;

    if (!parse_corpus_line(line, &hash_part, &name_part, "fuzzy"))
      continue;

    if (fuzzy_corpus_count == capacity) {
      struct fuzzy_corpus_entry *grown;

      capacity *= 2;
      grown = realloc(fuzzy_corpus, capacity * sizeof(*fuzzy_corpus));
      if (!grown) {
        fclose(fp);
        return -1;
      }
      fuzzy_corpus = grown;
    }

    snprintf(fuzzy_corpus[fuzzy_corpus_count].hash,
             sizeof(fuzzy_corpus[fuzzy_corpus_count].hash), "%.*s",
             (int)sizeof(fuzzy_corpus[fuzzy_corpus_count].hash) - 1, hash_part);
    snprintf(fuzzy_corpus[fuzzy_corpus_count].name,
             sizeof(fuzzy_corpus[fuzzy_corpus_count].name), "%.*s",
             (int)sizeof(fuzzy_corpus[fuzzy_corpus_count].name) - 1, name_part);
    fuzzy_corpus_count++;
  }
  fclose(fp);

  if (fuzzy_corpus_count == 0)
    fprintf(stderr,
            "avd: fuzzy corpus \"%s\" loaded but empty - "
            "fuzzy matching will never trigger\n",
            path);
  else
    printf("avd: loaded %zu fuzzy hash(es) from %s\n", fuzzy_corpus_count,
           path);

  return 0;
}

/*
 * Compares the already-open file `fd` against every entry in the
 * fuzzy corpus. On the best match at or above FUZZY_MATCH_THRESHOLD,
 * copies the corpus entry's name into name_out and the score into
 * score_out, returning 1. Returns 0 if nothing met the threshold (or
 * no corpus loaded), -1 on a hashing error.
 *
 * Takes `fd` rather than a path - see handle_scan_request()'s comment
 * on why the whole scan/quarantine sequence now reads through one fd
 * opened once at the top, instead of re-resolving a path string at
 * each step. Hashes via a dup()'d handle, same convention as
 * check_tlsh_corpus()/av_tlsh_hash_fd() - but unlike the
 * fuzzy_hash_file() this replaced (which explicitly seeks back to the
 * original position when done), that dup()'d handle is left wherever
 * the read loop stopped: dup()'d fds share the same underlying file
 * offset as the original, so `fd` itself is left there too. No
 * current caller relies on `fd`'s position surviving this call (every
 * one either re-seeks or closes it immediately after), but don't add
 * one that does without restoring the position first. Streamed
 * through libfuzzy's incremental fuzzy_update()/fuzzy_digest() API in
 * fixed-size chunks rather than handed to fuzzy_hash_file() directly -
 * see MAX_FUZZY_TLSH_FILE_SIZE's comment for why.
 */
/* Shared size gate for check_fuzzy_corpus()/check_tlsh_corpus() - see
 * MAX_FUZZY_TLSH_FILE_SIZE's comment for why this exists. Returns
 * true if `fd` is small enough to fuzzy/TLSH-hash; on fstat() failure
 * fails open (returns true) so a stat error alone doesn't disable
 * these checks for otherwise-normal files, matching this codebase's
 * general fail-open stance on inconclusive information.
 *
 * A REJECT-ONLY gate - callers must still read up to the fixed
 * MAX_FUZZY_TLSH_FILE_SIZE cap themselves (not whatever size this
 * check happened to measure). An earlier version of this function
 * also reported the measured size back to check_fuzzy_corpus() to
 * size its read buffer exactly; that size became the actual read
 * bound instead of just an accept/reject threshold, which under-hashed
 * a file that grew after this fstat() (hashing a stale, truncated
 * snapshot instead of current content) and produced a bogus empty-file
 * digest whenever st_size raced to 0 - worse than the unbounded
 * fuzzy_hash_file() this cap replaced. Streaming through a fixed
 * buffer (see check_fuzzy_corpus()) already made that size-hint
 * unnecessary for memory reasons, so it's gone entirely now - both
 * callers just read-to-EOF-or-MAX_FUZZY_TLSH_FILE_SIZE, exactly like
 * av_tlsh_hash_fd(). */
static bool fuzzy_tlsh_size_ok(int fd, const char *label) {
  struct stat st;

  /* Fail closed: an fstat() failure on an fd we already opened
   * successfully means something is wrong (not a legitimate "file is
   * small enough" case), so skip the hash rather than let it through
   * unbounded - same stance as this function's own over-cap rejection
   * just below. */
  if (fstat(fd, &st) != 0) {
    fprintf(stderr, "avd: skipping %s hash - fstat failed: %s\n", label,
            strerror(errno));
    return false;
  }
  if (st.st_size > (off_t)MAX_FUZZY_TLSH_FILE_SIZE) {
    fprintf(stderr,
            "avd: skipping %s hash - file is %lld bytes, over the %d cap\n",
            label, (long long)st.st_size, MAX_FUZZY_TLSH_FILE_SIZE);
    return false;
  }
  return true;
}

static int check_fuzzy_corpus(int fd, char *name_out, size_t name_out_len,
                              int *score_out) {
  char file_hash[FUZZY_MAX_RESULT];
  int best_score = -1;
  size_t best_idx = 0;
  size_t i;
  int dup_fd;
  unsigned char buf[65536];
  size_t total = 0;
  ssize_t n;
  struct fuzzy_state *state;
  int hash_ret;

  if (fuzzy_corpus_count == 0)
    return 0;
  if (!fuzzy_tlsh_size_ok(fd, "fuzzy"))
    return 0;

  dup_fd = dup(fd);
  if (dup_fd < 0)
    return -1;
  if (lseek(dup_fd, 0, SEEK_SET) < 0) {
    close(dup_fd);
    return -1;
  }

  state = fuzzy_new();
  if (!state) {
    close(dup_fd);
    return -1;
  }

  /* Stream at most MAX_FUZZY_TLSH_FILE_SIZE bytes through a fixed-size
   * buffer and libfuzzy's incremental fuzzy_update()/fuzzy_digest()
   * API - constant memory regardless of the cap, same shape as
   * av_tlsh_hash_fd()'s own 64KB-buffer loop in tlsh_shim.c, and the
   * same fixed bound check_tlsh_corpus() passes it (not whatever size
   * fuzzy_tlsh_size_ok() happened to measure a moment earlier - see
   * that function's comment for why reading to a stale measured size
   * instead of this fixed cap was itself a bug). An earlier version of
   * this loop instead read one malloc()'d `want`-sized snapshot before
   * calling fuzzy_hash_buf() on it - correct, but with 8 concurrent
   * scan workers and a cap up to 256MB, that traded the worker-thread-
   * time exhaustion this cap exists to fix for a ~2GB daemon-memory
   * exhaustion vector instead. Bounding the read itself (rather than
   * the buffer size) keeps the same concurrent-growth protection - the
   * loop still can never consume more than the cap - without ever
   * holding more than one 64KB chunk at a time. */
  while (total < MAX_FUZZY_TLSH_FILE_SIZE) {
    size_t chunk = sizeof(buf);

    if (MAX_FUZZY_TLSH_FILE_SIZE - total < chunk)
      chunk = MAX_FUZZY_TLSH_FILE_SIZE - total;

    n = read(dup_fd, buf, chunk);
    if (n == 0)
      break;
    if (n < 0) {
      if (errno == EINTR)
        continue;
      fuzzy_free(state);
      close(dup_fd);
      return -1;
    }
    if (fuzzy_update(state, buf, (size_t)n) != 0) {
      fuzzy_free(state);
      close(dup_fd);
      return -1;
    }
    total += (size_t)n;
  }
  close(dup_fd);

  hash_ret = fuzzy_digest(state, file_hash, 0);
  fuzzy_free(state);

  if (hash_ret != 0)
    return -1;

  for (i = 0; i < fuzzy_corpus_count; i++) {
    int score = fuzzy_compare(file_hash, fuzzy_corpus[i].hash);

    if (score > best_score) {
      best_score = score;
      best_idx = i;
    }
  }

  if (best_score >= FUZZY_MATCH_THRESHOLD) {
    snprintf(name_out, name_out_len, "%s", fuzzy_corpus[best_idx].name);
    *score_out = best_score;
    return 1;
  }

  return 0;
}

/*
 * Startup regression guard for the hand-ported TLSH implementation
 * (tlsh_core.c/tlsh_shim.c - see that port's own top comment: "any
 * transcription error here would silently produce plausible-looking
 * but wrong hashes for every input, not a crash"). Hashes the exact
 * same fixed input vector as tests/test_tlsh_core.sh's "kat_a.txt"
 * known-answer test (three repeated lines of pangram text, byte-for-
 * byte identical - the expected digest below is the same
 * oracle-generated value that test hardcodes) and asserts the result
 * still matches. That test only runs in CI/manual dev runs; this
 * makes the same check self-contained in the actual shipped daemon,
 * so a corrupted/bit-rotted build still catches the failure at
 * startup instead of shipping silently-wrong verdicts. Uses
 * memfd_create() rather than a real temp file - no filesystem
 * dependency (writable /tmp, disk space, cleanup) for what is purely
 * an in-memory known-input check. Returns 0 if the digest matches, -1
 * otherwise (caller should treat -1 as fatal - see its call site in
 * main()).
 */
static int av_tlsh_selftest(void) {
  static const char vector[] =
      "The quick brown fox jumps over the lazy dog. Pack my box with five "
      "dozen liquor jugs. How vexingly quick daft zebras jump! The five "
      "boxing wizards jump quickly. Sphinx of black quartz, judge my "
      "vow.\n"
      "The quick brown fox jumps over the lazy dog. Pack my box with five "
      "dozen liquor jugs. How vexingly quick daft zebras jump! The five "
      "boxing wizards jump quickly. Sphinx of black quartz, judge my "
      "vow.\n"
      "The quick brown fox jumps over the lazy dog. Pack my box with five "
      "dozen liquor jugs. How vexingly quick daft zebras jump! The five "
      "boxing wizards jump quickly. Sphinx of black quartz, judge my "
      "vow.\n";
  static const char expected_hash[] =
      "6DF023C4F665119516E9040C435E7572D1EC8A045313F63050745183205C1734CF06B5";
  int fd;
  char hash[AV_TLSH_HASH_BUFSZ];
  int ret;
  bool ok;
  size_t off = 0;
  const size_t vector_len = sizeof(vector) - 1;

  fd = memfd_create("av-tlsh-selftest", MFD_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "avd: TLSH self-test: memfd_create failed: %s\n",
            strerror(errno));
    return -1;
  }

  /* Plain retry-on-partial-write loop, not write_all() (defined much
   * later in this file, alongside the control-socket code it's
   * otherwise only used by) - a memfd write of under 1KB always
   * completes in one call in practice, but looping costs nothing and
   * avoids depending on a short write never happening. */
  while (off < vector_len) {
    ssize_t n = write(fd, vector + off, vector_len - off);

    if (n < 0) {
      if (errno == EINTR)
        continue;
      fprintf(stderr, "avd: TLSH self-test: could not write test vector: %s\n",
              strerror(errno));
      close(fd);
      return -1;
    }
    off += (size_t)n;
  }
  lseek(fd, 0, SEEK_SET);

  ret = av_tlsh_hash_fd(fd, hash, sizeof(hash), (size_t)-1);
  close(fd);

  ok = (ret == 0 && strcmp(hash, expected_hash) == 0);
  if (!ok) {
    fprintf(stderr,
            "avd: TLSH self-test FAILED (ret=%d, got=%s, expected=%s) - "
            "the TLSH port may be corrupted; refusing to start\n",
            ret, ret == 0 ? hash : "(none)", expected_hash);
    return -1;
  }

  return 0;
}

/*
 * Loads the TLSH corpus from `path` (format: see
 * corpus/tlsh_hashes.txt - identical shape to fuzzy_hashes.txt:
 * <hex_hash>,<name> per line). Same not-fatal-if-missing stance as
 * load_fuzzy_corpus() and the same reasoning.
 */
static int load_tlsh_corpus(const char *path) {
  FILE *fp;
  char line[512];
  size_t capacity = 16;
  size_t hash_maxlen = av_tlsh_hash_maxlen();

  /* AV_TLSH_HASH_BUFSZ's comment promises this holds; check it rather
   * than trust it silently drifting true forever if either constant
   * ever changes without the other. */
  if (hash_maxlen + 1 > AV_TLSH_HASH_BUFSZ) {
    fprintf(stderr,
            "avd: BUG: AV_TLSH_HASH_BUFSZ (%d) is smaller than "
            "av_tlsh_hash_maxlen()+1 (%zu) - aborting rather than risk "
            "silently truncating TLSH hashes\n",
            AV_TLSH_HASH_BUFSZ, hash_maxlen + 1);
    return -1;
  }

  fp = fopen(path, "r");
  if (!fp) {
    fprintf(stderr,
            "avd: could not open TLSH corpus \"%s\": %s - "
            "TLSH matching disabled\n",
            path, strerror(errno));
    return 0; /* not fatal - everything else still works without this */
  }

  tlsh_corpus = malloc(capacity * sizeof(*tlsh_corpus));
  if (!tlsh_corpus) {
    fclose(fp);
    return -1;
  }

  while (fgets(line, sizeof(line), fp)) {
    char *hash_part, *name_part;

    if (!parse_corpus_line(line, &hash_part, &name_part, "TLSH"))
      continue;

    /* sizeof(tlsh_corpus[...].hash) is a fixed AV_TLSH_HASH_BUFSZ
     * (200) byte array (see struct tlsh_corpus_entry's comment);
     * hash_maxlen is libtlsh's actual reported max length, queried
     * once above via the shim.
     * If some future libtlsh build ever needs more than that, this
     * skip-with-a-warning is a clear failure mode rather than a
     * silent truncated-hash corruption. */
    if (strlen(hash_part) > hash_maxlen) {
      fprintf(stderr,
              "avd: skipping TLSH corpus line with an oversized hash "
              "(%zu chars, max %zu): %s\n",
              strlen(hash_part), hash_maxlen, name_part);
      continue;
    }

    if (tlsh_corpus_count == capacity) {
      struct tlsh_corpus_entry *grown;

      capacity *= 2;
      grown = realloc(tlsh_corpus, capacity * sizeof(*tlsh_corpus));
      if (!grown) {
        fclose(fp);
        return -1;
      }
      tlsh_corpus = grown;
    }

    snprintf(tlsh_corpus[tlsh_corpus_count].hash,
             sizeof(tlsh_corpus[tlsh_corpus_count].hash), "%.*s",
             (int)sizeof(tlsh_corpus[tlsh_corpus_count].hash) - 1, hash_part);
    snprintf(tlsh_corpus[tlsh_corpus_count].name,
             sizeof(tlsh_corpus[tlsh_corpus_count].name), "%.*s",
             (int)sizeof(tlsh_corpus[tlsh_corpus_count].name) - 1, name_part);
    tlsh_corpus_count++;
  }
  fclose(fp);

  if (tlsh_corpus_count == 0)
    fprintf(stderr,
            "avd: TLSH corpus \"%s\" loaded but empty - "
            "TLSH matching will never trigger\n",
            path);
  else
    printf("avd: loaded %zu TLSH hash(es) from %s\n", tlsh_corpus_count, path);

  return 0;
}

/*
 * Compares the already-open file `fd` against every entry in the TLSH
 * corpus. On the best (LOWEST - see TLSH_MATCH_MAX_DIFF's comment on
 * why this is the opposite direction from check_fuzzy_corpus()) diff
 * at or under TLSH_MATCH_MAX_DIFF, copies the corpus entry's name
 * into name_out and the diff into diff_out, returning 1. Returns 0 if
 * nothing met the threshold, no corpus loaded, OR the file simply
 * didn't have enough data for TLSH to produce a hash at all (-2 from
 * av_tlsh_hash_fd() - an expected, common, non-error outcome for
 * short files, NOT the same thing as a real hashing failure; treating
 * it as an error here used to make handle_scan_request() log a
 * spurious "TLSH hash ... failed" line for every small file scanned).
 * Returns -1 on an actual hashing error (I/O failure, or a hash that
 * somehow didn't fit the buffer - see av_tlsh_hash_fd()'s own -1/-3
 * distinction in tlsh_shim.h, both collapsed to -1 here since callers
 * only need "don't trust this result" either way). Same fd/dup()
 * convention as check_fuzzy_corpus() - see av_tlsh_hash_fd()'s own
 * comment in tlsh_shim.h.
 */
static int check_tlsh_corpus(int fd, char *name_out, size_t name_out_len,
                             int *diff_out) {
  char file_hash[AV_TLSH_HASH_BUFSZ];
  int best_diff = -1;
  size_t best_idx = 0;
  size_t i;
  int dup_fd;
  int hash_ret;

  if (tlsh_corpus_count == 0)
    return 0;
  if (!fuzzy_tlsh_size_ok(fd, "TLSH"))
    return 0;

  dup_fd = dup(fd);
  if (dup_fd < 0)
    return -1;

  /* max_len backstops fuzzy_tlsh_size_ok()'s earlier fstat()-based
   * check against a file that keeps growing after that check ran -
   * the read loop inside av_tlsh_hash_fd() itself now can never
   * consume more than MAX_FUZZY_TLSH_FILE_SIZE bytes regardless of
   * how much more data shows up concurrently. */
  hash_ret = av_tlsh_hash_fd(dup_fd, file_hash, sizeof(file_hash),
                             MAX_FUZZY_TLSH_FILE_SIZE);
  close(dup_fd);

  if (hash_ret == -2)
    return 0; /* too short/insufficiently diverse - not an error */
  if (hash_ret != 0)
    return -1;

  for (i = 0; i < tlsh_corpus_count; i++) {
    int diff = av_tlsh_diff(file_hash, tlsh_corpus[i].hash);

    if (diff < 0)
      continue; /* malformed corpus entry - skip, don't abort the scan */
    if (best_diff < 0 || diff < best_diff) {
      best_diff = diff;
      best_idx = i;
    }
  }

  if (best_diff >= 0 && best_diff <= TLSH_MATCH_MAX_DIFF) {
    snprintf(name_out, name_out_len, "%s", tlsh_corpus[best_idx].name);
    *diff_out = best_diff;
    return 1;
  }

  return 0;
}

struct yara_match_ctx {
  int matched;
  int match_count;
  int score;            /* sum of every matched rule's `weight` meta - see
                         * MALICIOUS_SCORE_THRESHOLD above */
  int override_matched; /* v1.0.0-merge: true if any matched rule
                         * carries `override = true` - convicts
                         * regardless of aggregate score. See
                         * elf_analysis.yar's header comment for
                         * why only a small, carefully-chosen set
                         * of rules get this. */
  char rule_name[AV_RULE_NAME_MAXLEN + 1]; /* comma-joined, truncated to fit */
};

static int yara_callback(YR_SCAN_CONTEXT *context, int message,
                         void *message_data, void *user_data) {
  struct yara_match_ctx *ctx = (struct yara_match_ctx *)user_data;

  (void)context;

  if (message == CALLBACK_MSG_RULE_MATCHING) {
    YR_RULE *rule = (YR_RULE *)message_data;
    YR_META *meta;
    size_t used = strlen(ctx->rule_name);
    size_t remaining = sizeof(ctx->rule_name) - used;

    ctx->matched = 1;
    ctx->match_count++;

    /* Every rule in the .yar files under rules/ carries a `weight` meta; a rule
     * missing one contributes 0 rather than crashing or silently
     * auto-convicting - fail toward "needs corroboration", not
     * toward "convict on anything". */
    yr_rule_metas_foreach(rule, meta) {
      if (meta->type == META_TYPE_INTEGER &&
          strcmp(meta->identifier, "weight") == 0) {
        ctx->score += (int)meta->integer;
      }
      if (meta->type == META_TYPE_BOOLEAN && meta->integer &&
          strcmp(meta->identifier, "override") == 0) {
        ctx->override_matched = 1;
      }
    }

    /* Collect every matching rule rather than stopping at the
     * first - with related rules (e.g. Imports_Ptrace and the
     * compound Multiple_Suspicious_Imports both matching the same
     * file), aborting early could hide the more meaningful
     * compound match behind a low-confidence single-API one. */
    if (remaining > 1) {
      snprintf(ctx->rule_name + used, remaining, "%s%s", used > 0 ? "," : "",
               rule->identifier);
    }
    return CALLBACK_CONTINUE;
  }

  return CALLBACK_CONTINUE;
}

/*
 * Records one completed scan into the ring buffer described by struct
 * verdict_record above. Called exactly once, from perform_scan()'s
 * single exit path, so every scan - kernel-triggered or on-demand,
 * clean or malicious, YARA/fuzzy/TLSH/no-rules-loaded - gets an entry.
 */
static void record_verdict_history(uint32_t pid, uid_t uid, const char *path,
                                    const char *sha256_hex, uint8_t verdict,
                                    const char *rule_name, int score,
                                    bool on_demand) {
  struct verdict_record *rec;

  pthread_mutex_lock(&verdict_history_lock);
  rec = &verdict_history[verdict_history_next];
  rec->id = verdict_history_next_id++;
  rec->timestamp = time(NULL);
  rec->pid = pid;
  rec->uid = uid;
  snprintf(rec->path, sizeof(rec->path), "%s", path ? path : "");
  snprintf(rec->sha256_hex, sizeof(rec->sha256_hex), "%s",
           sha256_hex ? sha256_hex : "");
  rec->verdict = verdict;
  snprintf(rec->rule_name, sizeof(rec->rule_name), "%s",
           rule_name ? rule_name : "");
  rec->score = score;
  rec->on_demand = on_demand;

  verdict_history_next = (verdict_history_next + 1) % AVD_VERDICT_HISTORY_MAX;
  if (verdict_history_count < AVD_VERDICT_HISTORY_MAX)
    verdict_history_count++;
  pthread_mutex_unlock(&verdict_history_lock);
}

/*
 * Parses one quarantine sidecar file (see write_quarantine_meta()) into
 * `out`. Returns 0 on success, -1 if the file couldn't be opened or had
 * no ORIGINAL_PATH= line (the one field restore/list genuinely can't
 * proceed without). Unrecognized lines are ignored rather than treated
 * as an error - forward compatible with new fields added later.
 */
static int read_quarantine_meta(const char *meta_path,
                                struct quarantine_meta *out) {
  FILE *f = fopen(meta_path, "r");
  char line[PATH_MAX + 64];

  if (!f)
    return -1;

  memset(out, 0, sizeof(*out));
  out->original_mode = 0600; /* sane fallback if ORIGINAL_MODE is
                              * missing or unparseable */

  while (fgets(line, sizeof(line), f)) {
    size_t len = strlen(line);

    if (len > 0 && line[len - 1] == '\n')
      line[--len] = '\0';

    /* "%.*s" with an explicit precision, not a bare "%s" - `line` is a
     * PATH_MAX+64 stack buffer whose actual content length gcc can't
     * bound at compile time, so a bare "%s" into these smaller fixed
     * struct fields trips -Wformat-truncation. Same pattern already
     * used by load_fuzzy_corpus()/load_tlsh_corpus() above for the
     * identical reason. */
    if (!strncmp(line, "ORIGINAL_PATH=", 14))
      snprintf(out->original_path, sizeof(out->original_path), "%.*s",
               (int)sizeof(out->original_path) - 1, line + 14);
    else if (!strncmp(line, "ORIGINAL_MODE=", 14))
      out->original_mode = (mode_t)strtoul(line + 14, NULL, 8);
    else if (!strncmp(line, "ORIGINAL_UID=", 13))
      out->original_uid = (uid_t)strtoul(line + 13, NULL, 10);
    else if (!strncmp(line, "ORIGINAL_GID=", 13))
      out->original_gid = (gid_t)strtoul(line + 13, NULL, 10);
    else if (!strncmp(line, "TIMESTAMP=", 10))
      out->timestamp = (time_t)strtoll(line + 10, NULL, 10);
    else if (!strncmp(line, "RULE_NAME=", 10))
      snprintf(out->rule_name, sizeof(out->rule_name), "%.*s",
               (int)sizeof(out->rule_name) - 1, line + 10);
    else if (!strncmp(line, "SHA256=", 7))
      snprintf(out->sha256_hex, sizeof(out->sha256_hex), "%.*s",
               (int)sizeof(out->sha256_hex) - 1, line + 7);
  }
  fclose(f);

  if (out->original_path[0] == '\0')
    return -1;

  return 0;
}

/*
 * Writes the sidecar `<dest>.meta` next to a quarantined file, called
 * from quarantine_file() before that function chmod's the quarantine
 * copy to 0000 - see quarantine_file()'s own comment for why this has
 * to happen first. `orig_st` (may be NULL if the pre-quarantine fstat()
 * failed) supplies the mode/uid/gid to restore later; without it,
 * restore falls back to 0600/root:root rather than failing outright.
 *
 * ORIGINAL_PATH is written LAST and has no field after it - Linux
 * filenames may legally contain a literal newline (never NUL or '/'),
 * which would otherwise let a pathological path corrupt whatever line
 * came after it when this file is read back with fgets(). Putting it
 * last means that edge case can only truncate the path itself on
 * restore, never a different field - the same kind of narrow,
 * documented limitation as avctl's save/load format (see do_save()'s
 * comment in avctl.c for the equivalent caveat there).
 */
static int write_quarantine_meta(const char *dest, const struct stat *orig_st,
                                 const char *orig_path, const char *rule_name,
                                 const char *sha256_hex) {
  /* PATH_MAX + 8, not PATH_MAX - `dest` is itself a PATH_MAX buffer, so
   * appending ".meta" needs headroom beyond it for gcc's
   * -Wformat-truncation to prove this can't overflow (same margin
   * avctl.c's do_save() uses for its own "%s.tmp" append). */
  char meta_path[PATH_MAX + 8];
  FILE *f;
  int mfd;
  int mn;

  /* Fail closed on truncation: a silently-truncated meta path would
   * attach the sidecar to the wrong file (or a different directory)
   * with no error, leaving a quarantine entry unrestorable. */
  mn = snprintf(meta_path, sizeof(meta_path), "%s.meta", dest);
  if (mn < 0 || (size_t)mn >= sizeof(meta_path))
    return -1;
  /* O_EXCL|O_NOFOLLOW, not fopen("w"): dest itself is an
   * unpredictable pid+nanotime name (see quarantine_file()), so a
   * planted symlink here is impractical - but fopen() would still
   * follow one if it ever existed, and O_EXCL also turns a
   * same-nanosecond collision into a loud failure instead of a
   * silent clobber. Best-effort either way (caller logs, quarantine
   * itself still stands). */
  mfd = open(meta_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if (mfd < 0)
    return -1;
  f = fdopen(mfd, "w");
  if (!f) {
    close(mfd);
    unlink(meta_path);
    return -1;
  }

  fprintf(f, "ORIGINAL_MODE=%o\n", orig_st ? (orig_st->st_mode & 07777) : 0600);
  fprintf(f, "ORIGINAL_UID=%d\n", orig_st ? (int)orig_st->st_uid : 0);
  fprintf(f, "ORIGINAL_GID=%d\n", orig_st ? (int)orig_st->st_gid : 0);
  fprintf(f, "TIMESTAMP=%lld\n", (long long)time(NULL));
  fprintf(f, "RULE_NAME=%s\n", rule_name ? rule_name : "");
  fprintf(f, "SHA256=%s\n", sha256_hex ? sha256_hex : "");
  fprintf(f, "ORIGINAL_PATH=%s\n", orig_path);

  if (fclose(f) != 0) {
    unlink(meta_path);
    return -1;
  }
  return 0;
}

/* Trust policy for one existing path component: lstat (never stat, so
 * a symlink is seen rather than followed), must be a real directory
 * owned by the daemon's own euid (avd runs as root, so in practice uid
 * 0) or by root, with no group/other write access unless the sticky
 * bit excuses it when allow_sticky_ww is set - see
 * dir_hierarchy_trusted() for how the flag differs between final and
 * ancestor components). Returns 0 if trusted, -1 (error printed)
 * otherwise. */
static int trust_one_component(const char *label, const char *comp,
                               bool allow_sticky_ww) {
  struct stat st;
  uid_t euid = geteuid();

  if (lstat(comp, &st) != 0) {
    fprintf(stderr, "avd: %s \"%s\" vanished: %s\n", label, comp,
            strerror(errno));
    return -1;
  }
  if (S_ISLNK(st.st_mode)) {
    fprintf(stderr, "avd: %s \"%s\" is a symlink - refusing to follow it\n",
            label, comp);
    return -1;
  }
  if (!S_ISDIR(st.st_mode)) {
    fprintf(stderr, "avd: %s \"%s\" exists but is not a directory\n", label,
            comp);
    return -1;
  }
  if (st.st_uid != euid && st.st_uid != 0) {
    fprintf(stderr,
            "avd: %s \"%s\" is owned by uid %d - refusing to use a directory an unprivileged user controls\n",
            label, comp, (int)st.st_uid);
    return -1;
  }
  if ((st.st_mode & (S_IWGRP | S_IWOTH)) &&
      (!allow_sticky_ww || !(st.st_mode & S_ISVTX))) {
    fprintf(stderr,
            "avd: %s \"%s\" is writable by other users%s - refusing to use a directory other users can modify\n",
            label, comp,
            allow_sticky_ww ? " without the sticky bit" : "");
    return -1;
  }
  return 0;
}

/* Full-hierarchy version of the trust gate: validating only the final
 * component leaves a gap - a writable non-sticky ancestor lets an
 * unprivileged user rename a root-owned mode-0755 directory after the
 * check (e.g. attacker-owned /tmp/attacker replaced wholesale, taking
 * /tmp/attacker/socket-parent with it), and every later path-based op
 * (bind/chmod by path, quarantine renames) re-resolves through the
 * swapped ancestor. So every ancestor from / down is checked with the
 * same ownership/symlink rules, shallow to deep: a symlinked ancestor
 * fails before anything beneath it is even examined (deeper prefixes
 * are never resolved through it), and an attacker-owned or
 * attacker-writable one fails on its own terms. Ancestors allow the
 * sticky exception unconditionally: a sticky ancestor (like /tmp
 * itself) cannot be renamed by non-owners, and without the exception
 * no chain beneath /tmp could ever validate - including the test
 * suite's throwaway dirs. The FINAL component uses allow_sticky_ww:
 * false keeps it strictly unshared (the quarantine dir - no group or
 * other write at all, so nobody else can even plant fake entries
 * there), true additionally permits a sticky-shared final dir (the
 * socket parent - a sticky socket dir is safe because only the entry
 * owner can touch the socket, and every socket op re-verifies it).
 * (".." and "." segments need no special handling: neither can be a
 * symlink, and each literal prefix is still lstat'd for
 * ownership/mode.) Applied on every path - including after a
 * successful mkdir(), whose fresh directory is ours but whose
 * ancestors merely allowed its creation (root can mkdir inside an
 * attacker-owned tree just as easily as anywhere else). Once the
 * whole chain is trusted, no unprivileged user can modify any of it -
 * which is also what closes the check-then-use gap without pinned fds
 * for every later operation: the window remains in theory, but there
 * is nobody left who is both unprivileged and able to write through
 * it. Returns 0 if the whole chain is trusted, -1 otherwise. */
static int dir_hierarchy_trusted(const char *label, const char *dir,
                                 bool allow_sticky_ww) {
  char buf[PATH_MAX];
  size_t len, i;
  int sn;

  if (!dir[0] || dir[0] != '/') {
    fprintf(stderr, "avd: %s \"%s\" must be an absolute path\n", label,
            dir);
    return -1;
  }
  sn = snprintf(buf, sizeof(buf), "%s", dir);
  if (sn < 0 || (size_t)sn >= sizeof(buf)) {
    fprintf(stderr, "avd: %s path too long: \"%s\"\n", label, dir);
    return -1;
  }
  /* Strip trailing slashes so "/a/b/" checks "/a/b" (root "/" keeps
   * its own slash). */
  len = strlen(buf);
  while (len > 1 && buf[len - 1] == '/')
    buf[--len] = '\0';
  /* "/" itself is an ancestor of everything: sticky-tolerant, like
   * all non-final components. (In practice root-owned 555/755.) */
  if (trust_one_component(label, "/", true) != 0)
    return -1;
  /* Every deeper prefix ending at a component boundary, shallow
   * first. Consecutive slashes yield empty segments, skipped. The
   * boundary at i == len is the final component and gets the
   * caller's allow_sticky_ww; anything before it is an ancestor. */
  for (i = 1; i <= len; i++) {
    if (buf[i] == '/' || buf[i] == '\0') {
      char saved;
      bool is_final = (i == len);
      int r;

      if (i == 1 || buf[i - 1] == '/')
        continue; /* leading or doubled slash: no new component */
      saved = buf[i];
      buf[i] = '\0';
      r = trust_one_component(label, buf,
                              is_final ? allow_sticky_ww : true);
      buf[i] = saved;
      if (r != 0)
        return -1;
    }
  }
  return 0;
}

static int ensure_quarantine_dir(void) {
  if (mkdir(quarantine_dir, 0700) != 0 && errno != EEXIST) {
    fprintf(stderr, "avd: could not create quarantine dir \"%s\": %s\n",
            quarantine_dir, strerror(errno));
    return -1;
  }
  /* mkdir() tolerating EEXIST must not treat "a symlink to /etc"
   * the same as "the directory already exists": an attacker who
   * pre-creates a symlink at quarantine_dir before avd starts would
   * otherwise redirect every quarantine write through it. And the
   * check runs after a successful mkdir() too: a fresh directory is
   * ours, but the ancestors that allowed its creation may still be
   * attacker-controlled (root can mkdir inside an attacker-owned tree
   * just as easily as anywhere else - an attacker-owned ancestor can
   * rename our new directory away afterwards). The full chain - not
   * just the final component - is validated, so no unprivileged user
   * can modify any of it; that is also what closes the check-then-use
   * gap without pinned fds for every later operation. No *at()/dir-FD
   * pinning on top: once unprivileged users cannot modify the
   * directory or any ancestor, there is nothing left for a retained
   * FD to defend against. */
  return dir_hierarchy_trusted("quarantine dir", quarantine_dir, false);
}

/* Fallback for quarantine_file()'s linkat() failing - see that
 * function's comment for the two real cases this covers (EXDEV:
 * quarantine dir on a different filesystem; ENOENT: the source's
 * link count already hit zero, e.g. an unlink()-then-replace race
 * rather than a rename()-away one - linkat(fd, "", ..., AT_EMPTY_PATH)
 * cannot resurrect a fully unlinked inode even though the fd itself
 * is still perfectly valid). Copies the already-open `fd`'s content
 * into `dst`, reading through `fd` rather than re-opening a path, so
 * this copy step itself reads the exact file that was scanned,
 * regardless of anything that may have happened to its original path
 * since - and regardless of which of the two cases above triggered
 * it. Does NOT unlink the original; the caller does that separately
 * once, since removing-by-path is the one operation here that still
 * has to re-resolve a path name and can't be done purely through `fd`
 * (see quarantine_file()'s identity re-check that guards it). */
static int copy_fd_to(int fd, const char *dst) {
  int out_fd;
  char buf[65536];
  ssize_t n;
  int ret = 0;

  if (lseek(fd, 0, SEEK_SET) < 0)
    return -1;

  out_fd = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (out_fd < 0)
    return -1;

  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    if (write(out_fd, buf, (size_t)n) != n) {
      ret = -1;
      break;
    }
  }
  if (n < 0)
    ret = -1;

  close(out_fd);

  if (ret != 0)
    unlink(dst); /* best-effort cleanup of the partial copy */

  return ret;
}

/*
 * Moves the already-open file `fd` into the quarantine directory and
 * chmod's it to 0000 (unreadable/unwritable/unexecutable by anyone,
 * including root without an explicit chmod back - a deliberate speed
 * bump against accidental re-execution, not real access control).
 * `path` is used for the destination's basename and log messages, and
 * for one narrow unlink described below - it does NOT drive identity
 * for the quarantine copy itself. Logs the outcome either way; a
 * quarantine failure does NOT block the verdict already being sent
 * back to the kernel for the kill.
 *
 * `fd` was opened once at the very top of handle_scan_request(),
 * before scanning even began, and has been read from (never
 * re-opened by path) for every step since - see that function's
 * comment. The quarantine copy is created via linkat(fd, "", ...,
 * AT_EMPTY_PATH) - this creates a new directory entry pointing at
 * fd's underlying inode DIRECTLY, without re-walking `path`, so it's
 * immune to the swap-the-path race the previous, path-only version of
 * this function could only narrow (lstat/rename gap, double-swap)
 * rather than close: there's nothing left here to swap out from under
 * an fd-identified link. This is the "more complete fix" that
 * function's comment used to point at as a follow-up.
 *
 * NOTE: a plain rename() through /proc/self/fd/N looks like it should
 * do the same thing and was tried first - it doesn't. Verified
 * empirically: it always fails with EXDEV, because the kernel treats
 * the source as living on procfs itself for the cross-device check
 * rather than transparently resolving to the real file's actual
 * filesystem. linkat()+AT_EMPTY_PATH is the primitive that actually
 * targets the fd's real inode.
 *
 * linkat() can fail for reasons that have nothing to do with a swap -
 * same-filesystem-only like any hardlink (EXDEV if the quarantine dir
 * is elsewhere), and it cannot resurrect a fully unlinked inode
 * (ENOENT once `fd`'s link count hits zero - a real, not just
 * theoretical, case: an unlink()-then-replace race hits this, a
 * rename()-away-then-replace race doesn't, and an attacker doesn't
 * owe us a choice between the two). copy_fd_to() below is the
 * fallback for any such failure, still reading through `fd` rather
 * than `path` either way. Once the quarantine copy exists (by
 * whichever route), removing the ORIGINAL by `path` is the one step left
 * that still has to re-walk it - unlink() has no fd-based equivalent
 * - so it gets a re-check-and-refuse immediately before it, comparing
 * the fd's true identity against a fresh lstat(). This is
 * risk-reduction, not elimination, for this one narrowed step - same
 * kind of tradeoff documented elsewhere in this codebase (see
 * Has_RWX_Segment's scope note) - but unlike the old design, a
 * mismatch here only means the original wasn't also cleaned up from
 * its old location, never that the wrong content got quarantined.
 *
 * `rule_name`/`sha256_hex` (may be NULL/empty) are passed through only
 * for write_quarantine_meta()'s sidecar - purely informational, no
 * effect on the quarantine/unlink logic itself.
 */
static void quarantine_file(int fd, const char *path, const char *rule_name,
                            const char *sha256_hex) {
  char dest[PATH_MAX];
  const char *base;
  struct timespec ts;
  struct stat fd_st;
  struct stat orig_st;
  bool have_orig_st;
  bool linked;

  if (ensure_quarantine_dir() != 0)
    return;

  /* Captured before linkat()/chmod() below - once linkat() succeeds,
   * `dest` is a second directory entry for fd's SAME inode (a
   * hardlink, not a copy), so chmod(dest, 0000) further down would
   * otherwise also be the last read of the original's own mode. This
   * is the one place in this function that needs the pre-quarantine
   * permissions, for write_quarantine_meta()'s restore record - not to
   * be confused with the fd_st fstat() later on, which is a distinct,
   * unrelated identity recheck immediately before the original's
   * unlink(). */
  have_orig_st = (fstat(fd, &orig_st) == 0);

  base = strrchr(path, '/');
  base = base ? base + 1 : path;

  /* <pid>_<nanotime>_<base> rather than <epoch>_<base>: two files
   * with the same basename quarantined within the same wall-clock
   * second used to collide on this name, and the second link/copy
   * silently clobbered the first (avd is single-threaded today, but
   * this shouldn't quietly break if that ever changes). PID plus a
   * monotonic-clock nanosecond reading is unique per call even if
   * two quarantines land in the same second. */
  clock_gettime(CLOCK_MONOTONIC, &ts);
  /* Fail closed on truncation: a silently-truncated dest would quarantine
   * into the wrong directory entry (potentially outside quarantine_dir
   * for a long attacker-influenced basename) with no error. */
  {
    int dn = snprintf(dest, sizeof(dest), "%s/%d_%ld%09ld_%s.quarantined",
                        quarantine_dir, (int)getpid(), (long)ts.tv_sec,
                        ts.tv_nsec, base);
    if (dn < 0 || (size_t)dn >= sizeof(dest)) {
      fprintf(stderr, "avd: quarantine destination path would truncate - refusing\n");
      return;
    }
  }

  linked = (linkat(fd, "", AT_FDCWD, dest, AT_EMPTY_PATH) == 0);
  if (!linked) {
    /* Fall back to the fd-based copy on ANY linkat failure, not just
     * EXDEV - see copy_fd_to()'s comment for why ENOENT (source fully
     * unlinked, not just renamed away) is an equally real case here,
     * and the copy is correct regardless of which one triggered it. */
    int linkat_errno = errno;

    if (copy_fd_to(fd, dest) != 0) {
      fprintf(stderr,
              "avd: quarantine failed for \"%s\": linkat: %s; copy "
              "fallback: %s\n",
              path, strerror(linkat_errno), strerror(errno));
      return;
    }
  }

  /* Sidecar metadata written before the chmod(dest, 0000) below, and
   * before the original is touched at all - the whole point of this
   * file is to survive even if a later step here fails, so the
   * quarantine stays restorable. Best-effort: a metadata write failure
   * is logged but doesn't abort the quarantine itself - an
   * unrestorable-by-GUI quarantine is still a successful quarantine,
   * same "logging failure isn't a quarantine failure" stance as
   * everywhere else in this function. */
  if (write_quarantine_meta(dest, have_orig_st ? &orig_st : NULL, path,
                            rule_name, sha256_hex) != 0)
    fprintf(stderr,
            "avd: could not write quarantine metadata for \"%s\" - restore "
            "via avctl will not be possible for this file\n",
            dest);

  /* Lock down the quarantine copy before touching the original at
   * all - this is what matters for "can this be re-executed". A
   * failed chmod means the copy is sitting there with whatever mode
   * the original had (potentially world-readable/executable), so
   * stop here rather than also removing the original: that would
   * trade a file we know the location and permissions of for one at
   * an unpredictable quarantine path that's LESS locked down, not
   * more. Best-effort remove the half-secured copy and leave the
   * original in place - a worse but at least contained outcome for
   * this specific (essentially unreachable in practice: this is a
   * freshly-created file we just opened successfully) failure. */
  if (chmod(dest, 0000) != 0) {
    fprintf(stderr, "avd: quarantined \"%s\" to \"%s\" but chmod failed: %s "
            "- leaving the original in place rather than removing it "
            "without a locked-down copy to show for it\n",
            path, dest, strerror(errno));
    unlink(dest);
    return;
  }

  /* Unlike the initial fd open at the top of handle_scan_request()
   * (which fails open on an inconclusive lstat - see that function's
   * comment), this fstat() is the immediate-pre-unlink recheck, and
   * gets the strict treatment: refuse rather than proceed if it
   * fails, matching this function's own stance everywhere else in
   * this recheck (a mismatch below also refuses). fstat() on our own
   * valid, already-successfully-read fd failing here would be
   * essentially unreachable in practice, but "essentially
   * unreachable" is exactly when failing closed instead of open costs
   * nothing and buys real margin. */
  if (fstat(fd, &fd_st) != 0) {
    fprintf(stderr,
            "avd: quarantined \"%s\" to \"%s\", but refusing to remove the "
            "original - fstat on our own fd failed unexpectedly: %s\n",
            path, dest, strerror(errno));
    return;
  }

  {
    struct stat now_st;

    /* This lstat()-then-unlink() pair is not, and cannot be made,
     * atomic through standard POSIX path-based syscalls - a swap
     * landing in the gap between this check and unlink() below (as
     * opposed to before it, which this check does catch) would still
     * remove whatever now occupies `path` instead of the original.
     * There is no portable "unlink iff this path still names inode X"
     * primitive to close that with. The alternative - doing this
     * removal from kernel space, where the already-resolved dentry
     * from detection could be unlinked directly - is deliberately out
     * of scope: see this file's top comment on why kernel-side
     * rename()/unlink() is the riskier direction, not the safer one,
     * for this codebase specifically. What's left is the same
     * risk-reduction-not-elimination tradeoff as every other
     * TOCTOU note in this codebase (see Has_RWX_Segment's scope
     * note): this check narrows the race to the syscall gap right
     * here instead of the whole scan-to-quarantine sequence, which is
     * what it was worth fixing for - it was never going to make
     * path-based removal provably atomic, and claiming otherwise
     * would be the actual bug. */
    if (lstat(path, &now_st) != 0 || now_st.st_dev != fd_st.st_dev ||
        now_st.st_ino != fd_st.st_ino) {
      fprintf(stderr,
              "avd: quarantined \"%s\" to \"%s\", but refusing to remove "
              "the original - path now resolves to a different file "
              "(possible symlink swap); remove it manually if "
              "appropriate\n",
              path, dest);
      return;
    }
  }

  if (unlink(path) != 0)
    fprintf(stderr, "avd: unlink of original \"%s\" failed: %s\n", path,
            strerror(errno));
  else
    printf("avd: QUARANTINED \"%s\" -> \"%s\"%s\n", path, dest,
           linked ? "" : " (copy fallback)");
}

struct scan_result {
  uint8_t verdict; /* AV_VERDICT_CLEAN / AV_VERDICT_MALICIOUS */
  char rule_name[AV_RULE_NAME_MAXLEN + 1];
  int score; /* YARA aggregate score - 0 for a fuzzy/TLSH-only match or
             * a clean result; supplementary info, not authoritative */
  char sha256_hex[65];
};

/*
 * Shared core of file analysis - YARA, then fuzzy/TLSH fallback,
 * quarantine on MALICIOUS, and a verdict_history record either way.
 * Used by both handle_scan_request() (kernel-triggered, netlink) and
 * cmd_scan() (on-demand, control socket) - see each caller for how
 * they report `out` over their own transport; this function touches
 * neither.
 *
 * `fd` must already be open for reading - opening is the caller's
 * responsibility, deliberately kept out of this shared core since a
 * failed open means something different to each caller (fail-open and
 * tell the kernel CLEAN for the netlink path, vs. an ERR reply for the
 * interactive on-demand path). `sha256_hex` may be NULL/empty - kernel
 * scans always have one (precomputed via av/sigtable.c), on-demand
 * scans never do, and this fills one in via sha256_fd() either way.
 * `pid` is 0 for on-demand scans (no owning process - see struct
 * verdict_record's own comment).
 */
static void perform_scan(int fd, const char *path, const char *sha256_hex,
                         uint32_t pid, bool on_demand,
                         struct scan_result *out) {
  struct yara_match_ctx ctx = {.matched = 0,
                               .match_count = 0,
                               .score = 0,
                               .override_matched = 0,
                               .rule_name = ""};
  char sha256_buf[65] = "";
  const char *hash;
  int ret;
  struct stat owner_st;
  /* (uid_t)-1 (never a real uid) if the fstat() fails - callers treat
   * that as "owner unknown", visible to root only. See struct
   * verdict_record's uid field comment. */
  uid_t owner_uid = fstat(fd, &owner_st) == 0 ? owner_st.st_uid : (uid_t)-1;

  memset(out, 0, sizeof(*out));
  out->verdict = AV_VERDICT_CLEAN;

  if (sha256_hex && sha256_hex[0])
    hash = sha256_hex;
  else if (sha256_fd(fd, sha256_buf) == 0)
    hash = sha256_buf;
  else
    hash = ""; /* on-demand scan of a file sha256_fd() couldn't hash -
               * proceed without one rather than failing the scan
               * over it */

  printf("avd: %sscan \"%s\" pid=%u sha256=%s\n",
         on_demand ? "on-demand " : "", path, pid, hash[0] ? hash : "(unknown)");

  if (!compiled_rules)
    goto record;

  /* sha256_fd() above drains through a dup()'d handle, and dup() shares
   * the underlying file offset with the original fd (same open file
   * description) - so on any on-demand scan (no precomputed sha256_hex,
   * i.e. every avctl/GUI SCAN request) `fd` is sitting at EOF here and
   * YARA would scan zero bytes and always report CLEAN. Rewind before
   * scanning; yr_rules_scan_fd() does not do this itself. Fail open on
   * a rewind error, matching this function's stance on inconclusive
   * information elsewhere. */
  if (lseek(fd, 0, SEEK_SET) < 0) {
    fprintf(stderr, "avd: lseek(\"%s\", SEEK_SET) before YARA scan failed: "
                    "%s - failing open\n",
            path, strerror(errno));
    goto record;
  }

  ret = yr_rules_scan_fd(compiled_rules, fd, 0, yara_callback, &ctx,
                         SCAN_TIMEOUT_SECS);
  if (ret != ERROR_SUCCESS) {
    /* File vanished, permission denied, scan timeout, etc. - fail
     * open here too, matching the kernel side's own fail-open
     * stance on inconclusive information (see docs/netlink-protocol.md). */
    fprintf(stderr, "avd: yr_rules_scan_fd(\"%s\") failed: error %d\n", path,
            ret);
    goto record;
  }

  if (ctx.matched) {
    /* Sum of matched rules' weights has to clear
     * MALICIOUS_SCORE_THRESHOLD before this convicts - a single
     * low-confidence import heuristic (or even one "verified"
     * structural rule alone) is logged for visibility but no
     * longer enough by itself. See the threshold's own comment
     * for why: real testing killed zsh/sh/uwsm on exactly this
     * single-weak-match pattern before this existed.
     *
     * EXCEPT: a small, deliberately narrow set of rules carry
     * `override = true` and convict on their own regardless of
     * score - added after discovering that pure additive scoring
     * let the v0.9.0 entropy-dilution evasion through the WHOLE
     * pipeline (not just the entropy layer) once Entry_Point_
     * Outside_Text's weight was reduced for its own false
     * positive. See elf_analysis.yar's header comment and
     * docs/evasion-findings.md for the full story. */
    if (ctx.override_matched || ctx.score >= MALICIOUS_SCORE_THRESHOLD) {
      printf("avd: MATCH \"%s\" -> %d rule(s), score=%d, override=%d: \"%s\"\n",
             path, ctx.match_count, ctx.score, ctx.override_matched,
             ctx.rule_name);
      out->verdict = AV_VERDICT_MALICIOUS;
      snprintf(out->rule_name, sizeof(out->rule_name), "%s", ctx.rule_name);
      out->score = ctx.score;
      quarantine_file(fd, path, out->rule_name, hash);
      goto record;
    }

    printf("avd: %d rule(s) matched \"%s\" but score=%d is below "
           "threshold (%d) and no override rule fired - not "
           "convicting: \"%s\"\n",
           ctx.match_count, path, ctx.score, MALICIOUS_SCORE_THRESHOLD,
           ctx.rule_name);
    out->score = ctx.score;
    /* Falls through to the fuzzy-hash check below rather than
     * declaring clean immediately - a below-threshold YARA match
     * plus a fuzzy-hash hit against the known-bad corpus is still
     * worth convicting on, even though neither alone was enough. */
  }

  /* No YARA rule fired - try fuzzy-hash similarity against the
   * corpus before declaring clean. This catches near-identical
   * variants of a known-bad file that would evade both the kernel's
   * exact hash check (av/sigtable.c) and exact YARA string/structure
   * matches. */
  {
    char fuzzy_name[128];
    int fuzzy_score = 0;
    int fret =
        check_fuzzy_corpus(fd, fuzzy_name, sizeof(fuzzy_name), &fuzzy_score);

    if (fret == 1) {
      /* fuzzy_compare()'s documented range is 0-100; clamping
       * here (defensive, should never actually trigger) also
       * gives the compiler's range analysis what it needs to
       * prove the snprintf below can't truncate. */
      if (fuzzy_score < 0)
        fuzzy_score = 0;
      if (fuzzy_score > 100)
        fuzzy_score = 100;

      out->verdict = AV_VERDICT_MALICIOUS;
      snprintf(out->rule_name, sizeof(out->rule_name), "Fuzzy:%.40s(%d)",
               fuzzy_name, fuzzy_score);
      printf("avd: FUZZY MATCH \"%s\" -> \"%s\" score=%d\n", path, fuzzy_name,
             fuzzy_score);
      quarantine_file(fd, path, out->rule_name, hash);
      goto record;
    }
    if (fret < 0)
      fprintf(stderr, "avd: fuzzy hash of \"%s\" failed\n", path);
  }

  /* ssdeep didn't match either - try TLSH before declaring clean.
   * Complementary, not redundant: the two algorithms fingerprint
   * files differently (ssdeep's rolling-hash context-triggered
   * piecewise hashing vs. TLSH's locality-sensitive quartile/bucket
   * histogram), so a variant that happens to fall below one
   * algorithm's similarity threshold isn't guaranteed to fall below
   * the other's too - running both is real defense in depth, not
   * just running the same check twice. */
  {
    char tlsh_name[128];
    int tlsh_diff = 0;
    int tret =
        check_tlsh_corpus(fd, tlsh_name, sizeof(tlsh_name), &tlsh_diff);

    if (tret == 1) {
      out->verdict = AV_VERDICT_MALICIOUS;
      snprintf(out->rule_name, sizeof(out->rule_name), "TLSH:%.40s(%d)",
               tlsh_name, tlsh_diff);
      printf("avd: TLSH MATCH \"%s\" -> \"%s\" diff=%d\n", path, tlsh_name,
             tlsh_diff);
      quarantine_file(fd, path, out->rule_name, hash);
      goto record;
    }
    if (tret < 0)
      fprintf(stderr, "avd: TLSH hash of \"%s\" failed\n", path);
  }

record:
  snprintf(out->sha256_hex, sizeof(out->sha256_hex), "%s", hash);
  record_verdict_history(pid, owner_uid, path, out->sha256_hex, out->verdict,
                         out->rule_name, out->score, on_demand);
}

static void handle_scan_request(uint64_t reqid, uint32_t pid, const char *path,
                                const char *sha256_hex) {
  struct scan_result result;
  int fd;

  printf("avd: scan request reqid=%llu pid=%u path=\"%s\" sha256=%s\n",
         (unsigned long long)reqid, pid, path, sha256_hex);

  /* Opened exactly once, here, before anything else touches the file.
   * The YARA scan, the fuzzy-hash check, and quarantine on a
   * MALICIOUS verdict all read/act through THIS fd from now on rather
   * than re-resolving `path` at each step - see quarantine_file()'s
   * comment for how the quarantine step itself uses it. An open fd keeps
   * referring to the exact same file for its entire lifetime
   * regardless of what happens to `path` afterward (deleted, renamed,
   * replaced with a symlink to something else - even during the scan
   * itself, which can take up to SCAN_TIMEOUT_SECS), so there's
   * nothing left for an attacker to swap out from under it. This
   * replaces the previous design's lstat-baseline-then-re-check-at-
   * rename-time approach, which could only narrow that window, not
   * close it. */
  fd = open(path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "avd: could not open \"%s\" for scanning: %s\n", path,
            strerror(errno));
    send_verdict(reqid, AV_VERDICT_CLEAN, NULL);
    return;
  }

  perform_scan(fd, path, sha256_hex, pid, false, &result);

  if (send_verdict(reqid, result.verdict, result.rule_name) < 0)
    fprintf(stderr,
            "avd: failed to send %s verdict for reqid=%llu \"%s\" - "
            "kernel side will fail open on timeout\n",
            result.verdict == AV_VERDICT_MALICIOUS ? "MALICIOUS" : "CLEAN",
            (unsigned long long)reqid, path);

  close(fd);
}

/* Producer side (called only from msg_handler(), the netlink recv
 * thread). Copies the request into a heap task and blocks if the
 * queue is at avd_scan_queue_max rather than growing unbounded - this
 * is deliberate backpressure: if every worker is busy and the queue
 * is full, pausing the recv loop is no worse than the pre-fix
 * behavior (a scan already blocked the loop outright), and the
 * kernel's own DAEMON_TIMEOUT_MS still bounds how long any single
 * request waits before that side fails open. Returns false only on
 * shutdown or allocation failure, in which case the caller drops the
 * request (matching this codebase's existing fail-open stance). */
static bool enqueue_scan_task(uint64_t reqid, uint32_t pid, const char *path,
                              const char *sha256_hex) {
  struct scan_task *task = malloc(sizeof(*task));

  if (!task)
    return false;

  task->next = NULL;
  task->reqid = reqid;
  task->pid = pid;
  snprintf(task->path, sizeof(task->path), "%s", path ? path : "");
  snprintf(task->sha256_hex, sizeof(task->sha256_hex), "%s",
           sha256_hex ? sha256_hex : "");

  pthread_mutex_lock(&queue_lock);
  while (queue_len >= (size_t)avd_scan_queue_max && !shutting_down)
    pthread_cond_wait(&queue_not_full, &queue_lock);

  if (shutting_down) {
    pthread_mutex_unlock(&queue_lock);
    free(task);
    return false;
  }

  if (queue_tail)
    queue_tail->next = task;
  else
    queue_head = task;
  queue_tail = task;
  queue_len++;
  pthread_cond_signal(&queue_not_empty);
  pthread_mutex_unlock(&queue_lock);

  return true;
}

/* Consumer side - runs on each of the avd_scan_threads worker
 * threads. Blocks for work, exits once shutting_down is set AND the
 * queue has drained (rather than abandoning whatever's still queued,
 * since those requests are otherwise silently lost with no verdict
 * sent). */
static void *scan_worker_main(void *arg) {
  (void)arg;

  for (;;) {
    struct scan_task *task;

    pthread_mutex_lock(&queue_lock);
    while (!queue_head && !shutting_down)
      pthread_cond_wait(&queue_not_empty, &queue_lock);

    if (!queue_head && shutting_down) {
      pthread_mutex_unlock(&queue_lock);
      break;
    }

    task = queue_head;
    queue_head = task->next;
    if (!queue_head)
      queue_tail = NULL;
    queue_len--;
    pthread_cond_signal(&queue_not_full);
    pthread_mutex_unlock(&queue_lock);

    handle_scan_request(task->reqid, task->pid, task->path,
                        task->sha256_hex);
    free(task);
  }

  return NULL;
}

/* maxlen bounds are defense-in-depth, not the primary guard - msg_handler()
 * below already rejects anything not from the kernel (nlmsg_get_src()
 * check), and the kernel always sends AV_A_PATH/AV_A_SHA256 well within
 * these sizes (PATH_MAX and a 64-hex-char digest + NUL respectively, see
 * netlink_proto.h). Bounding them anyway means a future kernel-side bug
 * or protocol change can't hand this process an unbounded string to deal
 * with by accident. */
static struct nla_policy av_policy[AV_A_MAX + 1] = {
    [AV_A_REQID] = {.type = NLA_U64},
    [AV_A_PID] = {.type = NLA_U32},
    [AV_A_PATH] = {.type = NLA_STRING, .maxlen = AV_PATH_ATTR_MAXLEN},
    [AV_A_SHA256] = {.type = NLA_STRING, .maxlen = AV_SHA256_ATTR_MAXLEN + 1},
};

static int msg_handler(struct nl_msg *msg, void *arg) {
  (void)arg;
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  struct genlmsghdr *gnlh = nlmsg_data(nlh);
  struct nlattr *attrs[AV_A_MAX + 1];

  if (genlmsg_parse(nlh, 0, attrs, AV_A_MAX, av_policy) < 0) {
    fprintf(stderr, "avd: failed to parse incoming message\n");
    return NL_SKIP;
  }

  /* AV_C_SCAN_REQUEST must originate from the kernel (source portid ==
   * 0). Unlike AV_C_VERDICT on the kernel side (see the daemon_portid
   * check in netlink_chan.c's av_nl_verdict_doit()), nothing here
   * restricts who may unicast a message straight to this socket's
   * portid: this process never registers its own genl_family, so
   * GENL_ADMIN_PERM (which only gates access to a *kernel*-registered
   * .doit handler) doesn't apply to it at all. Any local process that
   * knows avd's portid - which defaults to avd's own pid via netlink
   * autobind, so it's as discoverable as `pgrep avd` - could otherwise
   * forge a SCAN_REQUEST with an arbitrary path/reqid directly to this
   * socket, bypassing the kernel (and any CAP_NET_ADMIN requirement)
   * entirely: flooding the bounded scan queue to starve real
   * detection, or directing this (typically root) daemon to
   * scan/quarantine a path of the attacker's choosing.
   *
   * MUST check nlmsg_get_src(msg)->nl_pid, NOT nlh->nlmsg_pid: the
   * latter is part of the message payload itself, written by whoever
   * constructed the message (our own kernel code happens to put 0
   * there via genlmsg_put()'s `port` argument, but nothing stops a
   * forged message from claiming the same value) - checking it
   * defeats the whole point of this guard, since the exact spoofer
   * this is meant to stop would just set that field to 0 themselves.
   * nlmsg_get_src() instead returns the sockaddr_nl the kernel itself
   * populated from the delivering socket's real, kernel-enforced
   * portid (via the recvmsg() call's out-of-band source address, same
   * trust boundary as genl_info->snd_portid on the kernel side) -
   * that's not attacker-writable. */
  if (gnlh->cmd == AV_C_SCAN_REQUEST) {
    struct sockaddr_nl *src = nlmsg_get_src(msg);

    if (!src || src->nl_pid != 0) {
      fprintf(stderr,
              "avd: SCAN_REQUEST from non-kernel portid %u ignored "
              "(possible spoofed request)\n",
              src ? src->nl_pid : (uint32_t)-1);
      return NL_SKIP;
    }
  }

  if (gnlh->cmd == AV_C_SCAN_REQUEST) {
    if (!attrs[AV_A_REQID] || !attrs[AV_A_PATH]) {
      fprintf(stderr, "avd: malformed SCAN_REQUEST (missing attrs)\n");
      return NL_SKIP;
    }
    if (!enqueue_scan_task(
            nla_get_u64(attrs[AV_A_REQID]),
            attrs[AV_A_PID] ? nla_get_u32(attrs[AV_A_PID]) : 0,
            nla_get_string(attrs[AV_A_PATH]),
            attrs[AV_A_SHA256] ? nla_get_string(attrs[AV_A_SHA256]) : ""))
      fprintf(stderr,
              "avd: dropped SCAN_REQUEST reqid=%llu (shutting down or "
              "out of memory) - kernel side will fail open on timeout\n",
              (unsigned long long)nla_get_u64(attrs[AV_A_REQID]));
  }

  return NL_OK;
}

static int register_with_kernel(void) {
  struct nl_msg *msg;
  int ret;

  msg = nlmsg_alloc();
  if (!msg)
    return -1;

  if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                   AV_C_REGISTER, AV_GENL_VERSION)) {
    nlmsg_free(msg);
    return -1;
  }

  ret = nl_send_auto(sock, msg);
  nlmsg_free(msg);
  return ret < 0 ? -1 : 0;
}

/* ------------------------------------------------------------------
 * Control socket - avctl/GUI management path. See
 * docs/avd-socket-protocol.md for the full wire protocol; this is the
 * implementation side of that document.
 * ------------------------------------------------------------------ */

static int write_all(int fd, const char *buf, size_t len) {
  size_t off = 0;

  while (off < len) {
    ssize_t n = write(fd, buf + off, len - off);

    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    off += (size_t)n;
  }
  return 0;
}

static void send_err(int fd, const char *msg) {
  char buf[256];

  snprintf(buf, sizeof(buf), "ERR %s\n", msg);
  write_all(fd, buf, strlen(buf));
}

/*
 * Reads one newline-terminated line from `fd` into `buf` (NUL
 * terminated, newline stripped), one byte at a time - simple rather
 * than fast, which is fine here: control-socket commands are rare
 * relative to the actual scan path and never more than
 * AVD_SOCK_LINE_MAX bytes. Returns the line length on success, 0 on a
 * clean EOF before any data, -1 on a read error, a timeout, or on
 * exceeding `bufsz` without finding a newline (a line this long can
 * only be a malformed/hostile client - see AVD_SOCK_LINE_MAX's
 * comment).
 *
 * Enforces its own ABSOLUTE deadline (AVD_CONTROL_RECV_TIMEOUT_SECS
 * from the first call), on top of whatever SO_RCVTIMEO the caller may
 * have set on `fd` - SO_RCVTIMEO alone only bounds each individual
 * read() call, so a client trickling one byte just under that
 * interval at a time would never trip any single call's timeout and
 * could hold a connection (and its AVD_CONTROL_MAX_CONNS slot) open
 * for up to AVD_SOCK_LINE_MAX reads' worth of that interval -
 * effectively unbounded in practice. This function has exactly one
 * caller (control_conn_main()), so hardcoding the same constant here
 * rather than threading a deadline parameter through is the simpler
 * choice for now.
 */
static ssize_t read_line(int fd, char *buf, size_t bufsz) {
  size_t len = 0;
  struct timespec deadline;

  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += AVD_CONTROL_RECV_TIMEOUT_SECS;

  while (len + 1 < bufsz) {
    struct timespec now;
    char c;
    ssize_t n;

    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec > deadline.tv_sec ||
        (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
      errno = ETIMEDOUT;
      return -1;
    }

    n = read(fd, &c, 1);

    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0)
      return len == 0 ? 0 : -1; /* EOF mid-line - treat as malformed,
                                * not as "here's a valid short line" */
    if (c == '\n') {
      buf[len] = '\0';
      return (ssize_t)len;
    }
    buf[len++] = c;
  }
  return -1; /* line too long */
}

/* id must be a bare basename (no '/', not "." or ".."), matching what
 * cmd_quarantine_list() returns - reconstructed into a path below via
 * plain snprintf(), so this is the only thing standing between a
 * hostile QUARANTINE RESTORE/DELETE argument and a path-traversal
 * escape out of quarantine_dir. */
static int quarantine_id_valid(const char *id) {
  if (!id[0] || strchr(id, '/'))
    return 0;
  if (!strcmp(id, ".") || !strcmp(id, ".."))
    return 0;
  if (strlen(id) >= PATH_MAX - 32) /* leaves room for the .quarantined.meta suffix */
    return 0;
  return 1;
}

static void cmd_status(int fd) {
  char row[256];
  size_t qlen;

  pthread_mutex_lock(&queue_lock);
  qlen = queue_len;
  pthread_mutex_unlock(&queue_lock);

  write_all(fd, "OK\n", 3);
  write_all(fd, "COUNT 1\n", 8);
  snprintf(row, sizeof(row), "%ld\t%d\t%zu\t%zu\t%zu\t%d\n",
           (long)(time(NULL) - start_time), compiled_rules ? 1 : 0,
           fuzzy_corpus_count, tlsh_corpus_count, qlen, avd_scan_threads);
  write_all(fd, row, strlen(row));
  write_all(fd, "END\n", 4);
}

/* A peer may only see verdict history for files it owns - root sees
 * everything, an entry whose owner couldn't be determined ((uid_t)-1,
 * see perform_scan()) is root-only. Without this, any local user could
 * read every other user's (and root's) scanned paths and SHA-256
 * hashes over the world-writable control socket. */
static bool verdict_visible_to(const struct verdict_record *rec,
                               uid_t peer_uid, bool is_root) {
  return is_root || rec->uid == peer_uid;
}

static void cmd_verdicts_recent(int fd, size_t n, uid_t peer_uid,
                                bool is_root) {
  struct verdict_record *snap;
  char hdr[32];
  size_t avail, take, i;

  pthread_mutex_lock(&verdict_history_lock);
  avail = verdict_history_count;
  snap = avail ? malloc(avail * sizeof(*snap)) : NULL;
  if (avail && !snap) {
    pthread_mutex_unlock(&verdict_history_lock);
    send_err(fd, "out of memory");
    return;
  }
  for (i = 0; i < avail; i++) {
    /* Newest first - see verdict_history_next's own comment for why
     * (verdict_history_next - 1 - i) mod MAX is the i-th most recent
     * entry. */
    size_t idx = (verdict_history_next + AVD_VERDICT_HISTORY_MAX - 1 - i) %
                AVD_VERDICT_HISTORY_MAX;
    snap[i] = verdict_history[idx];
  }
  pthread_mutex_unlock(&verdict_history_lock);

  /* Two passes over the (already newest-first, at most
   * AVD_VERDICT_HISTORY_MAX = 500 rows) snapshot: first count how many
   * this peer may see so COUNT is accurate before any row is sent (the
   * wire format requires COUNT up front - see docs/avd-socket-protocol.md),
   * then emit exactly those, still capped at `n`. */
  take = 0;
  for (i = 0; i < avail && take < n; i++) {
    if (verdict_visible_to(&snap[i], peer_uid, is_root))
      take++;
  }

  write_all(fd, "OK\n", 3);
  snprintf(hdr, sizeof(hdr), "COUNT %zu\n", take);
  write_all(fd, hdr, strlen(hdr));
  for (i = 0, take = 0; i < avail && take < n; i++) {
    char row[PATH_MAX + 256];

    if (!verdict_visible_to(&snap[i], peer_uid, is_root))
      continue;
    take++;

    snprintf(row, sizeof(row), "%llu\t%ld\t%u\t%s\t%s\t%s\t%s\t%d\t%d\n",
             (unsigned long long)snap[i].id, (long)snap[i].timestamp,
             snap[i].pid, snap[i].path, snap[i].sha256_hex,
             snap[i].verdict == AV_VERDICT_MALICIOUS ? "MALICIOUS" : "CLEAN",
             snap[i].rule_name, snap[i].score, snap[i].on_demand ? 1 : 0);
    /* Stop at the first failed write rather than pressing on through
     * the rest of `take` rows - SO_SNDTIMEO (see control_conn_main())
     * bounds each individual write_all() call, not this whole loop,
     * so a client that stops reading would otherwise make this
     * connection (and its AVD_CONTROL_MAX_CONNS slot) pay a full
     * timeout interval PER REMAINING ROW instead of just one. */
    if (write_all(fd, row, strlen(row)) != 0) {
      free(snap);
      return;
    }
  }
  write_all(fd, "END\n", 4);
  free(snap);
}

static int filter_quarantined(const struct dirent *de) {
  static const char suffix[] = ".quarantined";
  size_t suflen = sizeof(suffix) - 1;
  size_t len = strlen(de->d_name);

  return len > suflen && !strcmp(de->d_name + len - suflen, suffix);
}

static void cmd_quarantine_list(int fd, uid_t peer_uid, bool is_root) {
  struct dirent **namelist;
  char hdr[32];
  int n, i;
  bool *visible = NULL;
  int visible_count = 0;

  n = scandir(quarantine_dir, &namelist, filter_quarantined, alphasort);
  if (n < 0) {
    send_err(fd, "could not read quarantine directory");
    return;
  }

  /* Same owner-only visibility rule as cmd_verdicts_recent() - a
   * quarantined file's path/hash is exactly the kind of information
   * that shouldn't leak to an unrelated local user. An entry with no
   * metadata (or a read failure) has no known owner, so it's
   * root-only - fail closed rather than guess. Precomputed into
   * `visible` (parallel to namelist) so COUNT, sent before any row,
   * matches what actually gets emitted below. */
  visible = n ? malloc((size_t)n * sizeof(*visible)) : NULL;
  if (n && !visible) {
    for (i = 0; i < n; i++)
      free(namelist[i]);
    free(namelist);
    send_err(fd, "out of memory");
    return;
  }
  for (i = 0; i < n; i++) {
    char meta_path[PATH_MAX + 72]; /* see cmd_quarantine_restore()'s comment */
    struct quarantine_meta meta;

    snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", quarantine_dir,
             namelist[i]->d_name);

    visible[i] = is_root || (read_quarantine_meta(meta_path, &meta) == 0 &&
                             meta.original_uid == peer_uid);
    if (visible[i])
      visible_count++;
  }

  write_all(fd, "OK\n", 3);
  snprintf(hdr, sizeof(hdr), "COUNT %d\n", visible_count);
  write_all(fd, hdr, strlen(hdr));

  for (i = 0; i < n; i++) {
    static const char suffix[] = ".quarantined";
    size_t suflen = sizeof(suffix) - 1;
    size_t namelen = strlen(namelist[i]->d_name);
    char id[PATH_MAX];
    char meta_path[PATH_MAX + 72]; /* see cmd_quarantine_restore()'s comment */
    struct quarantine_meta meta;
    char row[AVD_ROW_MAX];

    if (!visible[i]) {
      free(namelist[i]);
      continue;
    }

    snprintf(id, sizeof(id), "%.*s", (int)(namelen - suflen),
             namelist[i]->d_name);
    snprintf(meta_path, sizeof(meta_path), "%s/%s.meta", quarantine_dir,
             namelist[i]->d_name);

    if (read_quarantine_meta(meta_path, &meta) == 0)
      snprintf(row, sizeof(row), "%s\t%s\t%ld\t%s\t%s\n", id,
               meta.original_path, (long)meta.timestamp, meta.rule_name,
               meta.sha256_hex);
    else
      /* No metadata - quarantined before this feature existed, or the
       * sidecar write itself failed (see quarantine_file()'s comment).
       * Still list it (it's a real quarantined file on disk) rather
       * than hiding it, just without the extra fields. Only reachable
       * here when is_root, since a missing/unreadable meta makes
       * visible[i] false for anyone else above. */
      snprintf(row, sizeof(row), "%s\t?\t0\t?\t?\n", id);

    /* Stop at the first failed write, same reasoning as
     * cmd_verdicts_recent()'s identical check - still have to free
     * every remaining scandir() entry (not just the one just used)
     * before returning, unlike a plain "return" would give us. */
    if (write_all(fd, row, strlen(row)) != 0) {
      free(namelist[i]);
      for (i++; i < n; i++)
        free(namelist[i]);
      free(namelist);
      free(visible);
      return;
    }
    free(namelist[i]);
  }
  free(namelist);
  free(visible);
  write_all(fd, "END\n", 4);
}

static void cmd_quarantine_restore(int fd, const char *id) {
  /* PATH_MAX*2 headroom: `quarantine_dir` and `id` are each bounded to
   * well under PATH_MAX at runtime (quarantine_id_valid() checked
   * above), but gcc's -Wformat-truncation can't see that dynamic
   * bound, only that both are `const char *` with no static length
   * limit it can prove - same margin used throughout this file's other
   * multi-component path buffers. */
  char dest[PATH_MAX * 2], meta_path[PATH_MAX * 2 + 8];
  struct quarantine_meta meta;
  struct stat st;

  if (!quarantine_id_valid(id)) {
    send_err(fd, "invalid id");
    return;
  }

  /* Fail closed on truncation: a silently-truncated dest would open,
   * chmod, or rename the wrong quarantine entry with no error. The
   * PATH_MAX*2 buffer above already gives gcc room to prove this
   * can't happen for valid ids, so any failure here is a real logic
   * error worth refusing rather than proceeding with a wrong path. */
  {
    int dn = snprintf(dest, sizeof(dest), "%s/%s.quarantined", quarantine_dir, id);
    int mn;
    if (dn < 0 || (size_t)dn >= sizeof(dest)) {
      send_err(fd, "internal path error");
      return;
    }
    mn = snprintf(meta_path, sizeof(meta_path), "%s.meta", dest);
    if (mn < 0 || (size_t)mn >= sizeof(meta_path)) {
      send_err(fd, "internal path error");
      return;
    }
  }

  if (read_quarantine_meta(meta_path, &meta) != 0) {
    send_err(fd, "no metadata for this id (quarantined before this feature "
                "existed, or corrupt) - cannot determine where to restore it");
    return;
  }

  /* Opened once, here, by path only this one time - every step below
   * that can act through this fd instead (fchmod/fchown, not
   * chmod/chown by path) does, precisely so that once meta.original_path
   * becomes reachable (the rename() below), the file already has its
   * final mode/owner and there is no later path-based operation left
   * for anything to race against it. */
  {
    /* O_NOFOLLOW: dest must be the regular quarantine file this daemon
     * created, never a symlink planted at a predicted id. The fstat() +
     * S_ISREG check below is the second half of the same guard. */
    int qfd = open(dest, O_RDONLY | O_NOFOLLOW);

    if (qfd < 0) {
      send_err(fd, "quarantined file not found");
      return;
    }

    if (fstat(qfd, &st) != 0 || !S_ISREG(st.st_mode)) {
      close(qfd);
      send_err(fd, "quarantined file is not a regular file - refusing to restore");
      return;
    }

    /* No clobbering - if something already occupies the original path,
     * refuse rather than guess. Documented, narrow limitation: extend
     * later with an explicit alternate-destination argument if this
     * turns out to matter in practice. */
    if (lstat(meta.original_path, &st) == 0) {
      close(qfd);
      send_err(fd, "original path is occupied - move or remove it first");
      return;
    }

    if (fchmod(qfd, meta.original_mode) != 0) {
      close(qfd);
      send_err(fd, "chmod failed");
      return;
    }

    /* fchown() on the already-open fd, NOT chown(meta.original_path,
     * ...) after rename() - a path-based chown() done AFTER the file
     * is reachable at meta.original_path has a TOCTOU: anything with
     * write access to that path's parent directory could swap in a
     * symlink between the rename() succeeding and the chown() call,
     * and chown() follows symlinks - letting that attacker redirect a
     * root-run chown() to an arbitrary target of their choosing.
     * fchown() on this fd is immune: it always acts on the exact
     * inode opened above, and happens before the file is reachable at
     * meta.original_path at all, so there is nothing left to swap. */
    if (fchown(qfd, meta.original_uid, meta.original_gid) != 0)
      fprintf(stderr,
              "avd: quarantine restore: fchown of \"%s\" failed: %s (file "
              "will be restored under avd's own uid/gid instead)\n",
              dest, strerror(errno));

    if (rename(dest, meta.original_path) != 0) {
      /* Leave it chmod'd/chown'd back to original but still under
       * quarantine_dir rather than deleting the .meta - the operator
       * can still recover it manually (e.g. the two directories are
       * on different filesystems), and losing the recovery record
       * here would be strictly worse than a restore that has to be
       * retried. */
      close(qfd);
      send_err(fd, "rename failed (different filesystem? check "
                  "/var/lib/av-quarantine manually)");
      return;
    }
    close(qfd);
  }

  unlink(meta_path);
  printf("avd: RESTORED \"%s\" -> \"%s\"\n", dest, meta.original_path);
  write_all(fd, "OK\n", 3);
}

static void cmd_quarantine_delete(int fd, const char *id) {
  char dest[PATH_MAX * 2], meta_path[PATH_MAX * 2 + 8]; /* see cmd_quarantine_restore()'s comment */

  if (!quarantine_id_valid(id)) {
    send_err(fd, "invalid id");
    return;
  }

  /* Same truncation-fail-closed reasoning as cmd_quarantine_restore(). */
  {
    int dn = snprintf(dest, sizeof(dest), "%s/%s.quarantined", quarantine_dir, id);
    int mn;
    if (dn < 0 || (size_t)dn >= sizeof(dest)) {
      send_err(fd, "internal path error");
      return;
    }
    mn = snprintf(meta_path, sizeof(meta_path), "%s.meta", dest);
    if (mn < 0 || (size_t)mn >= sizeof(meta_path)) {
      send_err(fd, "internal path error");
      return;
    }
  }

  if (unlink(dest) != 0 && errno != ENOENT) {
    send_err(fd, "delete failed");
    return;
  }
  unlink(meta_path); /* best effort - dest is already gone either way */
  printf("avd: DELETED quarantined file \"%s\"\n", dest);
  write_all(fd, "OK\n", 3);
}

static void cmd_scan(int fd, const char *path) {
  struct scan_result result;
  char row[PATH_MAX + 256];
  struct stat st;
  int sfd;

  if (path[0] != '/') {
    send_err(fd, "path must be absolute");
    return;
  }

  /* O_NONBLOCK: without it, opening a FIFO for read-only blocks this
   * connection's own thread until a writer opens the other end -
   * given AVD_CONTROL_MAX_CONNS bounds those threads (see
   * control_accept_main()'s comment), a client repeatedly SCANning a
   * FIFO path could tie up every slot indefinitely. With O_NONBLOCK
   * the open succeeds immediately regardless, and the fstat()+
   * S_ISREG() check right below rejects it before perform_scan() ever
   * touches it - along with every other non-regular-file case
   * (character/block devices, sockets, directories). */
  sfd = open(path, O_RDONLY | O_NONBLOCK);
  if (sfd < 0) {
    send_err(fd, "could not open path for scanning");
    return;
  }

  if (fstat(sfd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(sfd);
    send_err(fd, "path is not a regular file");
    return;
  }

  /* Clear O_NONBLOCK now that the file is known-regular (where the
   * flag has no real read() effect anyway) - keeps this fd behaving
   * identically to every other scan path's plain O_RDONLY open from
   * here on, rather than leaving a flag set for a FIFO/device case
   * that's already been ruled out. */
  if (fcntl(sfd, F_SETFL, O_RDONLY) != 0) {
    close(sfd);
    send_err(fd, "could not prepare file for scanning");
    return;
  }

  perform_scan(sfd, path, NULL, 0, true, &result);
  close(sfd);

  write_all(fd, "OK\n", 3);
  write_all(fd, "COUNT 1\n", 8);
  snprintf(row, sizeof(row), "%s\t%s\t%d\t%s\n",
           result.verdict == AV_VERDICT_MALICIOUS ? "MALICIOUS" : "CLEAN",
           result.rule_name, result.score, result.sha256_hex);
  write_all(fd, row, strlen(row));
  write_all(fd, "END\n", 4);
}

/*
 * One control-socket connection, one command. Every state-changing
 * verb (SCAN, QUARANTINE RESTORE/DELETE) requires `is_root` - resolved
 * once by the caller via SO_PEERCRED, NOT re-checked per verb inside
 * here, so this is the single gate all three go through. STATUS
 * answers any peer (aggregate counts only, nothing per-file). VERDICTS
 * and QUARANTINE LIST answer any peer too, but each row is filtered to
 * `peer_uid` (root sees everything) inside cmd_verdicts_recent()/
 * cmd_quarantine_list() - unlike STATUS, these carry other users'
 * paths and SHA-256 hashes, which the world-writable socket must not
 * hand out to an unrelated local user. See docs/avd-socket-protocol.md.
 */
/*
 * sizeof(literal) - 1, NOT a hand-counted length - a manually-counted
 * prefix length here previously drifted from the actual string length
 * (17 vs. the real 16 for "VERDICTS RECENT ", 20 vs. 19 for
 * "QUARANTINE RESTORE ", 19 vs. 18 for "QUARANTINE DELETE "), which
 * silently broke every one of those commands: strncmp() with too LONG
 * an n implicitly requires line[n-1] to be the prefix's own NUL
 * terminator too, so it never matches a real command with an argument
 * after it. Caught by tests/test_avd_socket.sh - see that file's
 * comment for the exact repro. sizeof(literal)-1 can't drift from the
 * literal it's computed from.
 */
#define PREFIX_MATCH(line, literal) \
  (!strncmp((line), (literal), sizeof(literal) - 1))

/* Guards control_scan_conn_count against AVD_CONTROL_MAX_SCAN_CONNS - see
 * that constant's comment. A separate lock from control_conn_count_lock
 * rather than reusing it: this one is held only around the SCAN branch
 * below (a coarser, much longer-held region spanning the whole
 * perform_scan() call), so keeping it distinct avoids adding that hold
 * time to control_conn_count_lock's otherwise brief, frequent critical
 * sections. */
static pthread_mutex_t control_scan_conn_lock = PTHREAD_MUTEX_INITIALIZER;
static int control_scan_conn_count;

static void handle_control_line(int fd, const char *line, uid_t peer_uid,
                                bool is_root) {
  unsigned long n;
  char *end;

  if (!strcmp(line, "STATUS")) {
    cmd_status(fd);
  } else if (PREFIX_MATCH(line, "VERDICTS RECENT ")) {
    const char *arg = line + sizeof("VERDICTS RECENT ") - 1;

    n = strtoul(arg, &end, 10);
    if (end == arg) {
      send_err(fd, "malformed VERDICTS RECENT (expected a count)");
      return;
    }
    cmd_verdicts_recent(fd, (size_t)n, peer_uid, is_root);
  } else if (!strcmp(line, "QUARANTINE LIST")) {
    cmd_quarantine_list(fd, peer_uid, is_root);
  } else if (PREFIX_MATCH(line, "QUARANTINE RESTORE ")) {
    if (!is_root) {
      send_err(fd, "permission denied (use: pkexec avctl quarantine restore "
                   "<id>)");
      return;
    }
    cmd_quarantine_restore(fd, line + sizeof("QUARANTINE RESTORE ") - 1);
  } else if (PREFIX_MATCH(line, "QUARANTINE DELETE ")) {
    if (!is_root) {
      send_err(fd, "permission denied (use: pkexec avctl quarantine delete "
                   "<id>)");
      return;
    }
    cmd_quarantine_delete(fd, line + sizeof("QUARANTINE DELETE ") - 1);
  } else if (PREFIX_MATCH(line, "SCAN ")) {
    bool scan_slot_reserved;

    if (!is_root) {
      send_err(fd, "permission denied (use: pkexec avctl scan <path>)");
      return;
    }

    pthread_mutex_lock(&control_scan_conn_lock);
    scan_slot_reserved = control_scan_conn_count < AVD_CONTROL_MAX_SCAN_CONNS;
    if (scan_slot_reserved)
      control_scan_conn_count++;
    pthread_mutex_unlock(&control_scan_conn_lock);

    if (!scan_slot_reserved) {
      send_err(fd, "too many concurrent SCAN requests - try again shortly");
      return;
    }

    cmd_scan(fd, line + sizeof("SCAN ") - 1);

    pthread_mutex_lock(&control_scan_conn_lock);
    control_scan_conn_count--;
    pthread_mutex_unlock(&control_scan_conn_lock);
  } else {
    send_err(fd, "unknown command");
  }
}

struct control_conn_ctx {
  int fd;
  /* Resolved once in control_accept_main() (before the per-uid slot
   * check below reserves against it) and reused here for both that
   * reservation's matching release and is_root, instead of a second
   * SO_PEERCRED call on the same fd for the same, connection-lifetime-
   * invariant value. */
  uid_t uid;
  bool have_uid;
};

/* Guards control_conn_count, incremented (with the AVD_CONTROL_MAX_CONNS
 * check) in control_accept_main() before a connection thread is
 * spawned, decremented here on every exit from control_conn_main() -
 * there is exactly one exit point below, so one decrement covers it. */
static pthread_mutex_t control_conn_count_lock = PTHREAD_MUTEX_INITIALIZER;
static int control_conn_count;

/* Per-uid connection counts backing AVD_CONTROL_MAX_CONNS_PER_UID - sized
 * to AVD_CONTROL_MAX_CONNS since that's the hard ceiling on how many
 * distinct uids can have a slot open at any one time, so a fixed array
 * scanned linearly is simpler than a hash table and plenty fast at this
 * size. Both helpers below assume control_conn_count_lock is already held
 * by the caller - they're not independently thread-safe. A slot with
 * count == 0 is free regardless of what `uid` last held it. */
struct uid_conn_count {
  uid_t uid;
  int count;
};
static struct uid_conn_count uid_conn_counts[AVD_CONTROL_MAX_CONNS];

/* Returns true and records the reservation if `uid` is under
 * AVD_CONTROL_MAX_CONNS_PER_UID, false (no state change) otherwise. */
static bool uid_conn_reserve(uid_t uid) {
  int free_idx = -1;

  for (int i = 0; i < AVD_CONTROL_MAX_CONNS; i++) {
    if (uid_conn_counts[i].count > 0 && uid_conn_counts[i].uid == uid) {
      if (uid_conn_counts[i].count >= AVD_CONTROL_MAX_CONNS_PER_UID)
        return false;
      uid_conn_counts[i].count++;
      return true;
    }
    if (uid_conn_counts[i].count == 0 && free_idx < 0)
      free_idx = i;
  }
  /* free_idx < 0 cannot happen here: the table has AVD_CONTROL_MAX_CONNS
   * slots and a reservation is only ever made alongside a global
   * control_conn_count increment bounded by that same constant, so at
   * most AVD_CONTROL_MAX_CONNS uids can be reserved at once. */
  uid_conn_counts[free_idx].uid = uid;
  uid_conn_counts[free_idx].count = 1;
  return true;
}

static void uid_conn_release(uid_t uid) {
  for (int i = 0; i < AVD_CONTROL_MAX_CONNS; i++) {
    if (uid_conn_counts[i].count > 0 && uid_conn_counts[i].uid == uid) {
      uid_conn_counts[i].count--;
      return;
    }
  }
}

/* Releases one control_conn_count slot and, if `have_uid`, its matching
 * per-uid reservation - the two are always taken and released together
 * (see control_accept_main()), so every release path shares this instead
 * of repeating the lock/decrement/release pairing at each of the three
 * spots that need it. */
static void control_conn_release_slot(uid_t uid, bool have_uid) {
  pthread_mutex_lock(&control_conn_count_lock);
  control_conn_count--;
  if (have_uid)
    uid_conn_release(uid);
  pthread_mutex_unlock(&control_conn_count_lock);
}

static void *control_conn_main(void *arg) {
  struct control_conn_ctx *ctx = arg;
  char line[AVD_SOCK_LINE_MAX];
  struct timeval tv;
  bool is_root;
  ssize_t len;

  /* Bounds how long this connection's thread (and therefore its
   * AVD_CONTROL_MAX_CONNS slot) can be tied up on a single blocking
   * read()/write() call - read_line() below already treats any
   * read() error other than EINTR as failure, so a timeout
   * (EAGAIN/EWOULDBLOCK once this fires) falls out as the same
   * "malformed request" response as any other read failure, with no
   * separate handling needed there; write_all() (used by every cmd_*
   * response below) already does the same for write() errors. This
   * alone is NOT sufficient against a client trickling one byte just
   * under this interval at a time (SO_RCVTIMEO only bounds each
   * individual call, not the cumulative time to read a whole line) -
   * read_line() additionally enforces its own absolute deadline for
   * exactly that reason; SO_RCVTIMEO stays as a second layer under
   * it. SO_SNDTIMEO has no such second layer today, but write_all()
   * only ever sends a bounded, small response (a handful of KB at
   * most for e.g. VERDICTS RECENT), so a client that stops reading
   * mid-response is the only way to hit it, not a slow-trickle
   * variant of the same problem. Best-effort: a failure to set either
   * is logged but doesn't refuse the connection outright - worst case
   * it behaves like it did before this fix. */
  tv.tv_sec = AVD_CONTROL_RECV_TIMEOUT_SECS;
  tv.tv_usec = 0;
  if (setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
    fprintf(stderr, "avd: could not set control connection receive timeout: %s\n",
            strerror(errno));
  if (setsockopt(ctx->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
    fprintf(stderr, "avd: could not set control connection send timeout: %s\n",
            strerror(errno));

  /* ctx->uid/ctx->have_uid came from control_accept_main()'s SO_PEERCRED
   * call, which returns credentials the KERNEL captured at connect()
   * time from the connecting process - not attacker-writable, same
   * trust boundary as nlmsg_get_src() in msg_handler() above, and
   * invariant for the life of the connection so resolving it once
   * there and reusing it here is equivalent to a second call. A
   * failure there (should not happen for a genuine AF_UNIX peer) fails
   * closed: is_root stays false, so every privileged verb gets
   * rejected rather than silently trusted. */
  is_root = ctx->have_uid && ctx->uid == 0;

  len = read_line(ctx->fd, line, sizeof(line));
  if (len < 0)
    send_err(ctx->fd,
             "malformed request (missing newline, line too long, or timed out)");
  else if (len > 0)
    handle_control_line(ctx->fd, line, ctx->uid, is_root);
  /* len == 0: peer connected and disconnected without sending
   * anything - nothing to respond to, not an error. */

  close(ctx->fd);
  control_conn_release_slot(ctx->uid, ctx->have_uid);
  free(ctx);

  return NULL;
}

/* Best-effort mkdir of `path`'s parent directory - mirrors
 * ensure_quarantine_dir()'s stance (not fatal if it already exists,
 * loud if it can't be created for some other reason). Needed for
 * manual/test runs of avd outside systemd; under avd.service,
 * RuntimeDirectory=avd already creates /run/avd before avd starts, so
 * this is a no-op there (mkdir returns EEXIST). dirname() may modify
 * its argument, hence the local scratch copy. */
static int ensure_parent_dir(const char *path, mode_t mode) {
  char buf[PATH_MAX];
  char *dir;
  int sn;

  /* Fail closed on truncation: a truncated parent would mkdir/chmod
   * the wrong directory with no error. */
  sn = snprintf(buf, sizeof(buf), "%s", path);
  if (sn < 0 || (size_t)sn >= sizeof(buf)) {
    fprintf(stderr, "avd: path too long: \"%s\"\n", path);
    return -1;
  }
  dir = dirname(buf);
  if (mkdir(dir, mode) != 0 && errno != EEXIST) {
    fprintf(stderr, "avd: could not create directory \"%s\": %s\n", dir,
            strerror(errno));
    return -1;
  }
  /* Same gate as ensure_quarantine_dir(), over the whole ancestor
   * chain: a pre-existing parent that an unprivileged user can modify
   * must not be silently accepted as "directory already exists" -
   * they could replace the socket between the bind() below and its
   * chmod(). Checked after a successful mkdir() as well, for the same
   * attacker-owned-ancestor reason. A freshly mkdir()'d parent is ours
   * by construction, so only pre-existing paths needed the old check;
   * the chain check covers both uniformly. Sticky world-writable
   * parents stay supported (safe: only the entry owner can
   * rename/remove entries there). */
  return dir_hierarchy_trusted("socket parent", dir, true);
}

static int start_control_socket(void) {
  struct sockaddr_un addr;
  struct stat st;
  int sn;

  /* Quarantine and socket paths come from argv/env (see main()), so a
   * relative value or a bare filename would silently resolve against
   * avd's cwd - fail closed on anything that isn't an absolute path
   * rather than binding/ writing somewhere the operator didn't mean. */
  if (control_sock_path[0] != '/') {
    fprintf(stderr,
            "avd: control socket path must be absolute, got \"%s\"\n",
            control_sock_path);
    return -1;
  }

  if (ensure_parent_dir(control_sock_path, 0755) != 0)
    return -1;

  if (strlen(control_sock_path) >= sizeof(addr.sun_path)) {
    fprintf(stderr, "avd: control socket path \"%s\" too long\n",
            control_sock_path);
    return -1;
  }

  /* A stale socket file from a previous unclean shutdown (kill -9,
   * crash) would otherwise make bind() fail with EADDRINUSE even
   * though nothing is listening on it any more. lstat() (not stat())
   * first so a planted symlink here is refused rather than unlinked-
   * then-replaced: unlink() on a symlink only removes the link
   * itself, but refusing outright keeps an attacker-planted path from
   * ever becoming the live control socket, and a live symlink points
   * at a target the subsequent bind() must not silently shadow. A
   * stale real socket file (S_ISSOCK) or nothing at all are the only
   * two states that proceed. */
  if (lstat(control_sock_path, &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      fprintf(stderr,
              "avd: control socket path \"%s\" is a symlink - refusing to replace it\n",
              control_sock_path);
      return -1;
    }
    if (!S_ISSOCK(st.st_mode)) {
      fprintf(stderr,
              "avd: control socket path \"%s\" exists and is not a socket - refusing to replace it\n",
              control_sock_path);
      return -1;
    }
    unlink(control_sock_path);
  } else if (errno != ENOENT) {
    fprintf(stderr, "avd: could not stat control socket path \"%s\": %s\n",
            control_sock_path, strerror(errno));
    return -1;
  }

  control_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (control_sock_fd < 0) {
    fprintf(stderr, "avd: control socket() failed: %s\n", strerror(errno));
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  /* Fail closed on truncation: a truncated socket path would bind (and
   * chmod 0666) the wrong path with no error. Length already checked
   * above, so this is defense in depth. */
  sn = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", control_sock_path);
  if (sn < 0 || (size_t)sn >= sizeof(addr.sun_path)) {
    fprintf(stderr, "avd: control socket path \"%s\" too long\n",
            control_sock_path);
    close(control_sock_fd);
    control_sock_fd = -1;
    return -1;
  }

  /* SUN_LEN (used length), not sizeof(addr): AF_UNIX callers must pass
   * the length covering sun_family plus the actual path bytes, and
   * sizeof(struct sockaddr_un) overstates it whenever sun_path is
   * shorter than the buffer. */
  if (bind(control_sock_fd, (struct sockaddr *)&addr, SUN_LEN(&addr)) != 0) {
    fprintf(stderr, "avd: could not bind control socket \"%s\": %s\n",
            control_sock_path, strerror(errno));
    close(control_sock_fd);
    control_sock_fd = -1;
    return -1;
  }

  /* Post-bind identity check: the path must now be the socket just
   * bound, not something swapped in during the lstat/unlink/bind
   * window. lstat() (not stat()) so a symlink swapped in at the last
   * moment is seen as a symlink rather than followed to its target. */
  if (lstat(control_sock_path, &st) != 0 || !S_ISSOCK(st.st_mode)) {
    fprintf(stderr,
            "avd: control socket path \"%s\" is not a socket after bind - refusing to serve it\n",
            control_sock_path);
    close(control_sock_fd);
    control_sock_fd = -1;
    return -1;
  }

  /* World-writable-connect, not world-writable-privileged: every verb
   * that mutates state is separately gated by the SO_PEERCRED check in
   * control_conn_main()/handle_control_line() above, so this mode is
   * what actually lets an unprivileged GUI process reach the read-only
   * verbs at all - same "gate specific commands, not the whole
   * channel" pattern as GENL_ADMIN_PERM in av/netlink_chan.c.
   *
   * Path-based chmod() is the only primitive that works here:
   * fchmod() on an AF_UNIX socket fd returns 0 but silently leaves the
   * mode unchanged (verified empirically), so "fixing" this to fchmod
   * would quietly ship a 0755 socket and lock the GUI out. The
   * check-then-chmod TOCTOU this implies (swap between the post-bind
   * lstat() above and this chmod, redirecting a root chmod onto an
   * attacker target) is closed by the parent-trust gate in
   * ensure_parent_dir(): nobody unprivileged can modify the parent,
   * so there is no one left who could stage the swap. The re-verify
   * below is the backstop - if the path is not our 0666 socket after
   * chmod, refuse to serve it rather than listen on a compromised
   * path. On mismatch nothing is unlinked: the path may now name
   * someone else's entry, and deleting that would be its own
   * vulnerability. */
  if (chmod(control_sock_path, 0666) != 0) {
    fprintf(stderr,
            "avd: chmod of control socket \"%s\" failed: %s - unprivileged "
            "clients (e.g. the GUI) may not be able to connect\n",
            control_sock_path, strerror(errno));
    close(control_sock_fd);
    control_sock_fd = -1;
    return -1;
  }
  if (lstat(control_sock_path, &st) != 0 || !S_ISSOCK(st.st_mode) ||
      (st.st_mode & 0777) != 0666) {
    fprintf(stderr,
            "avd: control socket path \"%s\" is not our 0666 socket after chmod - refusing to serve it\n",
            control_sock_path);
    close(control_sock_fd);
    control_sock_fd = -1;
    return -1;
  }

  if (listen(control_sock_fd, 16) != 0) {
    fprintf(stderr, "avd: control socket listen() failed: %s\n",
            strerror(errno));
    close(control_sock_fd);
    control_sock_fd = -1;
    unlink(control_sock_path);
    return -1;
  }

  return 0;
}

/* Accept loop - one thread, spawns a short-lived detached thread per
 * connection (control_conn_main() above) since each connection handles
 * exactly one command and then closes; a full worker-pool-plus-queue
 * like the scan path's is unwarranted here; these connections are rare
 * (interactive avctl/GUI use, not a hot path) and each one is brief. */
static void *control_accept_main(void *arg) {
  (void)arg;

  while (running) {
    struct control_conn_ctx *ctx;
    pthread_t tid;
    uid_t peer_uid = (uid_t)-1;
    bool have_uid;
    bool slot_reserved;
    int cfd = accept(control_sock_fd, NULL, NULL);

    if (cfd < 0) {
      if (errno == EINTR)
        continue;
      if (!running) /* expected - see main()'s shutdown sequence, which
                    * closes control_sock_fd to unblock this accept() */
        break;
      fprintf(stderr, "avd: control accept() failed: %s\n", strerror(errno));
      continue;
    }

    /* Resolved here, before the slot check, so AVD_CONTROL_MAX_CONNS_PER_UID
     * can be enforced alongside the global cap below - see
     * control_conn_main()'s comment for why this is the connection's one
     * SO_PEERCRED call rather than a second one there. have_uid false
     * (should not happen for a genuine AF_UNIX peer) means this
     * connection is exempt from the per-uid cap but still counts toward
     * the global one. */
    {
      struct ucred cred = {.pid = 0, .uid = (uid_t)-1, .gid = (gid_t)-1};
      socklen_t cred_len = sizeof(cred);

      have_uid = (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0);
      if (have_uid)
        peer_uid = cred.uid;
    }

    pthread_mutex_lock(&control_conn_count_lock);
    slot_reserved = control_conn_count < AVD_CONTROL_MAX_CONNS &&
                    (!have_uid || uid_conn_reserve(peer_uid));
    if (slot_reserved)
      control_conn_count++;
    pthread_mutex_unlock(&control_conn_count_lock);

    if (!slot_reserved) {
      /* Reject outright rather than queueing - see
       * AVD_CONTROL_MAX_CONNS's/AVD_CONTROL_MAX_CONNS_PER_UID's
       * comments. A real client (avctl/GUI) gets a clear error and can
       * just retry shortly; a client trying to exhaust connections gets
       * nothing to hold onto. */
      send_err(cfd, "too many concurrent control connections - try again shortly");
      close(cfd);
      continue;
    }

    ctx = malloc(sizeof(*ctx));
    if (!ctx) {
      close(cfd);
      control_conn_release_slot(peer_uid, have_uid);
      continue;
    }
    ctx->fd = cfd;
    ctx->uid = peer_uid;
    ctx->have_uid = have_uid;

    if (pthread_create(&tid, NULL, control_conn_main, ctx) != 0) {
      close(cfd);
      free(ctx);
      control_conn_release_slot(peer_uid, have_uid);
      continue;
    }
    pthread_detach(tid);
  }

  return NULL;
}

/* Reads `env_name` as a runtime override for one of avd_scan_threads/
 * avd_scan_queue_max, validates it, and returns the value to use.
 * Rejects (falls back to `default_val`, with a loud warning) rather
 * than silently clamping an out-of-range or malformed value into
 * range - same "reject, don't quietly reinterpret" stance avctl's
 * check_field_len()/check_algo() take on oversized/malformed CLI
 * input, for the same reason: a silently-clamped value would leave an
 * operator who typo'd or miscalculated their own config believing
 * it took effect as written. Unset is the normal case (not a
 * warning) and just returns `default_val`. */
static int parse_tunable_env(const char *env_name, int default_val,
                             int min_val, int max_val) {
  const char *val = getenv(env_name);
  char *end;
  long parsed;

  if (!val || val[0] == '\0')
    return default_val;

  errno = 0;
  parsed = strtol(val, &end, 10);
  if (errno != 0 || end == val || *end != '\0' || parsed < min_val ||
      parsed > max_val) {
    fprintf(stderr,
            "avd: %s=\"%s\" is not a valid integer in [%d, %d] - using "
            "default %d\n",
            env_name, val, min_val, max_val, default_val);
    return default_val;
  }

  return (int)parsed;
}

int main(int argc, char **argv) {
  const char *rules_dir = DEFAULT_RULES_DIR;
  const char *corpus_file = DEFAULT_CORPUS_FILE;
  const char *tlsh_corpus_file = DEFAULT_TLSH_CORPUS_FILE;

  if (argc > 1)
    rules_dir = argv[1];
  else if (getenv("AVD_RULES_DIR"))
    rules_dir = getenv("AVD_RULES_DIR");

  if (argc > 2)
    corpus_file = argv[2];
  else if (getenv("AVD_CORPUS_FILE"))
    corpus_file = getenv("AVD_CORPUS_FILE");

  if (argc > 3)
    quarantine_dir = argv[3];
  else if (getenv("AVD_QUARANTINE_DIR"))
    quarantine_dir = getenv("AVD_QUARANTINE_DIR");

  if (argc > 4)
    tlsh_corpus_file = argv[4];
  else if (getenv("AVD_TLSH_CORPUS_FILE"))
    tlsh_corpus_file = getenv("AVD_TLSH_CORPUS_FILE");

  if (argc > 5)
    control_sock_path = argv[5];
  else if (getenv("AVD_SOCK_PATH"))
    control_sock_path = getenv("AVD_SOCK_PATH");

  /* Fail closed on relative/empty daemon paths: both are argv/env
   * controlled, and a relative quarantine/socket path would silently
   * resolve against whatever cwd avd was started from - quarantine
   * writes or the world-visible control socket landing somewhere the
   * operator didn't mean. Absolute-path-only, same stance as
   * start_control_socket()'s own check (which re-checks the socket
   * path) and cmd_scan()'s absolute-path requirement. Deliberately no
   * expected-prefix allowlist (e.g. quarantine-must-be-under-/var/lib):
   * argv/env overrides legitimately point outside the production
   * prefixes - the test suite's throwaway dirs live under /tmp - so
   * the trusted-directory gate (ownership + no unprivileged write in
   * ensure_quarantine_dir()/ensure_parent_dir()) is what constrains
   * attacker influence instead of a prefix list that would break those
   * supported overrides. */
  if (!quarantine_dir[0] || quarantine_dir[0] != '/') {
    fprintf(stderr,
            "avd: quarantine directory must be an absolute path, got \"%s\"\n",
            quarantine_dir);
    return 1;
  }
  if (!control_sock_path[0] || control_sock_path[0] != '/') {
    fprintf(stderr,
            "avd: control socket path must be an absolute path, got \"%s\"\n",
            control_sock_path);
    return 1;
  }

  /* Env vars only, no positional argv slot - unlike rules_dir/
   * corpus_file/etc. above, these two aren't paths a packaging script
   * would want to override positionally, and adding a 6th/7th
   * positional argument here would be a much easier compatibility
   * break for existing callers (systemd unit, scripts) to trip over
   * than an opt-in env var. */
  avd_scan_threads = parse_tunable_env("AVD_SCAN_THREADS",
                                       AVD_SCAN_THREADS_DEFAULT,
                                       AVD_SCAN_THREADS_MIN,
                                       AVD_SCAN_THREADS_MAX);
  avd_scan_queue_max = parse_tunable_env("AVD_SCAN_QUEUE_MAX",
                                         AVD_SCAN_QUEUE_MAX_DEFAULT,
                                         AVD_SCAN_QUEUE_MIN,
                                         AVD_SCAN_QUEUE_MAX_MAX);

  printf("avd: quarantine directory: %s\n", quarantine_dir);
  printf("avd: control socket: %s\n", control_sock_path);

  start_time = time(NULL);

  /* sigaction(), not signal(): signal()'s semantics vary across libc
   * versions (restart vs EINTR, handler persistence), while sigaction()
   * pins exactly what we need - persistent handler, no SA_RESTART so a
   * blocking accept()/recv() EINTRs out promptly and the shutdown path
   * observes `running == 0` instead of hanging past it. */
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) != 0 ||
        sigaction(SIGTERM, &sa, NULL) != 0) {
      fprintf(stderr, "avd: failed to install SIGINT/SIGTERM handler: %s\n",
              strerror(errno));
      return 1;
    }
  }
  /* Route SIGINT/SIGTERM to the main thread's nl_recvmsgs_default()
   * loop below. All threads inherit their creator's signal mask, so a
   * process-directed SIGINT/SIGTERM arriving with the mask unblocked
   * could run handle_sigint() on a worker or control thread instead:
   * `running` would go to 0 there while the main thread stayed blocked
   * in nl_recvmsgs_default() with nothing to EINTR it out, hanging
   * shutdown. Blocking both signals here (before any pthread_create())
   * makes every subsequently spawned thread inherit them blocked; the
   * main thread unblocks them again just before entering the receive
   * loop, so termination is always delivered to the one thread whose
   * blocking call EINTRs out (sa_flags = 0, no SA_RESTART) and drives
   * the shutdown sequence. */
  {
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &block, NULL) != 0) {
      fprintf(stderr, "avd: failed to block SIGINT/SIGTERM: %s\n",
              strerror(errno));
      return 1;
    }
  }
  /* Without this, any write()/send() into a control-socket connection
   * whose peer already closed (a killed avctl, the GUI navigating
   * away mid-request, a network hiccup on a remote mount of the
   * socket path, etc.) raises SIGPIPE - whose default disposition is
   * to terminate the WHOLE PROCESS, not just that connection's
   * thread. Found by testing (a harness closing many client fds while
   * avd was still mid-response killed the entire daemon, not just
   * those connections). write_all()/send_err() already treat a
   * failed write as "give up on this one response" (they check the
   * return value and just stop, no retry-forever loop), so ignoring
   * SIGPIPE here is sufficient - write()/send() then simply return -1
   * with errno EPIPE instead of raising the signal, and existing error
   * handling takes it from there. */
  {
    struct sigaction sa_ign;
    memset(&sa_ign, 0, sizeof(sa_ign));
    sa_ign.sa_handler = SIG_IGN;
    sigemptyset(&sa_ign.sa_mask);
    sa_ign.sa_flags = 0;
    sigaction(SIGPIPE, &sa_ign, NULL);
  }

  if (av_tlsh_selftest() != 0) {
    fprintf(stderr, "avd: TLSH self-test failed - aborting\n");
    return 1;
  }

  if (load_rules(rules_dir) != 0) {
    fprintf(stderr, "avd: failed to initialize YARA - aborting\n");
    return 1;
  }

  if (load_fuzzy_corpus(corpus_file) != 0) {
    fprintf(stderr, "avd: failed to initialize fuzzy corpus - aborting\n");
    return 1;
  }

  if (load_tlsh_corpus(tlsh_corpus_file) != 0) {
    fprintf(stderr, "avd: failed to initialize TLSH corpus - aborting\n");
    return 1;
  }

  sock = nl_socket_alloc();
  if (!sock) {
    fprintf(stderr, "avd: nl_socket_alloc failed\n");
    return 1;
  }

  /* We receive kernel-INITIATED messages (SCAN_REQUEST), which don't
   * carry a sequence number libnl is expecting a reply to - without
   * this, libnl silently drops them as "sequence mismatch". */
  nl_socket_disable_seq_check(sock);
  nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, msg_handler, NULL);

  if (genl_connect(sock) < 0) {
    fprintf(stderr, "avd: genl_connect failed - is the av module loaded?\n");
    nl_socket_free(sock);
    return 1;
  }

  family_id = genl_ctrl_resolve(sock, AV_GENL_FAMILY_NAME);
  if (family_id < 0) {
    fprintf(stderr,
            "avd: could not resolve family \"%s\" - "
            "is the av module loaded? (sudo insmod av/av.ko)\n",
            AV_GENL_FAMILY_NAME);
    nl_socket_free(sock);
    return 1;
  }

  if (register_with_kernel() < 0) {
    fprintf(stderr, "avd: failed to register with kernel module\n");
    nl_socket_free(sock);
    return 1;
  }

  printf("avd: registered with kernel module (family id %d), listening...\n",
         family_id);

  {
    /* Heap-allocated, not a stack VLA/fixed array - avd_scan_threads is
     * an operator-tunable runtime value (see parse_tunable_env()), and
     * this is the one place its size actually drives an allocation. */
    pthread_t *workers = calloc((size_t)avd_scan_threads, sizeof(*workers));
    pthread_t control_thread;
    bool control_started;
    int i, spawned = 0;

    if (!workers) {
      fprintf(stderr, "avd: could not allocate %d scan worker slots\n",
              avd_scan_threads);
      nl_socket_free(sock);
      return 1;
    }

    for (i = 0; i < avd_scan_threads; i++) {
      if (pthread_create(&workers[i], NULL, scan_worker_main, NULL) != 0) {
        fprintf(stderr, "avd: pthread_create failed for worker %d: %s\n", i,
                strerror(errno));
        break;
      }
      spawned++;
    }
    if (spawned == 0) {
      fprintf(stderr, "avd: no scan workers could be started - aborting\n");
      free(workers);
      nl_socket_free(sock);
      return 1;
    }
    if (spawned < avd_scan_threads)
      fprintf(stderr,
              "avd: only %d/%d scan workers started - continuing with "
              "reduced concurrency\n",
              spawned, avd_scan_threads);

    /* Not fatal if this fails (permissions, read-only /run, etc.) -
     * the daemon's actual job (kernel-triggered scanning) doesn't
     * depend on it, so avd degrades to "no GUI/avctl management path"
     * rather than refusing to start entirely. */
    control_started = (start_control_socket() == 0);
    if (control_started) {
      if (pthread_create(&control_thread, NULL, control_accept_main, NULL) !=
          0) {
        fprintf(stderr, "avd: pthread_create failed for control socket: %s\n",
                strerror(errno));
        close(control_sock_fd);
        control_sock_fd = -1;
        unlink(control_sock_path);
        control_started = false;
      }
    } else {
      fprintf(stderr,
              "avd: control socket unavailable - avctl/GUI management "
              "commands will not work, kernel-triggered scanning is "
              "unaffected\n");
    }

    /* Main thread only: unblock the termination signals blocked above
     * so they are delivered here - the one thread parked in the
     * EINTR-able nl_recvmsgs_default() loop - rather than on a worker
     * or control thread that could never wake that loop up. Workers and
     * the control accept thread (plus every per-connection thread it
     * spawns) keep the inherited blocked mask for the life of the
     * process. On the unlikely pthread_sigmask() failure, abort startup
     * rather than run with undeliverable termination signals. */
    {
      sigset_t unblock;
      sigemptyset(&unblock);
      sigaddset(&unblock, SIGINT);
      sigaddset(&unblock, SIGTERM);
      if (pthread_sigmask(SIG_UNBLOCK, &unblock, NULL) != 0) {
        int unblock_err = errno;
        fprintf(stderr, "avd: failed to unblock SIGINT/SIGTERM in main: %s\n",
                strerror(unblock_err));
        pthread_mutex_lock(&queue_lock);
        shutting_down = true;
        pthread_cond_broadcast(&queue_not_empty);
        pthread_cond_broadcast(&queue_not_full);
        pthread_mutex_unlock(&queue_lock);
        for (i = 0; i < spawned; i++)
          pthread_join(workers[i], NULL);
        if (control_started) {
          /* Same self-connect wake-up as the normal shutdown path
           * below: joining the accept thread without it hangs. */
          int wake_fd = socket(AF_UNIX, SOCK_STREAM, 0);

          if (wake_fd >= 0) {
            struct sockaddr_un wake_addr;

            memset(&wake_addr, 0, sizeof(wake_addr));
            wake_addr.sun_family = AF_UNIX;
            snprintf(wake_addr.sun_path, sizeof(wake_addr.sun_path), "%s",
                     control_sock_path);
            connect(wake_fd, (struct sockaddr *)&wake_addr,
                    sizeof(wake_addr));
            close(wake_fd);
          }
          pthread_join(control_thread, NULL);
          close(control_sock_fd);
          control_sock_fd = -1;
          unlink(control_sock_path);
        }
        free(workers);
        nl_socket_free(sock);
        return 1;
      }
    }

    while (running) {
      int ret = nl_recvmsgs_default(sock);
      if (ret < 0 && ret != -NLE_INTR) {
        fprintf(stderr, "avd: nl_recvmsgs_default error: %s\n",
                nl_geterror(ret));
        break;
      }
    }

    printf("avd: shutting down, draining %zu queued scan(s)...\n", queue_len);
    pthread_mutex_lock(&queue_lock);
    shutting_down = true;
    pthread_cond_broadcast(&queue_not_empty);
    pthread_cond_broadcast(&queue_not_full);
    pthread_mutex_unlock(&queue_lock);

    for (i = 0; i < spawned; i++)
      pthread_join(workers[i], NULL);

    if (control_started) {
      /* Closing control_sock_fd out from under control_accept_main()'s
       * blocked accept() call does NOT reliably unblock it - verified
       * empirically while testing this (see
       * tests/test_avd_socket.sh's comment): unlike a blocking read()
       * on a pipe, another thread closing an fd out from under a
       * thread already parked in accept() on it is not guaranteed by
       * POSIX to interrupt that call, and in practice it just hangs.
       * The reliable fix is the classic self-pipe trick adapted to a
       * listening socket: connect to our own control socket to hand
       * accept() a real (if pointless) connection, which wakes the
       * loop up so it can observe `running == 0` and exit on its own.
       * That dummy connection gets a short-lived handler thread
       * spawned for it like any other (control_conn_main() below,
       * reading an empty line from a peer that's already gone -
       * harmless), which is fine since this only happens once, at
       * shutdown. */
      {
        int wake_fd = socket(AF_UNIX, SOCK_STREAM, 0);

        if (wake_fd >= 0) {
          struct sockaddr_un wake_addr;

          memset(&wake_addr, 0, sizeof(wake_addr));
          wake_addr.sun_family = AF_UNIX;
          snprintf(wake_addr.sun_path, sizeof(wake_addr.sun_path), "%s",
                   control_sock_path);
          connect(wake_fd, (struct sockaddr *)&wake_addr, sizeof(wake_addr));
          close(wake_fd);
        }
      }
      pthread_join(control_thread, NULL);
      close(control_sock_fd);
      control_sock_fd = -1;
      unlink(control_sock_path);
    }
    free(workers);
  }

  nl_socket_free(sock);
  if (compiled_rules)
    yr_rules_destroy(compiled_rules);
  yr_finalize();
  free(fuzzy_corpus);
  free(tlsh_corpus);
  return 0;
}
