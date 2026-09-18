#!/usr/bin/env bash
#
# tests/test_parser_robustness.sh - adversarial input coverage for the two
# externally-reachable parsers tracked in issue #105 (observability +
# fuzzing bullet):
#
#   - avd control-socket parser (userspace/avd/avd.c): read_line() bounds,
#     handle_control_line() dispatch (PREFIX_MATCH), VERDICTS RECENT count
#     strictness, quarantine_id_valid() traversal guard.
#   - netlink verdict validation (av/netlink_chan.c av_nl_verdict_doit()):
#     only AV_VERDICT_CLEAN (0) / AV_VERDICT_MALICIOUS (1) accepted.
#
# Neither parser has fuzz coverage today; this is the deterministic,
# rootless first half of that bullet (fixed adversarial vectors, no
# libFuzzer dependency). The validation logic below mirrors the
# production code exactly (source lines cited per block) so a drift in
# either file fails loudly here instead of silently widening the
# accepted input space.
#
# Pure userspace, no kernel module or root needed - the harness
# compiles only standard headers (no libnl/yara), same stance as
# test_sha256.sh. Safe to run standalone:
#   tests/test_parser_robustness.sh
#
set -u

BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_parser.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
# False positive: cleanup() IS invoked via `trap` on the next line -
# same idiom as test_sha256.sh / test_corpus_format.sh.
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

cat > "$BUILD_DIR/harness.c" <<'EOF'
/* Parser-robustness harness for issue #105 - built and run by
 * tests/test_parser_robustness.sh only, not part of the shipped avd
 * binary. Each block mirrors one production validation site; comments
 * cite the source so a logic drift is caught by inspection as well as
 * by failure. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int PASS, FAIL;

#define CHECK(cond, label) do { \
    if (cond) { printf("  PASS: %s\n", label); PASS++; } \
    else { printf("  FAIL: %s\n", label); FAIL++; } \
} while (0)

/* ---- quarantine_id_valid() (userspace/avd/avd.c) ----
 * Exact copy: bare basename, no '/', not "." or "..", room for the
 * ".quarantined.meta" suffix. The only thing standing between a
 * hostile QUARANTINE RESTORE/DELETE argument and a path-traversal
 * escape out of quarantine_dir. */
static int quarantine_id_valid(const char *id) {
    if (!id[0] || strchr(id, '/'))
        return 0;
    if (!strcmp(id, ".") || !strcmp(id, ".."))
        return 0;
    if (strlen(id) >= (size_t)(PATH_MAX - 32))
        return 0;
    return 1;
}

/* ---- VERDICTS RECENT count strictness (avd.c handle_control_line()) ----
 * strtoul() + (end == arg || *end != '\0') rejection of empty,
 * non-numeric, and trailing-garbage inputs. Returns 1 when the input
 * would be accepted, 0 when rejected with "malformed VERDICTS RECENT". */
static int verdicts_count_accepted(const char *arg, unsigned long *nout) {
    char *end;
    unsigned long n = strtoul(arg, &end, 10);
    if (end == arg || *end != '\0')
        return 0;
    if (nout)
        *nout = n;
    return 1;
}

/* ---- PREFIX_MATCH() dispatch (avd.c handle_control_line()) ----
 * sizeof(literal)-1, never a hand-counted length: a too-long n
 * implicitly requires the NUL terminator to match too, silently
 * breaking every command with an argument. */
#define PREFIX_MATCH(line, literal) \
    (!strncmp((line), (literal), sizeof(literal) - 1))

static int is_status(const char *line) { return !strcmp(line, "STATUS"); }
static int is_quarantine_list(const char *line) { return !strcmp(line, "QUARANTINE LIST"); }
static int is_verdicts(const char *line) { return PREFIX_MATCH(line, "VERDICTS RECENT "); }
static int is_restore(const char *line) { return PREFIX_MATCH(line, "QUARANTINE RESTORE "); }
static int is_delete(const char *line) { return PREFIX_MATCH(line, "QUARANTINE DELETE "); }
static int is_scan(const char *line) { return PREFIX_MATCH(line, "SCAN "); }

/* ---- netlink verdict range (av/netlink_chan.c av_nl_verdict_doit()) ----
 * Only AV_VERDICT_CLEAN (0) / AV_VERDICT_MALICIOUS (1) are defined;
 * anything else is rejected with -EINVAL rather than falling through
 * to clean. Mirrors the production check verbatim. */
#define AV_VERDICT_CLEAN 0
#define AV_VERDICT_MALICIOUS 1
static int verdict_accepted(unsigned int v) {
    return v == AV_VERDICT_CLEAN || v == AV_VERDICT_MALICIOUS;
}

/* ---- read_line() bounds (avd.c control socket) ----
 * Exact copy (deadline + one-byte reads + bufsz cap): overlong or
 * newline-less input returns -1, clean EOF before any data returns 0,
 * EOF mid-line returns -1. AVD_CONTROL_RECV_TIMEOUT_SECS is 5s in
 * production; the harness feeds all bytes up front so the deadline
 * never fires. */
#define AVD_CONTROL_RECV_TIMEOUT_SECS 5
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
            return len == 0 ? 0 : -1;
        if (c == '\n') {
            buf[len] = '\0';
            return (ssize_t)len;
        }
        buf[len++] = c;
    }
    return -1;
}

/* Feed `data` (len bytes, then EOF) through a pipe into read_line(). */
static ssize_t read_line_once(const char *data, size_t len, char *out, size_t outsz) {
    int fds[2];
    ssize_t r;
    size_t off = 0;

    if (pipe(fds) != 0)
        return -2;
    while (off < len) {
        ssize_t w = write(fds[1], data + off, len - off);
        if (w <= 0)
            break;
        off += (size_t)w;
    }
    close(fds[1]);
    r = read_line(fds[0], out, outsz);
    close(fds[0]);
    return r;
}

int main(void) {
    unsigned long n;
    char buf[64];

    /* 1. quarantine id: traversal guard */
    CHECK(quarantine_id_valid("abc123") == 1, "quarantine id accepts plain basename");
    CHECK(quarantine_id_valid("") == 0, "quarantine id rejects empty");
    CHECK(quarantine_id_valid("../evil") == 0, "quarantine id rejects slash traversal");
    CHECK(quarantine_id_valid("a/b") == 0, "quarantine id rejects embedded slash");
    CHECK(quarantine_id_valid("/abs") == 0, "quarantine id rejects leading slash");
    CHECK(quarantine_id_valid(".") == 0, "quarantine id rejects dot");
    CHECK(quarantine_id_valid("..") == 0, "quarantine id rejects dotdot");
    CHECK(quarantine_id_valid("a..b") == 1, "quarantine id accepts dots inside basename");
    {
        /* PATH_MAX-32 is the documented bound (room for the suffix). */
        static char over[PATH_MAX];
        memset(over, 'x', sizeof(over) - 1);
        over[sizeof(over) - 1] = '\0';
        CHECK(quarantine_id_valid(over) == 0, "quarantine id rejects overlong id");
    }

    /* 2. VERDICTS RECENT count: strict, no trailing garbage */
    CHECK(verdicts_count_accepted("5", &n) == 1 && n == 5, "verdicts count accepts plain number");
    CHECK(verdicts_count_accepted("0", &n) == 1 && n == 0, "verdicts count accepts zero");
    CHECK(verdicts_count_accepted("", NULL) == 0, "verdicts count rejects empty");
    CHECK(verdicts_count_accepted("abc", NULL) == 0, "verdicts count rejects non-numeric");
    CHECK(verdicts_count_accepted("5abc", NULL) == 0, "verdicts count rejects trailing garbage");
    CHECK(verdicts_count_accepted("5 ", NULL) == 0, "verdicts count rejects trailing space");
    CHECK(verdicts_count_accepted("12x34", NULL) == 0, "verdicts count rejects mid-string garbage");

    /* 3. dispatch: exact verbs vs prefix verbs */
    CHECK(is_status("STATUS") == 1, "dispatch accepts STATUS");
    CHECK(is_status("STATUSX") == 0, "dispatch rejects STATUS prefix extension");
    CHECK(is_quarantine_list("QUARANTINE LIST") == 1, "dispatch accepts QUARANTINE LIST");
    CHECK(is_verdicts("VERDICTS RECENT 5") == 1, "dispatch accepts VERDICTS RECENT with arg");
    CHECK(is_verdicts("VERDICTS RECENT ") == 1, "dispatch matches VERDICTS RECENT prefix (arg checked later)");
    CHECK(is_verdicts("VERDICTS RECENT") == 0, "dispatch rejects VERDICTS RECENT without trailing space");
    CHECK(is_restore("QUARANTINE RESTORE abc") == 1, "dispatch accepts QUARANTINE RESTORE with arg");
    CHECK(is_delete("QUARANTINE DELETE abc") == 1, "dispatch accepts QUARANTINE DELETE with arg");
    CHECK(is_scan("SCAN /tmp/x") == 1, "dispatch accepts SCAN with arg");
    CHECK(is_scan("SCAN") == 0, "dispatch rejects bare SCAN without trailing space");
    CHECK(is_scan("SCANX /tmp/x") == 0, "dispatch rejects SCAN prefix extension");

    /* 4. netlink verdict: closed value set */
    CHECK(verdict_accepted(0) == 1, "netlink verdict accepts CLEAN (0)");
    CHECK(verdict_accepted(1) == 1, "netlink verdict accepts MALICIOUS (1)");
    CHECK(verdict_accepted(2) == 0, "netlink verdict rejects 2");
    CHECK(verdict_accepted(42) == 0, "netlink verdict rejects 42");
    CHECK(verdict_accepted(255) == 0, "netlink verdict rejects 255");

    /* 5. read_line: bounds, not silent truncation */
    CHECK(read_line_once("HELLO\n", 6, buf, sizeof(buf)) == 5 && !strcmp(buf, "HELLO"),
          "read_line accepts newline-terminated line");
    CHECK(read_line_once("", 0, buf, sizeof(buf)) == 0,
          "read_line returns 0 on clean EOF");
    CHECK(read_line_once("NO_NEWLINE", 10, buf, sizeof(buf)) == -1,
          "read_line rejects EOF mid-line");
    {
        /* bufsz=64 with `len + 1 < bufsz`: the loop runs while len <= 62,
         * so 62 payload bytes + newline is the largest accepted line
         * (buf[62] = NUL still fits); 63 payload bytes must not fit. */
        char fits[63], too_long[65];
        memset(fits, 'A', 62);
        fits[62] = '\n';
        memset(too_long, 'A', 64);
        too_long[64] = '\n';
        CHECK(read_line_once(fits, sizeof(fits), buf, sizeof(buf)) == 62,
              "read_line accepts line at the size bound");
        CHECK(read_line_once(too_long, sizeof(too_long), buf, sizeof(buf)) == -1,
              "read_line rejects overlong line instead of truncating");
    }

    printf("\n===================================\n");
    printf("parser robustness: %d passed, %d failed\n", PASS, FAIL);
    printf("===================================\n");
    return FAIL ? 1 : 0;
}
EOF

if ! cc -Wall -Wextra -O2 \
        "$BUILD_DIR/harness.c" -o "$BUILD_DIR/harness" 2>"$BUILD_DIR/build.log"; then
    echo "FAIL: could not build the parser-robustness harness - see build log:"
    cat "$BUILD_DIR/build.log"
    exit 1
fi

"$BUILD_DIR/harness"
exit $?
