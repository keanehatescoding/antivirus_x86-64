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
# libFuzzer dependency). The harness includes the production headers
# directly (control_parse.h, netlink_proto.h), so it exercises the
# exact code the daemon/kernel enforce - a regression fails here
# instead of passing against a stale copy.
#
# Pure userspace, no kernel module or root needed - the harness
# compiles only standard headers (no libnl/yara), same stance as
# test_sha256.sh. Safe to run standalone:
#   tests/test_parser_robustness.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_parser.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
# False positive: cleanup() IS invoked via `trap` on the next line -
# same idiom as test_sha256.sh / test_corpus_format.sh.
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

cat > "$BUILD_DIR/harness.c" <<'EOF'
/* Parser-robustness harness for issue #105 - built and run by
 * tests/test_parser_robustness.sh only, not part of the shipped avd
 * binary. Includes the production headers directly
 * (userspace/avd/control_parse.h, av/netlink_proto.h), so every CHECK
 * below exercises the exact code the daemon/kernel enforce - a
 * regression in either file fails here instead of passing against a
 * stale copy. */
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "control_parse.h"
#include "netlink_proto.h"

static int PASS, FAIL;

#define CHECK(cond, label) do { \
    if (cond) { printf("  PASS: %s\n", label); PASS++; } \
    else { printf("  FAIL: %s\n", label); FAIL++; } \
} while (0)

static int is_status(const char *line) { return !strcmp(line, "STATUS"); }
static int is_quarantine_list(const char *line) { return !strcmp(line, "QUARANTINE LIST"); }
static int is_verdicts(const char *line) { return PREFIX_MATCH(line, "VERDICTS RECENT "); }
static int is_restore(const char *line) { return PREFIX_MATCH(line, "QUARANTINE RESTORE "); }
static int is_delete(const char *line) { return PREFIX_MATCH(line, "QUARANTINE DELETE "); }
static int is_scan(const char *line) { return PREFIX_MATCH(line, "SCAN "); }

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

    /* 2. VERDICTS RECENT count: strict, no trailing garbage.
     * parse_verdicts_count() is the production helper avd.c calls. */
    CHECK(parse_verdicts_count("5", &n) == 1 && n == 5, "verdicts count accepts plain number");
    CHECK(parse_verdicts_count("0", &n) == 1 && n == 0, "verdicts count accepts zero");
    CHECK(parse_verdicts_count("", NULL) == 0, "verdicts count rejects empty");
    CHECK(parse_verdicts_count("abc", NULL) == 0, "verdicts count rejects non-numeric");
    CHECK(parse_verdicts_count("5abc", NULL) == 0, "verdicts count rejects trailing garbage");
    CHECK(parse_verdicts_count("5 ", NULL) == 0, "verdicts count rejects trailing space");
    CHECK(parse_verdicts_count("12x34", NULL) == 0, "verdicts count rejects mid-string garbage");

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

    /* 4. netlink verdict: closed value set.
     * av_verdict_valid() is the production helper netlink_chan.c calls. */
    CHECK(av_verdict_valid(0) == 1, "netlink verdict accepts CLEAN (0)");
    CHECK(av_verdict_valid(1) == 1, "netlink verdict accepts MALICIOUS (1)");
    CHECK(av_verdict_valid(2) == 0, "netlink verdict rejects 2");
    CHECK(av_verdict_valid(42) == 0, "netlink verdict rejects 42");
    CHECK(av_verdict_valid(255) == 0, "netlink verdict rejects 255");

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
        -I "$REPO_ROOT/userspace/avd" -I "$REPO_ROOT/av" \
        "$BUILD_DIR/harness.c" -o "$BUILD_DIR/harness" 2>"$BUILD_DIR/build.log"; then
    echo "FAIL: could not build the parser-robustness harness - see build log:"
    cat "$BUILD_DIR/build.log"
    exit 1
fi

"$BUILD_DIR/harness"
exit $?
