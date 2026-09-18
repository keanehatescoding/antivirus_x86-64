/*
 * control_parse.h - shared control-socket parsing helpers for avd and its
 * adversarial test (tests/test_parser_robustness.sh, issue #105).
 *
 * Single source of truth: userspace/avd/avd.c includes this and calls
 * these helpers on its live request path, and the test harness includes
 * this same file directly - so the suite exercises the production
 * implementation, not an independent copy that could drift silently.
 *
 * Dependency-free by design (standard headers only, no libnl/yara) so
 * the rootless test can compile it standalone with plain `cc`.
 */

#ifndef AV_CONTROL_PARSE_H
#define AV_CONTROL_PARSE_H

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Bounds how long a single control connection may sit idle waiting for
 * its request line - without this, a client that connects and never
 * sends a newline (or a slow/hostile one trickling bytes) would block
 * that connection's thread, and therefore one of AVD_CONTROL_MAX_CONNS
 * slots, indefinitely. Lives here (not in avd.c) because read_line()
 * below enforces it. */
#define AVD_CONTROL_RECV_TIMEOUT_SECS 5

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

/* id must be a bare basename (no '/', not "." or ".."), matching what
 * cmd_quarantine_list() returns - reconstructed into a path below via
 * plain snprintf(), so this is the only thing standing between a
 * hostile QUARANTINE RESTORE/DELETE argument and a path-traversal
 * escape out of quarantine_dir. */
static inline int quarantine_id_valid(const char *id) {
    if (!id[0] || strchr(id, '/'))
        return 0;
    if (!strcmp(id, ".") || !strcmp(id, ".."))
        return 0;
    if (strlen(id) >= (size_t)(PATH_MAX - 32)) /* room for the .quarantined.meta suffix */
        return 0;
    return 1;
}

/*
 * Strict VERDICTS RECENT count parsing for handle_control_line():
 * strtoul() + (end == arg || *end != '\0') rejection of empty,
 * non-numeric, and trailing-garbage inputs. Returns 1 with *nout set
 * when the input would be accepted, 0 when handle_control_line()
 * must reply "malformed VERDICTS RECENT".
 */
static inline int parse_verdicts_count(const char *arg, unsigned long *nout) {
    char *end;
    unsigned long n = strtoul(arg, &end, 10);

    if (end == arg || *end != '\0')
        return 0;
    if (nout)
        *nout = n;
    return 1;
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
 * comment in avd.c).
 *
 * Enforces its own ABSOLUTE deadline (AVD_CONTROL_RECV_TIMEOUT_SECS
 * from the first call), on top of whatever SO_RCVTIMEO the caller may
 * have set on `fd` - SO_RCVTIMEO alone only bounds each individual
 * read() call, so a client trickling one byte just under that
 * interval at a time would never trip any single call's timeout and
 * could hold a connection (and its AVD_CONTROL_MAX_CONNS slot) open
 * for up to AVD_SOCK_LINE_MAX reads' worth of that interval -
 * effectively unbounded in practice.
 */
static inline ssize_t read_line(int fd, char *buf, size_t bufsz) {
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

#endif /* AV_CONTROL_PARSE_H */
