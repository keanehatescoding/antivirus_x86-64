// SPDX-License-Identifier: GPL-2.0
/* Exec target for fanotify_spike.c.
 *
 * Built three times from this one file with different MARKER_CHAR, so
 * the copies have distinct inodes AND are distinguishable by what they
 * report at startup:
 *
 *   target_orig     'A'  the marked file - the one the listener holds
 *   target_decoy    'B'  renamed over target_orig's path mid-event, to
 *                        show the held fd is not the path (phase 5)
 *   target_unmarked 'U'  never marked - selectivity control (phase 4)
 *
 * Reports TWO things over MARKER_FD, neither of which the exit status
 * can carry: which image ran, and - the load-bearing one - the moment
 * its first instruction ran, on CLOCK_MONOTONIC.
 *
 * The timestamp has to be taken HERE rather than when the listener reads
 * this pipe. The listener stalls deliberately before responding, so its
 * own read time says when it got round to looking, not when the exec was
 * released. Measuring that instead made the notification-class control
 * report a 300 ms "delay" that was purely the listener's own sleep.
 *
 * The write is best-effort: fd 3 is only open when fanotify_spike.c
 * spawned us, and run_spike.sh's preflight runs this binary by hand
 * (to prove the work directory is executable at all) with no fd 3. That
 * run must still exit TARGET_OK. */
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef MARKER_CHAR
#define MARKER_CHAR 'A'
#endif

/* Must match fanotify_spike.c: 8 bytes of CLOCK_MONOTONIC nanoseconds in
 * native byte order, then the marker byte. Written as a flat buffer
 * rather than a struct so no padding can creep between the two fields,
 * and in one write() - 9 bytes is far below PIPE_BUF, so the reader
 * cannot observe a partial report. */
#define MARKER_FD 3
#define TARGET_REPORT_LEN 9
#define TARGET_OK 7

int main(void)
{
	unsigned char rep[TARGET_REPORT_LEN];
	struct timespec ts;
	uint64_t ns;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;

	memcpy(rep, &ns, sizeof(ns));
	rep[sizeof(ns)] = (unsigned char)MARKER_CHAR;

	(void)!write(MARKER_FD, rep, sizeof(rep));
	return TARGET_OK;
}
