// SPDX-License-Identifier: GPL-2.0
/* Spike: is FAN_OPEN_EXEC_PERM the blocking verdict primitive #102 needs?
 *
 * The BPF LSM spike (spike/bpf-lsm/) settled that an LSM hook can deny an
 * exec, but also that it CANNOT park waiting for a YARA verdict from avd.
 * #102 then claims fanotify permission events are that missing primitive.
 * That claim has never been run. This runs it.
 *
 * Three things have to hold for the claim to carry the enforcement path:
 *
 *   1. The exec is really HELD - not merely observed - until userspace
 *      replies, so avd may take as long as YARA needs.
 *   2. A denial actually refuses the exec, with an errno we choose.
 *   3. The fd delivered with the event IS the image about to run, so
 *      scanning it is not racing a re-open of the path (#88).
 *
 * Every phase that asserts something is paired with a control that fails
 * if the assertion is vacuous - see README.md. The layout mirrors
 * spike/bpf-lsm/enforce_test.c, for the same reason: a check that cannot
 * fail proves nothing.
 *
 * SAFETY. Unlike the BPF LSM spike this needs no VM. Marks here are
 * FAN_MARK_ADD on individual inodes in a throwaway directory, never
 * FAN_MARK_MOUNT, so the only execs that can ever block on this listener
 * are of files this program created. A crash is survivable too: closing
 * the fanotify fd releases any pending permission event as ALLOW, and
 * the fd is closed by process exit.
 *
 * Needs CAP_SYS_ADMIN (FAN_CLASS_CONTENT).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Must match target.c. */
#define TARGET_OK 7
#define MARKER_FD 3
/* 8 bytes of CLOCK_MONOTONIC nanoseconds, then the marker byte. The
 * timestamp is the TARGET's, not ours - see target.c for why that
 * distinction is what makes phase 2's control meaningful. */
#define TARGET_REPORT_LEN 9
/* Child status when execl() itself failed. The real errno comes over a
 * separate pipe, not through the status - a denied exec and a target
 * that chose to exit(EACCES) are otherwise indistinguishable. */
#define EXEC_FAILED 127

/* How long the listener stalls before allowing, in the blocking phase.
 * Long enough to dwarf fork+exec scheduling noise, short enough that the
 * whole spike stays interactive. */
#define BLOCK_DELAY_MS 300
/* Poll slice while servicing one exec. Only bounds how often we re-check
 * for child exit; the deadline below is what actually limits a phase. */
#define POLL_SLICE_MS 100
/* Hard ceiling per exec. A phase that trips this is reported as a
 * failure rather than hanging the spike. */
#define PHASE_DEADLINE_MS 15000
/* Non-default on purpose: EPERM is what a denial returns anyway, so
 * asserting EPERM would not distinguish "FAN_DENY_ERRNO was honoured"
 * from "it was ignored". EACCES can only come from the errno we chose. */
#define DENY_ERRNO EACCES

/* Sentinel for "service the event but send no response" - the
 * notification-class control, which has no response to send.
 * FAN_ALLOW/FAN_DENY are small positive bit values, so -1 is free. */
#define NO_REPLY (-1)

#define MAX_IMAGE (4u << 20) /* targets are tiny; this is just a cap */

static char path_marked[PATH_MAX];
static char path_decoy[PATH_MAX];
static char path_unmarked[PATH_MAX];

/* Phase 5 compares three images: what the held fd yields, what the path
 * yields after the swap, and what actually ran. File-scope because the
 * event hook runs deep inside run_exec() and a spike does not need a
 * context-pointer apparatus to carry two buffers. */
static unsigned char buf_orig[MAX_IMAGE];
static size_t len_orig;
static unsigned char buf_decoy[MAX_IMAGE];
static size_t len_decoy;
static unsigned char buf_event[MAX_IMAGE];
static size_t len_event;
static unsigned char buf_path[MAX_IMAGE];
static size_t len_path;

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static double ms_since(uint64_t a, uint64_t b)
{
	return (double)((int64_t)b - (int64_t)a) / 1e6;
}

static void ms_sleep(unsigned ms)
{
	struct timespec ts = {
		.tv_sec = ms / 1000,
		.tv_nsec = (long)(ms % 1000) * 1000000L,
	};

	while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
		;
}

static ssize_t slurp_fd(int fd, unsigned char *buf, size_t max)
{
	size_t off = 0;

	/* pread, not read: the event fd's file offset is shared with
	 * whatever else holds that open file description, so a plain read
	 * would depend on an offset this program does not own. */
	while (off < max) {
		ssize_t n = pread(fd, buf + off, max - off, (off_t)off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	return (ssize_t)off;
}

static ssize_t slurp_path(const char *path, unsigned char *buf, size_t max)
{
	ssize_t n;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -1;
	n = slurp_fd(fd, buf, max);
	close(fd);
	return n;
}

struct run_opts {
	const char *path;
	int response;	     /* FAN_ALLOW / FAN_DENY(_ERRNO) / NO_REPLY */
	unsigned delay_ms;   /* stall before responding */
	int (*on_event)(int event_fd); /* inspect the held fd pre-response */
};

struct run_result {
	int events;	   /* events serviced during this exec */
	int exec_errno;	   /* 0 = exec succeeded */
	int exited_ok;	   /* target ran to completion (TARGET_OK) */
	char marker;	   /* which image ran, 0 if none did */
	int hook_failed;   /* on_event() reported a mismatch */
	int resp_errno;	   /* errno from a rejected response write, else 0 */
	int timed_out;
	uint64_t t_fork;
	uint64_t t_reply;  /* when the response was sent (or would have been) */
	uint64_t t_marker; /* when the target's first instruction RAN */
};

/* Fork a child that execs opts->path, service the resulting permission
 * event (if any) per opts, and report what happened.
 *
 * The order matters: the child's exec blocks inside the kernel until we
 * respond, so the event loop must run BEFORE any blocking waitpid().
 * Reaping first would deadlock the spike against itself. */
static int run_exec(int fanfd, const struct run_opts *o, struct run_result *r)
{
	int startp[2], errp[2];
	pid_t pid;
	int status = 0;
	int reaped = 0, start_done = 0;
	unsigned char rep[TARGET_REPORT_LEN];
	size_t rep_off = 0;
	uint64_t deadline;
	int e = 0;
	ssize_t got;

	memset(r, 0, sizeof(*r));

	if (pipe(startp) < 0)
		return -1;
	/* Both ends CLOEXEC: the child's write end closing on a SUCCESSFUL
	 * exec is exactly how the parent learns the exec succeeded. A
	 * short read means "no errno was written" means "it ran". */
	if (pipe2(errp, O_CLOEXEC) < 0) {
		close(startp[0]);
		close(startp[1]);
		return -1;
	}

	r->t_fork = now_ns();
	pid = fork();
	if (pid < 0) {
		close(startp[0]); close(startp[1]);
		close(errp[0]); close(errp[1]);
		return -1;
	}
	if (pid == 0) {
		close(startp[0]);
		close(errp[0]);
		/* BEFORE the dup2 below, not after. fanotify_init() is the
		 * first fd this process opens, so fanfd is typically 3 -
		 * which is MARKER_FD. Closing it after the dup2 closed the
		 * marker pipe instead, and every phase then reported a
		 * target that ran (exit 7) but never checked in. */
		close(fanfd);
		/* dup2 clears CLOEXEC, so the marker fd survives the exec
		 * while the errno fd does not - which is the point. */
		if (startp[1] != MARKER_FD) {
			if (dup2(startp[1], MARKER_FD) < 0)
				_exit(EXEC_FAILED);
			close(startp[1]);
		}
		execl(o->path, o->path, (char *)NULL);
		e = errno;
		(void)!write(errp[1], &e, sizeof(e));
		_exit(EXEC_FAILED);
	}

	close(startp[1]);
	close(errp[1]);

	deadline = now_ns() + (uint64_t)PHASE_DEADLINE_MS * 1000000ull;

	while (now_ns() < deadline) {
		struct pollfd pfd[2];
		int n;

		pfd[0].fd = fanfd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = start_done ? -1 : startp[0];
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;

		n = poll(pfd, 2, POLL_SLICE_MS);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (n > 0 && (pfd[1].revents & (POLLIN | POLLHUP))) {
			ssize_t k = read(startp[0], rep + rep_off,
					 sizeof(rep) - rep_off);

			if (k > 0) {
				rep_off += (size_t)k;
				if (rep_off == sizeof(rep)) {
					uint64_t ns;

					/* The target's own clock reading, not
					 * the time we happened to read this
					 * pipe - we may have been asleep. */
					memcpy(&ns, rep, sizeof(ns));
					r->t_marker = ns;
					r->marker = (char)rep[sizeof(ns)];
					start_done = 1;
				}
			} else {
				start_done = 1;
			}
		}

		if (n > 0 && (pfd[0].revents & POLLIN)) {
			char buf[4096];
			struct fanotify_event_metadata *md;
			ssize_t len = read(fanfd, buf, sizeof(buf));

			if (len <= 0)
				continue;
			md = (struct fanotify_event_metadata *)buf;
			while (FAN_EVENT_OK(md, len)) {
				if (md->vers != FANOTIFY_METADATA_VERSION) {
					fprintf(stderr,
						"  ! fanotify ABI mismatch (event %u, built %u)\n",
						md->vers, FANOTIFY_METADATA_VERSION);
					md = FAN_EVENT_NEXT(md, len);
					continue;
				}
				if (md->fd < 0) {
					md = FAN_EVENT_NEXT(md, len);
					continue;
				}
				r->events++;

				if (o->delay_ms)
					ms_sleep(o->delay_ms);
				if (o->on_event && o->on_event(md->fd) != 0)
					r->hook_failed = 1;

				if (o->response != NO_REPLY) {
					struct fanotify_response resp;

					resp.fd = md->fd;
					resp.response = (unsigned int)o->response;
					/* Taken before the write, so it is a
					 * LOWER bound on when the exec was
					 * released - the conservative choice
					 * for "the target started after this". */
					r->t_reply = now_ns();
					if (write(fanfd, &resp, sizeof(resp)) !=
					    (ssize_t)sizeof(resp)) {
						int werr = errno;

						/* A rejected response leaves
						 * the exec HELD, so always
						 * fall back to a plain DENY
						 * rather than leaving the
						 * child parked until the
						 * deadline. The caller reads
						 * resp_errno to see that the
						 * first form was refused. */
						if (o->response != FAN_ALLOW &&
						    o->response != FAN_DENY) {
							r->resp_errno = werr;
							resp.response = FAN_DENY;
							(void)!write(fanfd, &resp,
								     sizeof(resp));
						} else {
							errno = werr;
							perror("  ! fanotify response");
						}
					}
				} else {
					/* No response to send. Still record the
					 * point the CONTENT-class listener would
					 * have replied at, so the control is
					 * compared on equal terms. */
					r->t_reply = now_ns();
				}
				close(md->fd);
				md = FAN_EVENT_NEXT(md, len);
			}
		}

		if (!reaped && waitpid(pid, &status, WNOHANG) == pid)
			reaped = 1;
		/* n == 0 (an empty poll slice) is the drain condition, not
		 * just impatience: in the notification-class control the
		 * target runs and exits WITHOUT waiting for us, so the child
		 * can be reaped while its event is still queued. Breaking on
		 * reaped alone would drop that event and score the control
		 * against a response that was never made. */
		if (reaped && start_done && n == 0)
			break;
	}

	if (!reaped) {
		/* Either the deadline expired or the marker pipe is still
		 * open. WNOHANG first so a genuine hang is reported as a
		 * timeout instead of blocking here forever. */
		if (waitpid(pid, &status, WNOHANG) != pid) {
			r->timed_out = 1;
			kill(pid, SIGKILL);
			waitpid(pid, &status, 0);
		}
	}

	got = read(errp[0], &e, sizeof(e));
	r->exec_errno = (got == (ssize_t)sizeof(e)) ? e : 0;
	r->exited_ok = WIFEXITED(status) && WEXITSTATUS(status) == TARGET_OK;

	close(startp[0]);
	close(errp[0]);
	return 0;
}

/* Phase 5's hook. Runs while the exec is held, with md->fd in hand. */
static int swap_and_compare(int event_fd)
{
	ssize_t n;

	/* Replace the PATH with a different image while its exec is held.
	 * This is the race #88 describes, performed deliberately and at the
	 * worst possible moment. */
	if (rename(path_decoy, path_marked) < 0) {
		perror("  ! rename decoy over marked path");
		return -1;
	}

	n = slurp_fd(event_fd, buf_event, sizeof(buf_event));
	if (n < 0) {
		perror("  ! read event fd");
		return -1;
	}
	len_event = (size_t)n;

	n = slurp_path(path_marked, buf_path, sizeof(buf_path));
	if (n < 0) {
		perror("  ! read path after swap");
		return -1;
	}
	len_path = (size_t)n;
	return 0;
}

static int open_listener(unsigned int class_flag, const char **why)
{
	int fd = fanotify_init(class_flag | FAN_CLOEXEC, O_RDONLY | O_LARGEFILE);

	if (fd < 0) {
		*why = strerror(errno);
		return -1;
	}
	return fd;
}

/* The CONTENT listener's mark has to come OFF while a phase drives a
 * different listener over the same inode: two marked groups both get the
 * event, run_exec() services only the fd it was handed, and the exec
 * stays held by the other one until the deadline. That is not a finding,
 * it is the spike tripping over itself. */
static int set_content_mark(int fanfd, unsigned int flags)
{
	if (fanotify_mark(fanfd, flags, FAN_OPEN_EXEC_PERM, AT_FDCWD,
			  path_marked) < 0) {
		perror("  ! fanotify_mark(content)");
		return -1;
	}
	return 0;
}

static void report(const char *label, int pass, const char *detail)
{
	printf("RESULT: %s -> %s\n", pass ? "PASS" : "FAIL", label);
	if (detail && *detail)
		printf("        %s\n", detail);
}

int main(int argc, char **argv)
{
	struct utsname uts;
	struct run_result r;
	struct run_opts o;
	char detail[512];
	const char *why = "";
	int fanfd, notifd, precfd;
	int ok = 1, pass;
	int content_errno_ok, prec_errno_ok;
	ssize_t n;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <workdir>\n", argv[0]);
		return 2;
	}
	snprintf(path_marked, sizeof(path_marked), "%s/target_orig", argv[1]);
	snprintf(path_decoy, sizeof(path_decoy), "%s/target_decoy", argv[1]);
	snprintf(path_unmarked, sizeof(path_unmarked), "%s/target_unmarked",
		 argv[1]);

	if (uname(&uts) == 0)
		printf("kernel: %s\n", uts.release);
	printf("workdir: %s\n\n", argv[1]);

	fanfd = open_listener(FAN_CLASS_CONTENT, &why);
	if (fanfd < 0) {
		fprintf(stderr,
			"fanotify_init(FAN_CLASS_CONTENT) failed: %s\n", why);
		fprintf(stderr,
			"  permission events need CAP_SYS_ADMIN and CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y\n");
		return 1;
	}
	/* FAN_MARK_ADD on one inode - deliberately NOT FAN_MARK_MOUNT. Only
	 * execs of this exact file can ever block on this listener. */
	if (fanotify_mark(fanfd, FAN_MARK_ADD, FAN_OPEN_EXEC_PERM, AT_FDCWD,
			  path_marked) < 0) {
		perror("fanotify_mark(FAN_OPEN_EXEC_PERM)");
		return 1;
	}

	/* ---------------------------------------------------------------
	 * PHASE 1 - baseline. Same file phase 3 will deny, allowed here.
	 * Without this, a target that could not run for some unrelated
	 * reason would be refused in phase 3 too, and that refusal would
	 * be credited to enforcement it did not cause.
	 * --------------------------------------------------------------- */
	printf("== PHASE 1: marked target, FAN_ALLOW (expect: RUNS) ==\n");
	memset(&o, 0, sizeof(o));
	o.path = path_marked;
	o.response = FAN_ALLOW;
	if (run_exec(fanfd, &o, &r) < 0) {
		perror("run_exec");
		return 1;
	}
	pass = r.events == 1 && r.exec_errno == 0 && r.exited_ok &&
	       r.marker == 'A' && !r.timed_out;
	snprintf(detail, sizeof(detail),
		 "events=%d exec_errno=%d marker=%c exited_ok=%d",
		 r.events, r.exec_errno, r.marker ? r.marker : '-', r.exited_ok);
	report("allowed exec runs, and one permission event was delivered",
	       pass, detail);
	ok &= pass;
	printf("\n");

	/* ---------------------------------------------------------------
	 * PHASE 2 - the claim that matters: the exec is HELD, not observed.
	 * --------------------------------------------------------------- */
	printf("== PHASE 2: stall %d ms before FAN_ALLOW (expect: exec HELD) ==\n",
	       BLOCK_DELAY_MS);
	memset(&o, 0, sizeof(o));
	o.path = path_marked;
	o.response = FAN_ALLOW;
	o.delay_ms = BLOCK_DELAY_MS;
	if (run_exec(fanfd, &o, &r) < 0) {
		perror("run_exec");
		return 1;
	}
	pass = r.events == 1 && r.marker == 'A' && !r.timed_out &&
	       r.t_marker > r.t_reply &&
	       ms_since(r.t_fork, r.t_marker) >= (double)BLOCK_DELAY_MS;
	snprintf(detail, sizeof(detail),
		 "target started %.1f ms after fork, %.1f ms after the response",
		 ms_since(r.t_fork, r.t_marker), ms_since(r.t_reply, r.t_marker));
	report("exec did not start until the listener responded", pass, detail);
	ok &= pass;
	printf("\n");

	/* ---------------------------------------------------------------
	 * PHASE 2 CONTROL - is phase 2 measuring anything?
	 *
	 * Phase 2's parent slept 300 ms, so "300 ms elapsed" is true either
	 * way and proves nothing on its own. Re-run the identical timing
	 * against a NOTIFICATION-class listener, where the kernel does not
	 * wait for anyone. If the target still starts after the response
	 * there, phase 2's ordering is an artefact and both are void.
	 * --------------------------------------------------------------- */
	printf("== PHASE 2 CONTROL: same stall, FAN_CLASS_NOTIF (expect: NOT held) ==\n");
	if (set_content_mark(fanfd, FAN_MARK_REMOVE) < 0)
		return 1;
	notifd = open_listener(FAN_CLASS_NOTIF, &why);
	if (notifd < 0) {
		fprintf(stderr, "fanotify_init(FAN_CLASS_NOTIF) failed: %s\n", why);
		return 1;
	}
	if (fanotify_mark(notifd, FAN_MARK_ADD, FAN_OPEN_EXEC, AT_FDCWD,
			  path_marked) < 0) {
		perror("fanotify_mark(FAN_OPEN_EXEC)");
		return 1;
	}
	memset(&o, 0, sizeof(o));
	o.path = path_marked;
	o.response = NO_REPLY;
	o.delay_ms = BLOCK_DELAY_MS;
	if (run_exec(notifd, &o, &r) < 0) {
		perror("run_exec");
		return 1;
	}
	/* The listener must still be holding nothing: the target has to
	 * have run BEFORE the point a CONTENT listener would have replied. */
	pass = r.marker == 'A' && !r.timed_out && r.t_marker < r.t_reply &&
	       ms_since(r.t_fork, r.t_marker) < (double)BLOCK_DELAY_MS;
	snprintf(detail, sizeof(detail),
		 "target started %.1f ms after fork, %.1f ms BEFORE the response point",
		 ms_since(r.t_fork, r.t_marker), ms_since(r.t_marker, r.t_reply));
	report("notification-class exec ran immediately, so phase 2 measured real blocking",
	       pass, detail);
	ok &= pass;
	close(notifd);
	if (set_content_mark(fanfd, FAN_MARK_ADD) < 0)
		return 1;
	printf("\n");

	/* ---------------------------------------------------------------
	 * PHASE 3 - denial, with an errno of our choosing.
	 * --------------------------------------------------------------- */
	printf("== PHASE 3: FAN_DENY (expect: exec REFUSED with EPERM) ==\n");
	memset(&o, 0, sizeof(o));
	o.path = path_marked;
	o.response = FAN_DENY;
	if (run_exec(fanfd, &o, &r) < 0) {
		perror("run_exec");
		return 1;
	}
	pass = r.events == 1 && r.exec_errno == EPERM && r.marker == 0 &&
	       !r.exited_ok && !r.timed_out;
	snprintf(detail, sizeof(detail),
		 "execl failed with %s (%d), target never started",
		 strerror(r.exec_errno), r.exec_errno);
	report("denied exec is refused, and the image never runs", pass, detail);
	ok &= pass;
	printf("\n");

	/* ---------------------------------------------------------------
	 * PHASE 3b - can the denial errno be chosen?
	 *
	 * #102 lists FAN_DENY_ERRNO() as a plain capability. It is not: on
	 * this kernel a custom errno is accepted only from a PRE_CONTENT
	 * group, and a CONTENT group's response is rejected with EINVAL.
	 * Both classes are tried here so the answer is attributed to the
	 * class rather than to the kernel version.
	 * --------------------------------------------------------------- */
	printf("== OBSERVATION 3b: is the denial errno selectable? ==\n");
	memset(&o, 0, sizeof(o));
	o.path = path_marked;
	o.response = (int)FAN_DENY_ERRNO(DENY_ERRNO);
	if (run_exec(fanfd, &o, &r) < 0) {
		perror("run_exec");
		return 1;
	}
	content_errno_ok = r.resp_errno == 0 && r.exec_errno == DENY_ERRNO;
	printf("  FAN_CLASS_CONTENT:     %s; exec refused with %s\n",
	       content_errno_ok ? "honoured" : "response REJECTED",
	       strerror(r.exec_errno));
	if (r.resp_errno)
		printf("                         write(response) -> %s\n",
		       strerror(r.resp_errno));
	/* Whatever the errno, the exec must still have been refused - the
	 * fallback must not have quietly turned a denial into an allow. */
	pass = r.exec_errno != 0 && r.marker == 0 && !r.timed_out;

	if (set_content_mark(fanfd, FAN_MARK_REMOVE) < 0)
		return 1;
	precfd = open_listener(FAN_CLASS_PRE_CONTENT, &why);
	if (precfd < 0) {
		fprintf(stderr,
			"fanotify_init(FAN_CLASS_PRE_CONTENT) failed: %s\n", why);
		return 1;
	}
	if (fanotify_mark(precfd, FAN_MARK_ADD, FAN_OPEN_EXEC_PERM, AT_FDCWD,
			  path_marked) < 0) {
		perror("fanotify_mark(pre-content)");
		return 1;
	}
	memset(&o, 0, sizeof(o));
	o.path = path_marked;
	o.response = (int)FAN_DENY_ERRNO(DENY_ERRNO);
	if (run_exec(precfd, &o, &r) < 0) {
		perror("run_exec");
		return 1;
	}
	prec_errno_ok = r.resp_errno == 0 && r.exec_errno == DENY_ERRNO;
	printf("  FAN_CLASS_PRE_CONTENT: %s; exec refused with %s\n",
	       prec_errno_ok ? "honoured" : "response REJECTED",
	       strerror(r.exec_errno));
	if (r.resp_errno)
		printf("                         write(response) -> %s\n",
		       strerror(r.resp_errno));
	pass = pass && r.exec_errno != 0 && r.marker == 0 && !r.timed_out;
	close(precfd);
	if (set_content_mark(fanfd, FAN_MARK_ADD) < 0)
		return 1;

	/* Deliberately NOT an assertion on the errno itself. #102 lists
	 * FAN_DENY_ERRNO() as available; whether it is, is a fact to
	 * record, not a requirement to impose - a design can live with
	 * EPERM. What IS asserted is that both probes still refused the
	 * exec, so the fallback cannot have silently allowed it. */
	snprintf(detail, sizeof(detail),
		 "a chosen denial errno: %s",
		 content_errno_ok ? "works on FAN_CLASS_CONTENT" :
		 prec_errno_ok	  ? "needs FAN_CLASS_PRE_CONTENT" :
		 "REJECTED ON BOTH CLASSES - denial returns EPERM here");
	report("both probes refused the exec (the errno itself is an observation)",
	       pass, detail);
	ok &= pass;
	printf("\n");

	/* ---------------------------------------------------------------
	 * PHASE 4 - selectivity. A listener that stalled or denied every
	 * exec would satisfy phases 2 and 3 and look like a pass.
	 * --------------------------------------------------------------- */
	printf("== PHASE 4: unmarked sibling while the mark is live (expect: RUNS, no event) ==\n");
	memset(&o, 0, sizeof(o));
	o.path = path_unmarked;
	o.response = FAN_ALLOW;
	if (run_exec(fanfd, &o, &r) < 0) {
		perror("run_exec");
		return 1;
	}
	pass = r.events == 0 && r.exec_errno == 0 && r.exited_ok &&
	       r.marker == 'U' && !r.timed_out;
	snprintf(detail, sizeof(detail),
		 "events=%d marker=%c - denial and delay are keyed on the mark",
		 r.events, r.marker ? r.marker : '-');
	report("unmarked exec unaffected", pass, detail);
	ok &= pass;
	printf("\n");

	/* ---------------------------------------------------------------
	 * PHASE 5 - the fd is the image, not the path (#88).
	 *
	 * Swap a different binary over the path WHILE its exec is held,
	 * then ask three questions: what does the held fd contain, what
	 * does the path contain now, and what actually ran?
	 * --------------------------------------------------------------- */
	printf("== PHASE 5: swap the path mid-event (expect: fd and exec both see the ORIGINAL) ==\n");
	n = slurp_path(path_marked, buf_orig, sizeof(buf_orig));
	if (n < 0) {
		perror("read target_orig");
		return 1;
	}
	len_orig = (size_t)n;
	n = slurp_path(path_decoy, buf_decoy, sizeof(buf_decoy));
	if (n < 0) {
		perror("read target_decoy");
		return 1;
	}
	len_decoy = (size_t)n;
	if (len_orig == len_decoy &&
	    memcmp(buf_orig, buf_decoy, len_orig) == 0) {
		fprintf(stderr,
			"  ! target_orig and target_decoy are identical - phase 5 would be vacuous\n");
		return 1;
	}

	memset(&o, 0, sizeof(o));
	o.path = path_marked;
	o.response = FAN_ALLOW;
	o.on_event = swap_and_compare;
	if (run_exec(fanfd, &o, &r) < 0) {
		perror("run_exec");
		return 1;
	}
	pass = r.events == 1 && !r.hook_failed && !r.timed_out &&
	       /* the held fd still yields the image we were asked about */
	       len_event == len_orig &&
	       memcmp(buf_event, buf_orig, len_orig) == 0 &&
	       /* ...and the swap really happened, so that is not trivially true */
	       len_path == len_decoy &&
	       memcmp(buf_path, buf_decoy, len_decoy) == 0 &&
	       /* ...and the kernel ran the image we scanned, not the new path */
	       r.marker == 'A' && r.exited_ok;
	snprintf(detail, sizeof(detail),
		 "held fd = original (%zu B), path now = decoy (%zu B), exec ran marker=%c",
		 len_event, len_path, r.marker ? r.marker : '-');
	report("scanning the event fd cannot be raced by replacing the path",
	       pass, detail);
	ok &= pass;
	printf("\n");

	close(fanfd);

	printf("==================================================\n");
	if (ok) {
		printf("VERDICT: FAN_OPEN_EXEC_PERM holds the exec until userspace\n");
		printf("         responds, refuses it on FAN_DENY, and hands over the\n");
		printf("         image that actually runs.\n");
		printf("         The denial errno was NOT selectable here: EPERM only.\n");
		printf("         Scope: one inode mark, one listener, a stubbed verdict\n");
		printf("         that is just a sleep. Mount-wide marking, avd's own\n");
		printf("         re-entrancy and throughput are NOT tested - see README.\n");
		return 0;
	}
	printf("VERDICT: inconclusive - see the failing phase(s) above.\n");
	return 1;
}
