// SPDX-License-Identifier: GPL-2.0
/* PID 1 for the QEMU enforcement test: proves the spike's BPF LSM
 * program actually DENIES an exec, which the load-only run_spike.sh
 * deliberately cannot show (it runs the verifier and attaches nothing).
 *
 * Runs only inside a throwaway VM. Attaching this hook on a live
 * machine risks denying every exec on the system, which is why this
 * exists as a VM init rather than a host-side script.
 *
 * Shape of the test:
 *   1. load + attach the spike program (map empty -> denies nothing)
 *   2. exec /target_allowed              -> must SUCCEED
 *   3. add /target_blocked's {dev,ino} to blocked_files
 *   4. exec /target_blocked              -> must FAIL with EPERM
 *
 * Step 2 is not decoration: without it, a program that broke exec
 * outright would look identical to one enforcing correctly. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#define BPF_OBJ "/av_lsm_spike.bpf.o"
#define PROG_NAME "av_bprm_check"
#define MAP_NAME "blocked_files"
#define TARGET_ALLOWED "/target_allowed"
#define TARGET_BLOCKED "/target_blocked"

/* Must match the exit status in target.c. */
#define TARGET_OK 7
/* The child's status when execv itself failed; the real errno arrives
 * over the pipe, so this value only has to differ from TARGET_OK. */
#define TARGET_EXEC_FAILED 127

/* Must match struct file_id in av_lsm_spike.bpf.c exactly. */
struct file_id {
	unsigned long long ino;
	unsigned int dev;
	unsigned int __pad;
};

static void outmsg(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	/* vsnprintf returns the length it WOULD have written, which can
	 * exceed the buffer - clamp before write() reads past the end of
	 * it. Same clamp tests/qemu-boot/init.c's outmsg() uses. */
	if ((size_t)n >= sizeof(buf))
		n = sizeof(buf) - 1;
	(void)!write(STDOUT_FILENO, buf, (size_t)n);
}

static void finish(int pass)
{
	outmsg(pass ? "ENFORCE_TEST: PASS\n" : "ENFORCE_TEST: FAIL\n");
	sync();
	reboot(RB_POWER_OFF);
	for (;;)
		pause();
}

/* libbpf logs at INFO by default only with a callback; keep verifier
 * errors visible since a failure here is the interesting case. */
static int libbpf_print(enum libbpf_print_level level, const char *fmt,
			va_list ap)
{
	char buf[2048];
	int n;

	if (level == LIBBPF_DEBUG)
		return 0;
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	if (n < 0)
		return 0;
	/* Clamp as above - a verifier log is exactly the kind of
	 * diagnostic that overruns 2048 bytes. */
	if ((size_t)n >= sizeof(buf))
		n = sizeof(buf) - 1;
	(void)!write(STDOUT_FILENO, buf, (size_t)n);
	return 0;
}

/* The kernel stores i_sb->s_dev in kernel kdev_t encoding
 * (major << 20 | minor). glibc's st_dev uses a different packing, so
 * comparing them raw silently never matches - re-encode explicitly. */
static unsigned int kernel_dev(dev_t st_dev)
{
	return (unsigned int)((major(st_dev) << 20) | minor(st_dev));
}

/* Run PATH in a child and report whether the exec itself was allowed.
 *
 * Returns: 0 the target ran, >0 the errno execv failed with,
 *          -1 internal error / inconclusive.
 *
 * The exec errno comes back over a CLOEXEC pipe rather than through the
 * child's exit status. Exit status cannot carry both meanings at once:
 * errno 7 is E2BIG, which collides exactly with TARGET_OK, so a failed
 * exec would be indistinguishable from a successful run - and it would
 * fail in the direction that produces a false PASS. With the pipe there
 * is nothing to disambiguate: the close-on-exec is itself the signal, so
 * data means exec failed and EOF means it succeeded, for every errno. */
static int try_exec(const char *path)
{
	int pfd[2];
	pid_t pid;
	int status;
	int err = 0;
	ssize_t n;

	if (pipe2(pfd, O_CLOEXEC) < 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}

	if (pid == 0) {
		char *const argv[] = { (char *)path, NULL };

		close(pfd[0]);
		execv(path, argv);
		/* Only reached if the exec was refused. */
		err = errno;
		(void)!write(pfd[1], &err, sizeof(err));
		_exit(TARGET_EXEC_FAILED);
	}

	close(pfd[1]);
	n = read(pfd[0], &err, sizeof(err));
	close(pfd[0]);

	if (waitpid(pid, &status, 0) < 0)
		return -1;

	if (n == (ssize_t)sizeof(err))
		return err > 0 ? err : -1; /* exec refused, errno on the pipe */
	if (n != 0)
		return -1; /* short or failed read - don't guess */

	/* Pipe hit EOF with nothing written, so the exec succeeded. Confirm
	 * the target then ran to completion rather than dying on a signal. */
	if (!WIFEXITED(status) || WEXITSTATUS(status) != TARGET_OK)
		return -1;
	return 0;
}

/* Require PATH to execute and run to completion. Returns 1 on success,
 * or 0 after reporting why not. WHAT names the step, so a failure says
 * which of the four execs below went wrong. */
static int expect_runs(const char *path, const char *what)
{
	int rc = try_exec(path);

	if (rc == 0)
		return 1;
	if (rc < 0)
		outmsg("ENFORCE_TEST: %s inconclusive - could not determine "
		       "whether %s ran\n", what, path);
	else
		outmsg("ENFORCE_TEST: %s - %s was refused (%s)\n", what, path,
		       strerror(rc));
	return 0;
}

int main(void)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	struct bpf_map *map;
	struct file_id key = { 0 };
	struct stat st;
	unsigned char one = 1;
	int err, rc;

	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);

	libbpf_set_print(libbpf_print);
	outmsg("ENFORCE_TEST: init started\n");

	obj = bpf_object__open_file(BPF_OBJ, NULL);
	if (!obj) {
		outmsg("ENFORCE_TEST: open_file failed: %s\n", strerror(errno));
		finish(0);
	}

	err = bpf_object__load(obj);
	if (err) {
		outmsg("ENFORCE_TEST: load failed: %d\n", err);
		finish(0);
	}
	outmsg("ENFORCE_TEST: program loaded\n");

	prog = bpf_object__find_program_by_name(obj, PROG_NAME);
	map = bpf_object__find_map_by_name(obj, MAP_NAME);
	if (!prog || !map) {
		outmsg("ENFORCE_TEST: missing program or map\n");
		finish(0);
	}

	link = bpf_program__attach_lsm(prog);
	if (!link) {
		outmsg("ENFORCE_TEST: attach_lsm failed: %s\n", strerror(errno));
		finish(0);
	}
	outmsg("ENFORCE_TEST: attached to bprm_check_security\n");

	/* BASELINE: the file about to be blocked must run RIGHT NOW, with
	 * the program attached and the map empty. This is the control that
	 * matters, and it has to be this file: TARGET_ALLOWED succeeding
	 * says nothing about whether a different file was ever executable.
	 * Without this, a TARGET_BLOCKED that could not run for some
	 * unrelated reason would be refused after the map update too, and
	 * that refusal would be credited to enforcement it did not cause. */
	if (!expect_runs(TARGET_BLOCKED, "baseline (pre-block)"))
		finish(0);
	outmsg("ENFORCE_TEST: baseline - target_blocked runs before the "
	       "map update\n");

	/* CONTROL: an unrelated file also runs while the map is empty, so a
	 * program that broke exec outright is caught before the assertion. */
	if (!expect_runs(TARGET_ALLOWED, "control (pre-block)"))
		finish(0);
	outmsg("ENFORCE_TEST: control - target_allowed runs\n");

	if (stat(TARGET_BLOCKED, &st) < 0) {
		outmsg("ENFORCE_TEST: stat failed: %s\n", strerror(errno));
		finish(0);
	}
	key.ino = (unsigned long long)st.st_ino;
	key.dev = kernel_dev(st.st_dev);
	outmsg("ENFORCE_TEST: blocking dev=0x%x ino=%llu\n", key.dev, key.ino);

	err = bpf_map__update_elem(map, &key, sizeof(key), &one, sizeof(one),
				   BPF_ANY);
	if (err) {
		outmsg("ENFORCE_TEST: map update failed: %d\n", err);
		finish(0);
	}

	/* THE ASSERTION: the SAME file that just ran must now be refused
	 * with EPERM. The only thing that changed is the map entry. */
	rc = try_exec(TARGET_BLOCKED);
	if (rc == 0) {
		outmsg("ENFORCE_TEST: blocked target RAN - not enforced\n");
		finish(0);
	}
	if (rc < 0) {
		outmsg("ENFORCE_TEST: blocked target inconclusive - the exec "
		       "did not clearly succeed or fail\n");
		finish(0);
	}
	if (rc != EPERM) {
		outmsg("ENFORCE_TEST: blocked target refused with %s, "
		       "expected EPERM\n", strerror(rc));
		finish(0);
	}
	outmsg("ENFORCE_TEST: blocked target denied with EPERM\n");

	/* SELECTIVITY: the unblocked file must STILL run. Without this, a
	 * program that started denying everything the moment the map became
	 * non-empty would satisfy the assertion above and pass. */
	if (!expect_runs(TARGET_ALLOWED, "selectivity (post-block)"))
		finish(0);
	outmsg("ENFORCE_TEST: selectivity - target_allowed still runs, so "
	       "the denial is keyed on identity\n");

	bpf_link__destroy(link);
	bpf_object__close(obj);
	finish(1);
}
