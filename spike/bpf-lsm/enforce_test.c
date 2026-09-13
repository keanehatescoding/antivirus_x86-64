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
	if (n > 0)
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
	if (n > 0)
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

/* Returns: 0 exec succeeded, >0 the errno execv failed with, -1 internal. */
static int try_exec(const char *path)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return -1;

	if (pid == 0) {
		char *const argv[] = { (char *)path, NULL };

		execv(path, argv);
		_exit(errno); /* hand the exec errno back as the exit code */
	}

	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (!WIFEXITED(status))
		return -1;
	/* target_*.c exits 7 on success, so anything else is an exec errno. */
	return WEXITSTATUS(status) == 7 ? 0 : WEXITSTATUS(status);
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

	/* CONTROL: map is still empty, so this must run normally. If exec is
	 * broken outright, this catches it before the real assertion. */
	rc = try_exec(TARGET_ALLOWED);
	if (rc != 0) {
		outmsg("ENFORCE_TEST: control exec FAILED (rc=%d, %s) - "
		       "attaching broke exec generally\n", rc, strerror(rc));
		finish(0);
	}
	outmsg("ENFORCE_TEST: control exec succeeded (unblocked file runs)\n");

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

	/* THE ASSERTION: this exec must be refused with EPERM. */
	rc = try_exec(TARGET_BLOCKED);
	if (rc == 0) {
		outmsg("ENFORCE_TEST: blocked target RAN - not enforced\n");
		finish(0);
	}
	if (rc != EPERM) {
		outmsg("ENFORCE_TEST: blocked target failed with %d (%s), "
		       "expected EPERM\n", rc, strerror(rc));
		finish(0);
	}
	outmsg("ENFORCE_TEST: blocked target denied with EPERM\n");

	bpf_link__destroy(link);
	bpf_object__close(obj);
	finish(1);
}
