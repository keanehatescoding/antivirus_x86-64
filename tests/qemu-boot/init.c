/* Minimal PID 1 for the QEMU-boot runtime CI job (see
 * .github/workflows/qemu-boot-test.yml) - actually boots a kernel,
 * insmod's av.ko, and confirms EICAR detection fires for real, unlike
 * build-matrix.yml's compile-only testing. No busybox, no shell -
 * just enough libc + a couple of direct syscalls to mount what's
 * needed, load the module, exec a clean file and an EICAR file, check
 * the results against dmesg, print one final PASS/FAIL line to the
 * serial console, and power off. Statically linked.
 *
 * See also cold_launcher.c (same directory) - a dedicated companion
 * binary this one execs partway through, as a regression test for
 * #87 (cold userspace pathname pages missed by the old syscall-entry
 * kprobe - see its own header comment, and av/main.c's
 * handler_pre_bprm_check()).
 *
 * All output goes through outmsg() (vsnprintf into a buffer + a raw
 * write(2) to fd 1) rather than stdio - printf()+fflush() was tried
 * first and its output never reached the serial console (kernel
 * printk output appeared fine; only userspace stdio output was
 * lost), for reasons not fully root-caused. write() sidesteps
 * whatever that was rather than chasing it further.
 *
 * Runs in one of three modes:
 *   - argv[1] == "--clean-marker": immediately exit(42). This is what
 *     gets exec'd as the "definitely not malicious" test case - no
 *     separate coreutils/busybox binary needed, we just re-exec
 *     ourselves.
 *   - argv[1] == "--self-unlink" <path>: wait for a byte on fd 3, then
 *     unlink <path> and linger (exit 43 if still alive). Run from a
 *     copy of this binary by the self-delete correlation case.
 *   - no args (PID 1): the actual init/test-runner logic below.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define EICAR                                                                \
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

static void outmsg(const char *fmt, ...) {
  static char buf[65536];
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0)
    return;
  if ((size_t)n >= sizeof(buf))
    n = sizeof(buf) - 1;
  write(1, buf, (size_t)n);
}

static void die(const char *msg) __attribute__((noreturn));
static void die(const char *msg) {
  outmsg("QEMU_TEST: FAIL: %s: %s\n", msg, strerror(errno));
  sync();
  reboot(RB_POWER_OFF);
  _exit(1);
}

static void pass_and_poweroff(void) {
  outmsg("QEMU_TEST: PASS\n");
  sync();
  reboot(RB_POWER_OFF);
  _exit(0);
}

static void write_file(const char *path, const char *content) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
  if (fd < 0)
    die("open for write");
  if (write(fd, content, strlen(content)) < 0)
    die("write");
  close(fd);
}

/* Runs `path` and reports how it terminated via *killed_by_sigkill /
 * *exited_cleanly. Blocks until it exits. `arg1`, if non-NULL, is
 * passed as argv[1] (used to re-exec /init itself with
 * --clean-marker). */
static void run_and_wait(const char *path, const char *arg1,
                         int *killed_by_sigkill, int *exited_cleanly,
                         int *exit_code) {
  pid_t pid = fork();
  int status;

  if (pid < 0)
    die("fork");

  if (pid == 0) {
    char *const argv[] = {(char *)path, (char *)arg1, NULL};

    /* Touch `path`'s first byte before exec, forcing its page
     * resident. Historically required: the old syscall-entry kprobe
     * copied the pathname in atomic context and silently skipped
     * execs whose pathname sat on a cold page (#87). The
     * security_bprm_check() hook no longer reads userspace memory, so
     * this is now only belt-and-braces for the primary checks. It is
     * deliberately NOT applied to cold_launcher.c's own internal exec,
     * which exists to exercise the untouched-page case (see main()'s
     * cold-pathname regression block). */
    {
      volatile char touch = path[0];
      (void)touch;
    }

    execv(path, argv);
    /* Only reached if execv itself failed (e.g. ENOEXEC for a
     * non-ELF/non-script file like eicar.com). The kill for a
     * malicious file is workqueue-deferred (async), so it can in
     * principle race against this process's own synchronous
     * failure-and-exit path. 1 second, not a token 100ms: matches
     * tests/test_detection.sh's own `sleep 1` for the identical
     * async-kill-vs-local-exit race on real hardware - no reason this
     * environment's workqueue would be reliably faster. */
    usleep(1000000);
    _exit(127);
  }

  if (waitpid(pid, &status, 0) < 0)
    die("waitpid");

  *killed_by_sigkill = WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
  *exited_cleanly = WIFEXITED(status);
  *exit_code = *exited_cleanly ? WEXITSTATUS(status) : -1;
}

/* Reads the full kernel log ring buffer via the same syslog(2)
 * mechanism `dmesg` uses - no /dev/kmsg or dmesg binary needed. */
static char *read_kernel_log(void) {
  static char buf[65536];
  int n = syscall(SYS_syslog, /* SYSLOG_ACTION_READ_ALL */ 3, buf,
                  sizeof(buf) - 1);
  if (n < 0)
    die("syslog(SYSLOG_ACTION_READ_ALL)");
  buf[n] = '\0';
  return buf;
}

/* ---- helpers for the self-delete correlation case ---- */

static void sleep_ms(long ms) {
  struct timespec ts = {.tv_sec = ms / 1000,
                        .tv_nsec = (ms % 1000) * 1000 * 1000L};

  nanosleep(&ts, NULL);
}

static void copy_file(const char *src, const char *dst) {
  char buf[65536];
  int in = open(src, O_RDONLY);
  int out;
  ssize_t n;

  if (in < 0)
    die("open copy source");
  out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0700);
  if (out < 0)
    die("open copy destination");
  while ((n = read(in, buf, sizeof(buf))) > 0) {
    if (write(out, buf, (size_t)n) != n)
      die("write copy destination");
  }
  if (n < 0)
    die("read copy source");
  close(in);
  close(out);
}

/* Waits up to timeout_ms for `pid`, SIGKILLing (and reaping) it if it
 * is still running then. *exit_code is -1 unless it exited normally;
 * *term_sig is 0 unless a signal ended it. A timeout reports the
 * timeout's own SIGKILL as -1/0 so it can't pass for a detection. */
static void wait_for_exit(pid_t pid, int timeout_ms, int *exit_code,
                          int *term_sig) {
  int status;
  int waited = 0;

  for (;;) {
    pid_t r = waitpid(pid, &status, WNOHANG);

    if (r < 0)
      die("waitpid");
    if (r == pid)
      break;
    if (waited >= timeout_ms) {
      kill(pid, SIGKILL);
      if (waitpid(pid, &status, 0) < 0)
        die("waitpid after timeout");
      *exit_code = -1;
      *term_sig = 0;
      return;
    }
    sleep_ms(50);
    waited += 50;
  }
  *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  *term_sig = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
}

/* Execs `exec_path` (a copy of /init) in --self-unlink mode, lets it
 * unlink `unlink_path` once av.ko has recorded the exec, and reports
 * how it ended. `recorded_path` is the d_path() av.ko logs for the
 * exec (symlinks followed); its event=clean line for this pid is the
 * signal that av_behavior_record_exec() has run, since av_work_fn()
 * records before it logs. That line is ratelimited, so if it never
 * shows the case proceeds after SELF_DELETE_RECORD_WAIT_MS anyway -
 * an unscanned exec would leave no record and fail the kill
 * assertion, not pass it. Returns 1 if the child was SIGKILLed. */
#define SELF_DELETE_RECORD_WAIT_MS 5000
static int run_self_delete_case(const char *exec_path,
                                const char *recorded_path,
                                const char *unlink_path, int *exit_code,
                                int *term_sig, int *saw_record) {
  int sync_fd[2];
  pid_t pid;
  char needle[256];
  int waited = 0;

  if (pipe(sync_fd) != 0)
    die("pipe(self-delete sync)");
  pid = fork();
  if (pid < 0)
    die("fork(self-delete)");
  if (pid == 0) {
    char *const cargv[] = {(char *)exec_path, "--self-unlink",
                           (char *)unlink_path, NULL};

    close(sync_fd[1]);
    if (sync_fd[0] != 3) {
      if (dup2(sync_fd[0], 3) < 0)
        _exit(126);
      close(sync_fd[0]);
    }
    execv(exec_path, cargv);
    _exit(127);
  }
  close(sync_fd[0]);

  snprintf(needle, sizeof(needle), "path=\"%s\" pid=%d ", recorded_path,
           (int)pid);
  *saw_record = 0;
  while (waited < SELF_DELETE_RECORD_WAIT_MS) {
    if (strstr(read_kernel_log(), needle)) {
      *saw_record = 1;
      break;
    }
    sleep_ms(50);
    waited += 50;
  }

  if (write(sync_fd[1], "x", 1) != 1)
    die("write(self-delete sync)");
  close(sync_fd[1]);
  wait_for_exit(pid, 15000, exit_code, term_sig);
  return *term_sig == SIGKILL;
}

int main(int argc, char *const argv[]) {
  if (argc > 1 && !strcmp(argv[1], "--clean-marker")) {
    _exit(42);
  }
  /* Child half of the self-delete case below, run as a COPY of this
   * binary: block until the parent writes one byte to fd 3 (it does so
   * once av.ko has recorded this exec), unlink argv[2], then linger so
   * the kernel's asynchronous self-delete kill has time to land. Exit
   * 43 means it was NOT killed; 44/45 mean the helper itself broke. */
  if (argc > 2 && !strcmp(argv[1], "--self-unlink")) {
    char c;

    if (read(3, &c, 1) != 1)
      _exit(44);
    if (unlink(argv[2]) != 0)
      _exit(45);
    sleep(5);
    _exit(43);
  }

  /* ---- pid 1 setup ---- */
  if (mount("proc", "/proc", "proc", 0, NULL) != 0)
    die("mount /proc");
  /* CONFIG_DEVTMPFS_MOUNT already auto-mounts /dev before init runs -
   * EBUSY here just means that already happened, not a real failure. */
  if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) != 0 && errno != EBUSY)
    die("mount /dev");
  if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) != 0)
    die("mount /tmp");

  outmsg("QEMU_TEST: init started\n");

  /* ---- load av.ko (init_module(2) directly - no insmod binary) ---- */
  {
    int fd = open("/av.ko", O_RDONLY);
    struct stat st;
    void *image;

    if (fd < 0)
      die("open /av.ko");
    if (fstat(fd, &st) != 0)
      die("fstat /av.ko");
    /* st_size is attacker-influenced only in the sense that /av.ko comes
     * from the test initramfs we built ourselves, but validating it here
     * costs nothing and keeps a truncated/corrupt image from turning into
     * a huge malloc or a short read passed to init_module as if whole. */
    if (!S_ISREG(st.st_mode))
      die("/av.ko not a regular file");
    if (st.st_size <= 0 || st.st_size > (off_t)(32 * 1024 * 1024))
      die("/av.ko size out of bounds");
    image = malloc((size_t)st.st_size);
    if (!image)
      die("malloc for module image");
    {
      size_t remaining = (size_t)st.st_size;
      char *p = image;
      while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n < 0)
          die("read /av.ko");
        if (n == 0)
          die("read /av.ko: short read");
        p += n;
        remaining -= (size_t)n;
      }
    }
    close(fd);

    if (syscall(SYS_init_module, image, (unsigned long)st.st_size, "") != 0)
      die("init_module(av.ko)");
    free(image);
  }
  outmsg("QEMU_TEST: av.ko loaded\n");

  /* ---- clean-file check: exec ourselves with --clean-marker, must
   * exit(42) normally, not be killed ---- */
  {
    int killed, exited, code;
    run_and_wait("/init", "--clean-marker", &killed, &exited, &code);
    if (killed) {
      outmsg("QEMU_TEST: FAIL: clean-marker exec was killed (false "
             "positive)\n");
      reboot(RB_POWER_OFF);
      return 1;
    }
    if (!exited || code != 42) {
      outmsg("QEMU_TEST: FAIL: clean-marker exec exited unexpectedly "
             "(exited=%d code=%d)\n",
             exited, code);
      reboot(RB_POWER_OFF);
      return 1;
    }
  }
  outmsg("QEMU_TEST: clean-file check passed\n");

  /* ---- EICAR check: must be killed with SIGKILL, and dmesg must
   * show the structured detection line ---- */
  {
    int killed, exited, code;

    write_file("/tmp/eicar.com", EICAR);
    run_and_wait("/tmp/eicar.com", NULL, &killed, &exited, &code);

    if (!killed) {
      outmsg("QEMU_TEST: FAIL: EICAR exec was NOT killed by SIGKILL "
             "(exited=%d code=%d)\n",
             exited, code);
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      reboot(RB_POWER_OFF);
      return 1;
    }

    {
      char *log = read_kernel_log();
      if (!strstr(log, "event=detected") || !strstr(log, "action=kill") ||
          !strstr(log, "type=signature") ||
          !strstr(log, "path=\"/tmp/eicar.com\"")) {
        outmsg("QEMU_TEST: FAIL: EICAR was killed but dmesg is missing the "
               "expected structured detection line\n");
        outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", log);
        reboot(RB_POWER_OFF);
        return 1;
      }
    }
  }
  outmsg("QEMU_TEST: EICAR detection check passed\n");

  /* ---- regression case: cold-pathname exec (#87) ----
   * The old syscall-entry kprobe copied the pathname with
   * strncpy_from_user() in atomic context; a pathname on a
   * not-yet-resident page failed with -EFAULT and the exec went
   * unscanned. The hook now sits on security_bprm_check() and pins
   * bprm->file directly, so the kprobe never reads userspace memory.
   * cold_launcher.c is a separate binary so its embedded pathname
   * literal is genuinely untouched at exec time (see its header
   * comment). A kill is the expected outcome; anything else is a
   * FAIL. */
  {
    int killed, exited, code;

    write_file("/tmp/eicar_cold.com", EICAR);
    run_and_wait("/cold_launcher", NULL, &killed, &exited, &code);

    if (!killed) {
      /* code == 1 is cold_launcher.c's own `return 1` after its inner
       * execve() fails ENOEXEC without being killed - the #87 bypass
       * regressing. code == 127 is run_and_wait's OWN outer execv()
       * failing (/cold_launcher missing or broken in the initramfs). */
      outmsg("QEMU_TEST: FAIL: cold-pathname exec was NOT killed "
             "(exited=%d code=%d)%s\n",
             exited, code,
             (exited && code == 1) ? " - #87 bypass regressed"
                                   : " - /cold_launcher itself looks broken");
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      reboot(RB_POWER_OFF);
      return 1;
    }
  }
  outmsg("QEMU_TEST: cold-pathname check passed\n");

  /* ---- regression case: self-delete correlation through a directory
   * symlink ----
   * av_behavior_check_unlink() kills a process that unlinks its own
   * executable, matched by path string. The unlink side spells the path
   * lexically (resolve_absolute_path(): symlinks NOT followed); since
   * the security_bprm_check() hook the exec side records d_path() of
   * the executed file, which DOES follow them. With only that key,
   * exec /tmp/sd_alias/a followed by unlink("/tmp/sd_alias/a")
   * compared /tmp/sd_real/a against /tmp/sd_alias/a and missed. av.ko
   * now also records the exec name lexically (av_exec_lexical_path()),
   * and an unlink matching either key counts.
   *
   *   A: exec via the alias, unlink via the alias  -> killed (lexical key)
   *   B: exec via the alias, unlink via the real dir -> killed (d_path key)
   *   C: exec via the alias, unlink an unrelated file -> NOT killed
   *
   * C is the control: it proves the kills in A and B come from the
   * self-delete match and not from something else about the setup. */
  {
    static const struct {
      const char *name;   /* file under /tmp/sd_real */
      const char *unlink; /* what the child unlinks */
      int expect_kill;
    } cases[] = {
        {"a", "/tmp/sd_alias/a", 1},
        {"b", "/tmp/sd_real/b", 1},
        {"c", "/tmp/sd_real/c_other", 0},
    };
    int failed = 0;

    if (mkdir("/tmp/sd_real", 0755) != 0)
      die("mkdir /tmp/sd_real");
    if (symlink("/tmp/sd_real", "/tmp/sd_alias") != 0)
      die("symlink /tmp/sd_alias");
    write_file("/tmp/sd_real/c_other", "not the executable\n");

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      char real[64], alias[64];
      int code, sig, saw_record, killed;

      snprintf(real, sizeof(real), "/tmp/sd_real/%s", cases[i].name);
      snprintf(alias, sizeof(alias), "/tmp/sd_alias/%s", cases[i].name);
      copy_file("/init", real);
      killed = run_self_delete_case(alias, real, cases[i].unlink, &code,
                                    &sig, &saw_record);
      outmsg("QEMU_TEST: self-delete case %s: exec %s, unlink %s -> "
             "%s (exit=%d sig=%d, exec record %s)\n",
             cases[i].name, alias, cases[i].unlink,
             killed ? "killed" : "not killed", code, sig,
             saw_record ? "seen" : "not seen in log");
      if (killed != cases[i].expect_kill) {
        outmsg("QEMU_TEST: FAIL: self-delete case %s expected %s\n",
               cases[i].name, cases[i].expect_kill ? "a kill" : "no kill");
        failed = 1;
      } else if (!killed && code != 43) {
        outmsg("QEMU_TEST: FAIL: self-delete control case %s exited %d, "
               "not 43 - the helper itself broke (44 = sync read, "
               "45 = unlink)\n",
               cases[i].name, code);
        failed = 1;
      }
    }
    if (!failed) {
      const char *log = read_kernel_log();

      if (!strstr(log, "path=\"/tmp/sd_alias/a\" reason=\"self-deleting "
                       "binary") ||
          !strstr(log, "path=\"/tmp/sd_real/b\" reason=\"self-deleting "
                       "binary")) {
        outmsg("QEMU_TEST: FAIL: self-delete kills happened but dmesg is "
               "missing a reason=\"self-deleting binary\" line for them\n");
        failed = 1;
      }
    }
    if (failed) {
      outmsg("QEMU_TEST: --- dmesg dump ---\n%s\n", read_kernel_log());
      reboot(RB_POWER_OFF);
      return 1;
    }
  }
  outmsg("QEMU_TEST: self-delete correlation check passed\n");

  pass_and_poweroff();
  return 0; /* unreached */
}
