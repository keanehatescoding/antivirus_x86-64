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

/* av.ko's test-only knob that parks each deferred exec work item before
 * it d_path()s and hashes the file (see av_toctou_test_delay_ms in
 * av/main.c). Used only by the unlinked-before-d_path() self-delete
 * cases, and reset to 0 right after them. */
#define TOCTOU_DELAY_PARAM "/sys/module/av/parameters/av_toctou_test_delay_ms"

/* Set an integer sysfs/module-param attribute. No O_CREAT/O_TRUNC: the
 * target is an existing kernel attribute, and a failure to open it is a
 * real error worth reporting distinctly - most likely av.ko was built
 * without the test-only knob, or sysfs was not mounted. */
static void write_param_int(const char *path, int val) {
  char buf[16];
  int fd = open(path, O_WRONLY);
  int n;

  if (fd < 0)
    die("open module param (av.ko without the toctou test knob?)");
  n = snprintf(buf, sizeof(buf), "%d", val);
  if (n < 0 || (size_t)n >= sizeof(buf)) {
    close(fd);
    die("format module param value");
  }
  if (write(fd, buf, (size_t)n) != n) {
    close(fd);
    die("write module param");
  }
  close(fd);
}

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

/* Execs `exec_path` (a copy of /init) in `mode` (--self-unlink or
 * --self-unlink-early, see main()), lets it unlink `unlink_path` once
 * av.ko has recorded the exec (calling `on_record` first, if non-NULL
 * and the record was seen), and reports how it ended. `recorded_path` is the d_path() av.ko logs for the
 * exec (symlinks followed); its event=clean line for this pid is the
 * signal that av_behavior_record_exec() has run, since av_work_fn()
 * records before it logs. That line is ratelimited, so if it never
 * shows the case proceeds after SELF_DELETE_RECORD_WAIT_MS anyway -
 * an unscanned exec would leave no record and fail the kill
 * assertion, not pass it. Returns 1 if the child was SIGKILLed. */
#define SELF_DELETE_RECORD_WAIT_MS 5000
/* av_toctou_test_delay_ms for the unlinked-before-d_path() self-delete
 * cases: long enough that the child's own unlink (its first syscall
 * after exec) always beats the parked work item's d_path(). */
#define SELF_DELETE_EARLY_DELAY_MS 500
/* Attempts per unlinked-before-d_path() case: the fixed delay makes
 * the "(deleted)" record overwhelmingly likely, but only that log line
 * proves the ordering, so a run without it is retried, never counted. */
#define SELF_DELETE_EARLY_ATTEMPTS 3
/* Set around a run_self_delete_case() call to chroot() the child (and
 * chdir() it to the new "/") before it execs: exec_path and the unlink
 * path are then spelled from inside that root. Cases R and S. */
static const char *sd_chroot_dir;

static int run_self_delete_case(const char *exec_path, const char *mode,
                                const char *recorded_path,
                                const char *unlink_path,
                                void (*on_record)(void), int *exit_code,
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
    char *const cargv[] = {(char *)exec_path, (char *)mode,
                           (char *)unlink_path, NULL};

    close(sync_fd[1]);
    if (sync_fd[0] != 3) {
      if (dup2(sync_fd[0], 3) < 0)
        _exit(126);
      close(sync_fd[0]);
    }
    if (sd_chroot_dir && (chroot(sd_chroot_dir) != 0 || chdir("/") != 0))
      _exit(125);
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
  /* Between the record and the child's unlink: case G's retarget. */
  if (on_record && *saw_record)
    on_record();

  /* EPIPE means the child is already gone: in D/E the helper's first
   * unlink is checked on an unbound workqueue and can land after the
   * record, killing the child before this write - a correct detection,
   * judged by the wait and the caller's assertions below like any
   * other. (pid 1 never takes SIGPIPE's default action, so the write
   * returns the error rather than killing init.) */
  if (write(sync_fd[1], "x", 1) != 1 && errno != EPIPE)
    die("write(self-delete sync)");
  close(sync_fd[1]);
  wait_for_exit(pid, 15000, exit_code, term_sig);
  return *term_sig == SIGKILL;
}

/* Case G's on_record hook: re-point /tmp/sd_ralias from /tmp/sd_real
 * to /tmp/sd_other after av.ko has recorded the exec through it. */
static void retarget_sd_ralias(void) {
  if (unlink("/tmp/sd_ralias") != 0)
    die("unlink /tmp/sd_ralias");
  if (symlink("/tmp/sd_other", "/tmp/sd_ralias") != 0)
    die("symlink /tmp/sd_ralias -> /tmp/sd_other");
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
  /* Same, for the unlinked-before-d_path() cases: unlink argv[2] (this
   * image) straight away, while av.ko's exec work item is parked by
   * av_toctou_test_delay_ms, so d_path() later renders it with the
   * " (deleted)" suffix. That first unlink's check runs before the exec
   * is recorded and cannot match anything. Once the parent has seen the
   * record, unlink the same name again: av.ko's unlink hook fires at
   * syscall entry whatever the outcome (ENOENT here), so this is the
   * check-after-record ordering the fix is about, made deterministic. */
  if (argc > 2 && !strcmp(argv[1], "--self-unlink-early")) {
    char c;

    if (unlink(argv[2]) != 0)
      _exit(45);
    if (read(3, &c, 1) != 1)
      _exit(44);
    (void)unlink(argv[2]);
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
  /* For TOCTOU_DELAY_PARAM. The initramfs ships an empty /sys. */
  if (mount("sysfs", "/sys", "sysfs", 0, NULL) != 0 && errno != EBUSY)
    die("mount /sys");

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
      killed = run_self_delete_case(alias, "--self-unlink", real,
                                    cases[i].unlink, NULL, &code, &sig,
                                    &saw_record);
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
    /* Image unlinked before av.ko's d_path() (CodeRabbit on #110).
     * d_path() of an unlinked dentry ends in " (deleted)", so before the
     * fix the d_path() key was recorded with that suffix and the lexical
     * key was dropped on its final-component check ("d" vs
     * "d (deleted)"): an unlink check running after the record matched
     * neither. The delay knob parks the exec work item before d_path()
     * so the child's own unlink lands first. Only the "(deleted)" record
     * line proves it did, so an attempt without it is retried (up to
     * SELF_DELETE_EARLY_ATTEMPTS) and a case that never shows it fails:
     * a kill against a plain-path record would not test the stripping.
     *
     *   D: exec via the alias, unlink via the alias -> killed (lexical key)
     *   E: exec via the alias, unlink via the real dir -> killed (d_path key)
     *
     * Case C above stays the control for these too. */
    if (!failed) {
      static const struct {
        const char *name;
        const char *unlink;
      } early[] = {
          {"d", "/tmp/sd_alias/d"},
          {"e", "/tmp/sd_real/e"},
      };

      write_param_int(TOCTOU_DELAY_PARAM, SELF_DELETE_EARLY_DELAY_MS);
      for (size_t i = 0; i < sizeof(early) / sizeof(early[0]); i++) {
        char real[64], alias[64], recorded[80], reason_line[128];
        int code, sig, saw_record, killed;

        snprintf(real, sizeof(real), "/tmp/sd_real/%s", early[i].name);
        snprintf(alias, sizeof(alias), "/tmp/sd_alias/%s", early[i].name);
        snprintf(recorded, sizeof(recorded), "%s (deleted)", real);
        for (int attempt = 0; attempt < SELF_DELETE_EARLY_ATTEMPTS;
             attempt++) {
          copy_file("/init", real);
          killed = run_self_delete_case(alias, "--self-unlink-early",
                                        recorded, early[i].unlink, NULL,
                                        &code, &sig, &saw_record);
          if (saw_record)
            break;
          outmsg("QEMU_TEST: self-delete case %s attempt %d: no \"%s\" "
                 "record, retrying\n",
                 early[i].name, attempt + 1, recorded);
        }
        outmsg("QEMU_TEST: self-delete case %s (unlinked before d_path): "
               "exec %s, unlink %s -> %s (exit=%d sig=%d, \"(deleted)\" "
               "record %s)\n",
               early[i].name, alias, early[i].unlink,
               killed ? "killed" : "not killed", code, sig,
               saw_record ? "seen" : "not seen in log");
        snprintf(reason_line, sizeof(reason_line),
                 "path=\"%s\" reason=\"self-deleting binary", early[i].unlink);
        if (!saw_record) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s never logged the "
                 "\"%s\" record in %d attempts - the unlink-before-d_path() "
                 "ordering it tests was not reached\n",
                 early[i].name, recorded, SELF_DELETE_EARLY_ATTEMPTS);
          failed = 1;
        } else if (!killed) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s expected a kill%s\n",
                 early[i].name,
                 code == 45 ? " (helper's first unlink failed)" : "");
          failed = 1;
        } else if (!strstr(read_kernel_log(), reason_line)) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s was killed but dmesg "
                 "has no %s\" line\n",
                 early[i].name, reason_line);
          failed = 1;
        }
      }
      write_param_int(TOCTOU_DELAY_PARAM, 0);
    }
    /* F: exec through a symlink to the FILE whose name matches the
     * target's (/tmp/sd_flink/f -> /tmp/sd_real/f, /tmp/sd_flink a real
     * directory), then unlink that symlink -> NOT killed. Unlinking it
     * leaves the executable alone, but a lexical key accepted on
     * "same basename" alone matched it and killed (CodeRabbit on x86
     * #229). av.ko now accepts that key only when its directory
     * resolves to the executed file's own directory. */
    if (!failed) {
      int code, sig, saw_record, killed;

      if (mkdir("/tmp/sd_flink", 0755) != 0)
        die("mkdir /tmp/sd_flink");
      copy_file("/init", "/tmp/sd_real/f");
      if (symlink("/tmp/sd_real/f", "/tmp/sd_flink/f") != 0)
        die("symlink /tmp/sd_flink/f");
      killed = run_self_delete_case("/tmp/sd_flink/f", "--self-unlink",
                                    "/tmp/sd_real/f", "/tmp/sd_flink/f",
                                    NULL, &code, &sig, &saw_record);
      outmsg("QEMU_TEST: self-delete case f (file symlink, same name): "
             "exec /tmp/sd_flink/f, unlink /tmp/sd_flink/f -> %s "
             "(exit=%d sig=%d, exec record %s)\n",
             killed ? "killed" : "not killed", code, sig,
             saw_record ? "seen" : "not seen in log");
      /* Without the record the unlink ran before av.ko knew the exec,
       * and "not killed" would hold whatever the key logic did. */
      if (!saw_record || killed || code != 43) {
        outmsg("QEMU_TEST: FAIL: self-delete case f expected a seen exec "
               "record, no kill and exit 43 (44 = sync read, 45 = "
               "unlink)\n");
        failed = 1;
      }
    }
    /* G: exec through a directory alias, then point the alias somewhere
     * else before unlinking through it -> NOT killed. /tmp/sd_ralias ->
     * /tmp/sd_real at exec, so the lexical key "/tmp/sd_ralias/g" is
     * recorded; once the record exists the parent re-points the alias
     * at /tmp/sd_other, which holds its own "g", and the child's unlink
     * removes that one. The name still hashes the same, so before the
     * unlink-time directory check this killed a process whose image was
     * untouched (CodeRabbit on #229). */
    if (!failed) {
      int code, sig, saw_record, killed;
      struct stat st;

      if (mkdir("/tmp/sd_other", 0755) != 0)
        die("mkdir /tmp/sd_other");
      if (symlink("/tmp/sd_real", "/tmp/sd_ralias") != 0)
        die("symlink /tmp/sd_ralias");
      copy_file("/init", "/tmp/sd_real/g");
      copy_file("/init", "/tmp/sd_other/g");
      killed = run_self_delete_case("/tmp/sd_ralias/g", "--self-unlink",
                                    "/tmp/sd_real/g", "/tmp/sd_ralias/g",
                                    retarget_sd_ralias, &code, &sig,
                                    &saw_record);
      outmsg("QEMU_TEST: self-delete case g (alias retargeted after exec): "
             "exec /tmp/sd_ralias/g, alias -> /tmp/sd_other, unlink "
             "/tmp/sd_ralias/g -> %s (exit=%d sig=%d, exec record %s)\n",
             killed ? "killed" : "not killed", code, sig,
             saw_record ? "seen" : "not seen in log");
      if (!saw_record || killed || code != 43) {
        outmsg("QEMU_TEST: FAIL: self-delete case g expected a seen exec "
               "record, no kill and exit 43 (44 = sync read, 45 = "
               "unlink)\n");
        failed = 1;
      } else if (stat("/tmp/sd_real/g", &st) != 0 ||
                 stat("/tmp/sd_other/g", &st) == 0) {
        outmsg("QEMU_TEST: FAIL: self-delete case g's unlink did not "
               "remove /tmp/sd_other/g and leave /tmp/sd_real/g - the "
               "retarget did not take effect\n");
        failed = 1;
      }
    }
    /* H: exec through a directory symlink, then unlink through that
     * symlink followed by ".." -> NOT killed. /tmp/sd_hx/link ->
     * /tmp/sd_hy/sub; the child execs /tmp/sd_hx/link/h and unlinks
     * /tmp/sd_hx/link/../link/h. That collapses lexically to the exec's
     * key, but the kernel follows the link before the "..", so the
     * unlink removes /tmp/sd_hy/link/h and the image is untouched.
     * Checking the collapsed name's directory found /tmp/sd_hy/sub and
     * killed (CodeRabbit on x86 #229); the check now walks the
     * spelling the syscall walked. */
    if (!failed) {
      int code, sig, saw_record, killed;
      struct stat st;

      if (mkdir("/tmp/sd_hx", 0755) != 0 || mkdir("/tmp/sd_hy", 0755) != 0 ||
          mkdir("/tmp/sd_hy/sub", 0755) != 0 ||
          mkdir("/tmp/sd_hy/link", 0755) != 0)
        die("mkdir case h dirs");
      if (symlink("/tmp/sd_hy/sub", "/tmp/sd_hx/link") != 0)
        die("symlink /tmp/sd_hx/link");
      copy_file("/init", "/tmp/sd_hy/sub/h");
      copy_file("/init", "/tmp/sd_hy/link/h");
      killed = run_self_delete_case("/tmp/sd_hx/link/h", "--self-unlink",
                                    "/tmp/sd_hy/sub/h",
                                    "/tmp/sd_hx/link/../link/h", NULL, &code,
                                    &sig, &saw_record);
      outmsg("QEMU_TEST: self-delete case h (\"..\" after a dir symlink): "
             "exec /tmp/sd_hx/link/h, unlink /tmp/sd_hx/link/../link/h -> "
             "%s (exit=%d sig=%d, exec record %s)\n",
             killed ? "killed" : "not killed", code, sig,
             saw_record ? "seen" : "not seen in log");
      if (!saw_record || killed || code != 43) {
        outmsg("QEMU_TEST: FAIL: self-delete case h expected a seen exec "
               "record, no kill and exit 43 (44 = sync read, 45 = "
               "unlink)\n");
        failed = 1;
      } else if (stat("/tmp/sd_hy/sub/h", &st) != 0 ||
                 stat("/tmp/sd_hy/link/h", &st) == 0) {
        outmsg("QEMU_TEST: FAIL: self-delete case h's unlink did not "
               "remove /tmp/sd_hy/link/h and leave /tmp/sd_hy/sub/h - the "
               "\"..\" did not resolve physically\n");
        failed = 1;
      }
    }
    /* R/S: a chroot()ed task (CodeRabbit on x86 #229). Root
     * /tmp/sd_j, inside which /tmp/sd_j/alias -> real, so the task's
     * own "/tmp/sd_j/alias/<x>" is the host's
     * /tmp/sd_j/tmp/sd_j/real/<x> - the image. The host's
     * /tmp/sd_j/alias/<x>, the task's "/alias/<x>", is a different
     * file. Each child execs "/tmp/sd_j/alias/<x>" from inside the
     * chroot and unlinks relative to its "/".
     *
     *   R: unlink "alias/r" -> the unrelated host /tmp/sd_j/alias/r ->
     *      NOT killed. Spelling the relative unlink from this worker's
     *      root gave "/tmp/sd_j/alias/r", the exec's lexical key, and
     *      the directory check (from the task's root) then found the
     *      image's directory and killed.
     *   S: unlink "tmp/sd_j/alias/s" -> the image -> killed. Spelled
     *      from the worker's root that was "/tmp/sd_j/tmp/sd_j/alias/s",
     *      which matched neither key. */
    if (!failed) {
      static const struct {
        const char *name, *unlink, *survivor, *gone;
        int expect_kill;
      } jc[] = {
          {"r", "alias/r", "/tmp/sd_j/tmp/sd_j/real/r", "/tmp/sd_j/alias/r",
           0},
          {"s", "tmp/sd_j/alias/s", NULL, "/tmp/sd_j/tmp/sd_j/real/s", 1},
      };

      if (mkdir("/tmp/sd_j", 0755) != 0 || mkdir("/tmp/sd_j/alias", 0755) != 0 ||
          mkdir("/tmp/sd_j/tmp", 0755) != 0 ||
          mkdir("/tmp/sd_j/tmp/sd_j", 0755) != 0 ||
          mkdir("/tmp/sd_j/tmp/sd_j/real", 0755) != 0)
        die("mkdir case r/s dirs");
      if (symlink("real", "/tmp/sd_j/tmp/sd_j/alias") != 0)
        die("symlink /tmp/sd_j/tmp/sd_j/alias");
      for (size_t i = 0; i < sizeof(jc) / sizeof(jc[0]) && !failed; i++) {
        char image[64], exec_in[64], unrelated[64], needle[128];
        int code, sig, saw_record, killed;
        struct stat st;

        snprintf(image, sizeof(image), "/tmp/sd_j/tmp/sd_j/real/%s",
                 jc[i].name);
        snprintf(exec_in, sizeof(exec_in), "/tmp/sd_j/alias/%s", jc[i].name);
        snprintf(unrelated, sizeof(unrelated), "/tmp/sd_j/alias/%s",
                 jc[i].name);
        copy_file("/init", image);
        write_file(unrelated, "not the executable\n");
        sd_chroot_dir = "/tmp/sd_j";
        killed = run_self_delete_case(exec_in, "--self-unlink", image,
                                      jc[i].unlink, NULL, &code, &sig,
                                      &saw_record);
        sd_chroot_dir = NULL;
        outmsg("QEMU_TEST: self-delete case %s (chroot /tmp/sd_j): exec "
               "%s, unlink %s -> %s (exit=%d sig=%d, exec record %s)\n",
               jc[i].name, exec_in, jc[i].unlink,
               killed ? "killed" : "not killed", code, sig,
               saw_record ? "seen" : "not seen in log");
        snprintf(needle, sizeof(needle),
                 "path=\"/tmp/sd_j/tmp/sd_j/alias/%s\" reason=\"self-deleting "
                 "binary",
                 jc[i].name);
        if (!saw_record || killed != jc[i].expect_kill) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s expected a seen exec "
                 "record and %s\n",
                 jc[i].name, jc[i].expect_kill ? "a kill" : "no kill");
          failed = 1;
        } else if (!killed && code != 43) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s exited %d, not 43 "
                 "(44 = sync read, 45 = unlink, 125 = chroot)\n",
                 jc[i].name, code);
          failed = 1;
        } else if (killed && !strstr(read_kernel_log(), needle)) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s was killed but dmesg "
                 "has no %s line\n",
                 jc[i].name, needle);
          failed = 1;
        } else if ((jc[i].survivor && stat(jc[i].survivor, &st) != 0) ||
                   stat(jc[i].gone, &st) == 0) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s's unlink did not "
                 "remove %s%s%s\n",
                 jc[i].name, jc[i].gone,
                 jc[i].survivor ? " and leave " : "",
                 jc[i].survivor ? jc[i].survivor : "");
          failed = 1;
        }
      }
    }
    /* T/U: exec spellings whose lexical key used to be dropped
     * (CodeRabbit on x86 #229). Both must be killed.
     *
     *   T: ".." in the EXEC spelling (case H has it in the unlink).
     *      /tmp/sd_tx/link -> /tmp/sd_ty/sub, so an exec of
     *      /tmp/sd_tx/link/../t runs /tmp/sd_ty/t. The key was checked
     *      collapsed, as /tmp/sd_tx/t, whose directory is not the
     *      image's, and dropped; unlinking the same spelling then
     *      matched neither key.
     *   U: chroot /tmp/sd_u, inside which /tmp/sd_u -> "..", i.e. the
     *      task's own "/". Exec "tmp/sd_u/u" from "/" runs the host's
     *      /tmp/sd_u/u. Its canonical name equals the task-rooted key,
     *      so the key was dropped as redundant, but the unlink of
     *      "tmp/sd_u/u" is /tmp/sd_u/tmp/sd_u/u as this side spells
     *      it, and only the key matches it. */
    if (!failed) {
      static const struct {
        const char *name, *chroot_dir, *exec, *image, *unlink, *kill_path;
      } kc[] = {
          {"t", NULL, "/tmp/sd_tx/link/../t", "/tmp/sd_ty/t",
           "/tmp/sd_tx/link/../t", "/tmp/sd_tx/t"},
          {"u", "/tmp/sd_u", "tmp/sd_u/u", "/tmp/sd_u/u", "tmp/sd_u/u",
           "/tmp/sd_u/tmp/sd_u/u"},
      };

      if (mkdir("/tmp/sd_tx", 0755) != 0 || mkdir("/tmp/sd_ty", 0755) != 0 ||
          mkdir("/tmp/sd_ty/sub", 0755) != 0 ||
          mkdir("/tmp/sd_u", 0755) != 0 || mkdir("/tmp/sd_u/tmp", 0755) != 0)
        die("mkdir case t/u dirs");
      if (symlink("/tmp/sd_ty/sub", "/tmp/sd_tx/link") != 0)
        die("symlink /tmp/sd_tx/link");
      if (symlink("..", "/tmp/sd_u/tmp/sd_u") != 0)
        die("symlink /tmp/sd_u/tmp/sd_u");
      for (size_t i = 0; i < sizeof(kc) / sizeof(kc[0]) && !failed; i++) {
        char needle[128];
        int code, sig, saw_record, killed;
        struct stat st;

        copy_file("/init", kc[i].image);
        sd_chroot_dir = kc[i].chroot_dir;
        killed = run_self_delete_case(kc[i].exec, "--self-unlink",
                                      kc[i].image, kc[i].unlink, NULL, &code,
                                      &sig, &saw_record);
        sd_chroot_dir = NULL;
        outmsg("QEMU_TEST: self-delete case %s%s%s%s: exec %s, unlink %s "
               "-> %s (exit=%d sig=%d, exec record %s)\n",
               kc[i].name, kc[i].chroot_dir ? " (chroot " : "",
               kc[i].chroot_dir ? kc[i].chroot_dir : "",
               kc[i].chroot_dir ? ")" : "", kc[i].exec, kc[i].unlink,
               killed ? "killed" : "not killed", code, sig,
               saw_record ? "seen" : "not seen in log");
        snprintf(needle, sizeof(needle),
                 "path=\"%s\" reason=\"self-deleting binary", kc[i].kill_path);
        if (!saw_record || !killed) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s expected a seen exec "
                 "record and a kill%s\n",
                 kc[i].name,
                 code == 45 ? " (helper's unlink failed)"
                 : code == 125 ? " (chroot failed)"
                               : "");
          failed = 1;
        } else if (!strstr(read_kernel_log(), needle)) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s was killed but dmesg "
                 "has no %s line\n",
                 kc[i].name, needle);
          failed = 1;
        } else if (stat(kc[i].image, &st) == 0) {
          outmsg("QEMU_TEST: FAIL: self-delete case %s's unlink did not "
                 "remove %s\n",
                 kc[i].name, kc[i].image);
          failed = 1;
        }
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
