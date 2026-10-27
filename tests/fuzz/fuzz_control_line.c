/*
 * fuzz_control_line.c - libFuzzer target for avd's control-socket command
 * dispatcher, handle_control_line() (#105). Includes userspace/avd/avd.c
 * itself (main renamed) so the real dispatcher and every cmd_* handler it
 * reaches run under ASan/UBSan, with no daemon, netlink or kernel module.
 *
 * Two peers are modelled:
 *
 *   - an unprivileged peer (is_root = false) for every input. This is the
 *     surface any local user with access to the socket gets: STATUS,
 *     VERDICTS RECENT <n>, QUARANTINE LIST, and the permission-denied
 *     replies for everything else.
 *   - a root peer, only for QUARANTINE RESTORE / DELETE lines. Those are
 *     the verbs where a hostile id could escape the quarantine directory,
 *     so they are driven against a real, freshly seeded quarantine entry
 *     in a private temp directory. The token @ID@ in the input is replaced
 *     with that entry's real id so the fuzzer can reach the success paths.
 *     After every such call a sentinel file next to the quarantine
 *     directory must still exist.
 *
 * SCAN is deliberately only exercised as the unprivileged (denied) peer:
 * a root SCAN would open whatever path the fuzzer invents, including
 * /proc/kcore-style files that never finish hashing.
 *
 * Build and run through tests/fuzz/Makefile.
 */
#define _GNU_SOURCE
#define main avd_real_main
#include "avd.c"
#undef main

#include <ftw.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#define FUZZ_UNPRIV_UID 1000

#define REQUIRE(cond)                                                          \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "contract violated: %s (%s:%d)\n", #cond, __FILE__,      \
              __LINE__);                                                       \
      abort();                                                                 \
    }                                                                          \
  } while (0)

static char work_dir[PATH_MAX];
static char qdir_path[PATH_MAX];
static char sentinel_path[PATH_MAX];
static unsigned entry_counter;

/* Remove everything in the quarantine directory (not the directory). */
static void wipe_quarantine(void) {
  DIR *d = opendir(qdir_path);
  struct dirent *e;
  char p[PATH_MAX];

  if (!d)
    return;
  while ((e = readdir(d))) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
      continue;
    snprintf(p, sizeof(p), "%s/%s", qdir_path, e->d_name);
    unlink(p);
  }
  closedir(d);
}

/* Quarantine a fresh file the way a real conviction does and return the
 * resulting id (the file's basename inside the quarantine directory). */
static int seed_entry(char *id_out, size_t id_len) {
  char orig[PATH_MAX];
  DIR *d;
  struct dirent *e;
  struct stat created, reopened;
  int fd, found = 0;

  wipe_quarantine();
  snprintf(orig, sizeof(orig), "%s/orig_%u.bin", work_dir, entry_counter++);
  /* O_EXCL | O_NOFOLLOW: always a brand-new regular file, never one that
   * already existed or a symlink planted at the name. The directory is a
   * private mkdtemp tree, so this is belt and braces, but every later step
   * works on this descriptor rather than re-resolving the name. */
  fd = open(orig, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0644);
  if (fd < 0)
    return -1;
  if (write(fd, "payload", 7) != 7 || fstat(fd, &created) != 0) {
    close(fd);
    return -1;
  }
  /* Owned by the unprivileged peer so QUARANTINE LIST shows it to them.
   * fchown() on the open descriptor, not chown() on the name, so it cannot
   * land on whatever the name resolves to by then. */
  if (fchown(fd, FUZZ_UNPRIV_UID, FUZZ_UNPRIV_UID) != 0) {
    /* not root: the entry is simply invisible to the unprivileged peer */
  }
  close(fd);
  /* The scan path hands quarantine_file() a read-only descriptor, so reopen
   * read-only, and confirm it is the very file created above. */
  fd = open(orig, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return -1;
  if (fstat(fd, &reopened) != 0 || reopened.st_dev != created.st_dev ||
      reopened.st_ino != created.st_ino) {
    close(fd);
    return -1;
  }
  quarantine_file(fd, orig, "Fuzz_Rule",
                  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                  "abcdef");
  close(fd);

  d = opendir(qdir_path);
  if (!d)
    return -1;
  while ((e = readdir(d))) {
    size_t l = strlen(e->d_name);
    if (e->d_name[0] == '.')
      continue;
    if (l > 5 && !strcmp(e->d_name + l - 5, ".meta"))
      continue;
    /* The id QUARANTINE LIST reports and RESTORE/DELETE accept is the
     * basename without the ".quarantined" suffix; the handlers re-append
     * it themselves. */
    if (l > sizeof(".quarantined") - 1 &&
        !strcmp(e->d_name + l - (sizeof(".quarantined") - 1), ".quarantined")) {
      snprintf(id_out, id_len, "%.*s",
               (int)(l - (sizeof(".quarantined") - 1)), e->d_name);
      found = 1;
      break;
    }
  }
  closedir(d);
  return found ? 0 : -1;
}

static int rm_entry(const char *path, const struct stat *sb, int type,
                    struct FTW *ftw) {
  (void)sb;
  (void)type;
  (void)ftw;
  return remove(path);
}

/* Each process makes one private temp tree; don't leave it behind. */
static void cleanup_work_dir(void) {
  if (work_dir[0])
    nftw(work_dir, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  int fd;
  char p[PATH_MAX];

  (void)argc;
  (void)argv;
  signal(SIGPIPE, SIG_IGN);

  snprintf(work_dir, sizeof(work_dir), "%s/av_fuzz_ctl.XXXXXX",
           getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
  if (!mkdtemp(work_dir)) {
    perror("mkdtemp");
    exit(2);
  }
  atexit(cleanup_work_dir);
  snprintf(qdir_path, sizeof(qdir_path), "%s/q", work_dir);
  snprintf(sentinel_path, sizeof(sentinel_path), "%s/sentinel.quarantined",
           work_dir);
  fd = open(sentinel_path, O_CREAT | O_WRONLY, 0600);
  if (fd >= 0)
    close(fd);
  snprintf(p, sizeof(p), "%s.meta", sentinel_path);
  fd = open(p, O_CREAT | O_WRONLY, 0600);
  if (fd >= 0)
    close(fd);

  quarantine_dir = qdir_path;
  if (ensure_quarantine_dir() != 0) {
    fprintf(stderr, "could not prepare quarantine dir %s\n", qdir_path);
    exit(2);
  }

  /* A few history rows so VERDICTS RECENT has something to format,
   * including fields a hostile file name could put there. */
  record_verdict_history(100, FUZZ_UNPRIV_UID, "/tmp/a b\tc", "", 0, "", 0,
                         false);
  record_verdict_history(101, 0, "/tmp/evil\nname",
                         "0123456789abcdef0123456789abcdef0123456789abcdef"
                         "0123456789abcdef",
                         1, "Rule,With,Commas", 120, true);
  record_verdict_history(102, (uid_t)-1, "/x", "deadbeef", 1, "R", 5, true);
  return 0;
}

static void drain(int fd) {
  char buf[4096];

  while (read(fd, buf, sizeof(buf)) > 0)
    ;
}

/* Run one line through handle_control_line() over a socketpair. */
static void dispatch(const char *line, uid_t uid, bool is_root) {
  int sv[2];
  struct timeval tv = {.tv_sec = 0, .tv_usec = 50000};
  int sndbuf = 1 << 20;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    abort();
  setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  fcntl(sv[1], F_SETFL, O_NONBLOCK);

  handle_control_line(sv[0], line, uid, is_root);

  drain(sv[1]);
  close(sv[0]);
  close(sv[1]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char line[AVD_SOCK_LINE_MAX];
  char expanded[AVD_SOCK_LINE_MAX];
  size_t len, i;

  len = size < sizeof(line) - 1 ? size : sizeof(line) - 1;
  memcpy(line, data, len);
  line[len] = '\0';
  /* read_line() never hands the dispatcher a newline, and the dispatcher
   * only ever sees a C string. */
  for (i = 0; i < len; i++) {
    if (line[i] == '\n') {
      line[i] = '\0';
      break;
    }
  }

  if (PREFIX_MATCH(line, "QUARANTINE ") ||
      PREFIX_MATCH(line, "VERDICTS RECENT ")) {
    char id[NAME_MAX + 1] = "";
    const char *at = strstr(line, "@ID@");

    if (seed_entry(id, sizeof(id)) == 0 && at) {
      /* Substitute the real id for the first @ID@ token. */
      int n = snprintf(expanded, sizeof(expanded), "%.*s%s%s", (int)(at - line),
                       line, id, at + 4);
      if (n > 0 && (size_t)n < sizeof(expanded))
        memcpy(line, expanded, (size_t)n + 1);
    }
    if (PREFIX_MATCH(line, "QUARANTINE RESTORE ") ||
        PREFIX_MATCH(line, "QUARANTINE DELETE ")) {
      dispatch(line, 0, true);
      /* Whatever id the fuzzer sent, nothing outside the quarantine
       * directory may have been moved or removed. */
      REQUIRE(access(sentinel_path, F_OK) == 0);
      return 0;
    }
  }

  dispatch(line, FUZZ_UNPRIV_UID, false);
  return 0;
}
