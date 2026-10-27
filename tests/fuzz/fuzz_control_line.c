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
 *     replies for everything else. QUARANTINE RESTORE / DELETE lines go
 *     through this peer first and must be refused.
 *   - a root peer, only for QUARANTINE RESTORE / DELETE lines, after the
 *     refusal above. Those are the verbs where a hostile id could escape
 *     the quarantine directory, so they are driven against a real, freshly
 *     seeded quarantine entry in a private temp directory. The token @ID@
 *     in the input is replaced with that entry's real id so the fuzzer can
 *     reach the success paths. After every such call a sentinel file next
 *     to the quarantine directory must still exist, and the file a restore
 *     moved back out is removed so a long run cannot fill the disk.
 *
 * Every reply is read back and checked against the protocol in
 * docs/avd-socket-protocol.md (OK/ERR framing, the exact refusal and
 * invalid-id errors, no rows belonging to other uids), not discarded.
 * The "unprivileged" uid is 1000 when running as root; rootless runs (CI)
 * use the runner's own uid and gid, because fchown() to anyone else fails
 * there and the seeded entry would then be hidden from the peer.
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

/* The unprivileged peer's identity, chosen in LLVMFuzzerInitialize(). */
static uid_t peer_uid;
static gid_t peer_gid;

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
static char last_orig[PATH_MAX]; /* where the last seed lived before quarantine */
static bool seed_visible;        /* the last seed is owned by the peer */

/* A successful QUARANTINE RESTORE moves the seed back to its original
 * path. Remove it, or each run of a restore input leaves one more file
 * behind until the process exits. Harmless when it is already gone. */
static void forget_orig(void) {
  if (last_orig[0]) {
    unlink(last_orig);
    last_orig[0] = '\0';
  }
}

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
/* A second quarantine entry owned by root, so QUARANTINE LIST has
 * something it must hide from the unprivileged peer. Only possible as root
 * (the peer is root-distinct then); rootless every entry is the peer's. */
static void seed_foreign(void) {
  char path[PATH_MAX];
  int fd;

  if (geteuid() != 0)
    return;
  snprintf(path, sizeof(path), "%s/foreign_%u.bin", work_dir, entry_counter++);
  fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0644);
  if (fd < 0)
    return;
  if (write(fd, "foreign", 7) == 7) {
    close(fd);
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
      quarantine_file(fd, path, "Foreign_Rule", "ab");
      close(fd);
    }
  } else {
    close(fd);
  }
  unlink(path);
}

static int seed_entry(char *id_out, size_t id_len) {
  char orig[PATH_MAX];
  DIR *d;
  struct dirent *e;
  struct stat created, reopened;
  int fd, found = 0;

  forget_orig();
  seed_visible = false;
  wipe_quarantine();
  seed_foreign();
  snprintf(orig, sizeof(orig), "%s/orig_%u.bin", work_dir, entry_counter++);
  snprintf(last_orig, sizeof(last_orig), "%s", orig);
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
  seed_visible = fchown(fd, peer_uid, peer_gid) == 0;
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
    if (e->d_name[0] == '.' || strstr(e->d_name, "foreign_"))
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

  peer_uid = geteuid() == 0 ? FUZZ_UNPRIV_UID : geteuid();
  peer_gid = geteuid() == 0 ? FUZZ_UNPRIV_UID : getegid();

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
  record_verdict_history(100, peer_uid, "/tmp/a b\tc", "", 0, "", 0, false);
  /* Rows owned by other uids: the peer must never see these. */
  record_verdict_history(101, 0, "/tmp/evil\nname",
                         "0123456789abcdef0123456789abcdef0123456789abcdef"
                         "0123456789abcdef",
                         1, "Rule,With,Commas", 120, true);
  record_verdict_history(102, (uid_t)-1, "/x", "deadbeef", 1, "R", 5, true);
  return 0;
}

static char reply[1 << 20]; /* one reply at a time; fuzzing is single-threaded */

/* Run one line through handle_control_line() over a socketpair, and leave
 * everything it wrote, NUL-terminated, in `reply`. */
static void dispatch(const char *line, uid_t uid, bool is_root) {
  int sv[2];
  struct timeval tv = {.tv_sec = 0, .tv_usec = 50000};
  int sndbuf = 1 << 20;
  size_t len = 0;
  ssize_t n;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    abort();
  setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  fcntl(sv[1], F_SETFL, O_NONBLOCK);

  handle_control_line(sv[0], line, uid, is_root);

  /* Closing the server end makes the read below end at EOF. */
  close(sv[0]);
  while ((n = read(sv[1], reply + len, sizeof(reply) - 1 - len)) > 0)
    len += (size_t)n;
  REQUIRE(len < sizeof(reply) - 1); /* a truncated reply would blind the checks */
  reply[len] = '\0';
  close(sv[1]);
}

static bool starts(const char *s, const char *prefix) {
  return !strncmp(s, prefix, strlen(prefix));
}

/* Every reply opens with "OK\n" or "ERR " (docs/avd-socket-protocol.md). */
static void check_framing(void) {
  REQUIRE(starts(reply, "OK\n") || starts(reply, "ERR "));
}

/* The row count of an "OK\nCOUNT <n>\n" data reply. */
static long reply_count(void) {
  REQUIRE(starts(reply, "OK\nCOUNT "));
  return strtol(reply + sizeof("OK\nCOUNT ") - 1, NULL, 10);
}

/* What the unprivileged peer must get back for `line`. */
static void check_peer_reply(const char *line, bool seeded) {
  check_framing();
  if (PREFIX_MATCH(line, "QUARANTINE RESTORE ") ||
      PREFIX_MATCH(line, "QUARANTINE DELETE ") || PREFIX_MATCH(line, "SCAN ")) {
    REQUIRE(starts(reply, "ERR permission denied"));
  } else if (!strcmp(line, "STATUS")) {
    REQUIRE(starts(reply, "OK\nCOUNT 1\n"));
  } else if (PREFIX_MATCH(line, "VERDICTS RECENT ")) {
    unsigned long n;

    if (!parse_verdicts_count(line + sizeof("VERDICTS RECENT ") - 1, &n)) {
      REQUIRE(starts(reply, "ERR malformed VERDICTS RECENT"));
    } else {
      /* Only the one row the peer owns; never another uid's. */
      REQUIRE(reply_count() <= 1);
      REQUIRE(!strstr(reply, "evil") && !strstr(reply, "Rule,With,Commas") &&
              !strstr(reply, "deadbeef"));
    }
  } else if (!strcmp(line, "QUARANTINE LIST")) {
    /* The seeded entry belongs to the peer, so it must be listed, exactly
     * once. If the seed could not be handed to the peer it must be hidden. */
    if (seeded)
      REQUIRE(reply_count() == (seed_visible ? 1 : 0));
  } else {
    REQUIRE(starts(reply, "ERR unknown command"));
  }
}

/* What the root peer must get back for a RESTORE/DELETE of `arg`. */
static void check_root_reply(const char *arg, const char *id, bool seeded,
                             bool is_restore) {
  check_framing();
  if (!quarantine_id_valid(arg))
    REQUIRE(!strcmp(reply, "ERR invalid id\n"));
  else if (strlen(arg) + sizeof(".quarantined.meta") > NAME_MAX) {
    /* The metadata name no longer fits one path component, so RESTORE
     * cannot read it. DELETE only needs "<id>.quarantined": if that fits
     * and is absent, ENOENT is success; if not, unlink fails. Checked
     * rootless too: neither path needs to reopen a mode-000 file. */
    if (is_restore || strlen(arg) + sizeof(".quarantined") - 1 > NAME_MAX)
      REQUIRE(starts(reply, "ERR "));
    else
      REQUIRE(!strcmp(reply, "OK\n"));
  } else if (geteuid() != 0) {
    /* Rootless: RESTORE cannot reopen mode-000 files, so only its seeded
     * success check is skipped. DELETE just unlinks inside the private
     * quarantine directory, and a missing id has no metadata either way. */
    if (!is_restore)
      REQUIRE(!strcmp(reply, "OK\n"));
    else if (!(seeded && !strcmp(arg, id)))
      REQUIRE(starts(reply, "ERR no metadata for this id"));
    return;
  }
  else if (seeded && !strcmp(arg, id))
    REQUIRE(!strcmp(reply, "OK\n")); /* the real entry restores/deletes */
  else if (is_restore)
    /* The private quarantine directory holds only the seeded entry (and a
     * root-owned one with an unguessable id), so any other valid id has no
     * metadata. */
    REQUIRE(starts(reply, "ERR no metadata for this id"));
  else
    /* DELETE is idempotent: a missing entry (ENOENT) is not an error. */
    REQUIRE(!strcmp(reply, "OK\n"));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char line[AVD_SOCK_LINE_MAX];
  char expanded[AVD_SOCK_LINE_MAX];
  char id[NAME_MAX + 1] = "";
  bool seeded = false;
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
    const char *at = strstr(line, "@ID@");

    seeded = seed_entry(id, sizeof(id)) == 0;
    if (seeded && at) {
      /* Substitute the real id for the first @ID@ token. */
      int n = snprintf(expanded, sizeof(expanded), "%.*s%s%s", (int)(at - line),
                       line, id, at + 4);
      if (n > 0 && (size_t)n < sizeof(expanded))
        memcpy(line, expanded, (size_t)n + 1);
    }
  }

  /* Everyone goes through the unprivileged peer first. For RESTORE/DELETE
   * that is the permission check; it must refuse before the root peer runs
   * the same line against the real entry. */
  dispatch(line, peer_uid, false);
  check_peer_reply(line, seeded);

  if (PREFIX_MATCH(line, "QUARANTINE RESTORE ") ||
      PREFIX_MATCH(line, "QUARANTINE DELETE ")) {
    const char *arg =
        line + (PREFIX_MATCH(line, "QUARANTINE RESTORE ")
                    ? sizeof("QUARANTINE RESTORE ") - 1
                    : sizeof("QUARANTINE DELETE ") - 1);

    /* Refused, so nothing may have been touched yet. */
    REQUIRE(access(sentinel_path, F_OK) == 0);
    dispatch(line, 0, true);
    check_root_reply(arg, id, seeded, PREFIX_MATCH(line, "QUARANTINE RESTORE "));
    /* Whatever id the fuzzer sent, nothing outside the quarantine
     * directory may have been moved or removed. */
    REQUIRE(access(sentinel_path, F_OK) == 0);
  }
  forget_orig();
  return 0;
}
