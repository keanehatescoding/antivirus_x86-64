/*
 * fan_parse.h - parsing helpers for avd's fanotify exec-permission
 * listener (#176): /proc/self/mountinfo lines (which filesystems to
 * mark) and /proc/kernel_av_signatures lines (the signature snapshot
 * avd enforces pre-exec).
 *
 * Same single-source-of-truth arrangement as control_parse.h: avd.c
 * calls these on its live path, and tests/test_fan_parse.sh compiles
 * this same header standalone - so the test exercises the production
 * parser, not a copy. Dependency-free (standard headers only).
 */

#ifndef AV_FAN_PARSE_H
#define AV_FAN_PARSE_H

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Undo mountinfo's octal escaping (\040 space, \011 tab, \012 newline,
 * \134 backslash) in place. Anything that isn't a well-formed
 * three-digit octal escape is copied through untouched rather than
 * rejected - the kernel only ever emits those four, so a malformed one
 * can only come from a corrupted line, and leaving it literal makes
 * the subsequent fanotify_mark() fail on a nonexistent path (logged,
 * skipped) instead of marking something unexpected. */
static inline void fan_unescape_octal(char *s) {
  char *r = s, *w = s;

  while (*r) {
    if (r[0] == '\\' && r[1] >= '0' && r[1] <= '3' && r[2] >= '0' &&
        r[2] <= '7' && r[3] >= '0' && r[3] <= '7') {
      *w++ = (char)(((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
      r += 4;
    } else {
      *w++ = *r++;
    }
  }
  *w = '\0';
}

/* Parses one /proc/self/mountinfo line in place (proc(5) format):
 *
 *   36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw
 *   (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)    (10)  (11)
 *
 * Field 7 is zero or more optional tags terminated by a lone "-", so
 * the fstype is located relative to that separator, not by index.
 * Fills the device numbers, the unescaped mount point (field 5), the
 * filesystem type (field 9) and whether the per-mount options (field
 * 6) include "noexec". Pointers point into `line`. Returns 0 on
 * success, -1 on any malformed line (missing fields, no separator,
 * non-numeric device). */
static inline int fan_mountinfo_parse_line(char *line, unsigned *major_out,
                                           unsigned *minor_out,
                                           char **mountpoint_out,
                                           char **fstype_out,
                                           bool *noexec_out) {
  char *fields[6];
  char *save = NULL;
  char *tok;
  char *end;
  unsigned long maj, min;
  int n = 0;

  /* Exactly six tokens: a for-loop whose increment calls strtok_r()
   * would consume the 7th (the "-" separator, when there are no
   * optional fields) before the bound check stops it. */
  while (n < 6 && (tok = strtok_r(n ? NULL : line, " \n", &save)))
    fields[n++] = tok;
  if (n < 6)
    return -1;

  /* Optional fields until the lone "-" separator; fstype follows. */
  for (tok = strtok_r(NULL, " \n", &save); tok && strcmp(tok, "-") != 0;
       tok = strtok_r(NULL, " \n", &save))
    ;
  if (!tok)
    return -1;
  tok = strtok_r(NULL, " \n", &save);
  if (!tok || !tok[0])
    return -1;

  if (!isdigit((unsigned char)fields[2][0]))
    return -1;
  maj = strtoul(fields[2], &end, 10);
  if (*end != ':' || !isdigit((unsigned char)end[1]))
    return -1;
  min = strtoul(end + 1, &end, 10);
  if (*end != '\0')
    return -1;

  fan_unescape_octal(fields[4]);
  if (fields[4][0] != '/')
    return -1;

  *major_out = (unsigned)maj;
  *minor_out = (unsigned)min;
  *mountpoint_out = fields[4];
  *fstype_out = tok;
  {
    /* Whole-token match only: "noexec" must not also match a
     * hypothetical "noexecfoo". */
    const char *o = fields[5];
    bool noexec = false;

    while (*o) {
      size_t len = strcspn(o, ",");

      if (len == 6 && strncmp(o, "noexec", 6) == 0)
        noexec = true;
      o += len;
      if (*o == ',')
        o++;
    }
    *noexec_out = noexec;
  }
  return 0;
}

/* Whether avd should put a FAN_MARK_FILESYSTEM exec-permission mark on
 * a filesystem of this type. A deny-list of pseudo filesystems (nothing
 * to exec from, or marking them is refused/meaningless) and network /
 * FUSE filesystems (#176 scopes enforcement to local filesystems: a
 * permission event on a remote or userspace-served file puts a network
 * round-trip or another daemon in the path of every exec, and a FUSE
 * server that execs anything would deadlock against us). Everything
 * else - ext4, xfs, btrfs, f2fs, vfat, and tmpfs, which is where
 * /tmp and /dev/shm droppers actually land - is marked. */
static inline bool fan_fstype_markable(const char *fstype) {
  static const char *const skip[] = {
      "proc",     "sysfs",      "cgroup",    "cgroup2",   "devpts",
      "mqueue",   "debugfs",    "tracefs",   "securityfs", "pstore",
      "bpf",      "configfs",   "fusectl",   "hugetlbfs", "autofs",
      "binfmt_misc", "efivarfs", "nsfs",     "selinuxfs", "rpc_pipefs",
      "nfsd",     "nfs",        "nfs4",      "cifs",      "smb3",
      "smbfs",    "9p",         "ceph",      "glusterfs", "afs",
      "sshfs",    "fuse",       "fuseblk",   NULL,
  };
  size_t i;

  if (!fstype || !fstype[0])
    return false;
  /* fuse.<subtype> (fuse.sshfs, fuse.portal, fuse.gvfsd-fuse, ...) */
  if (strncmp(fstype, "fuse.", 5) == 0)
    return false;
  for (i = 0; skip[i]; i++)
    if (strcmp(fstype, skip[i]) == 0)
      return false;
  return true;
}

/* Parses one /proc/kernel_av_signatures line ("<algo> <hex> <name>",
 * see sig_proc_show() in av/sigtable.c) in place. Only sha256 entries
 * are returned (return 1) - avd hashes the exec image with SHA-256
 * only, so MD5/SHA-1 entries are reported back via *algo_out (return
 * 0) for the caller to count, and stay enforced by the kernel's
 * post-exec bprm_check path. The hex is lowercased and validated as
 * exactly 64 hex digits. `name` is the rest of the line (sigtable
 * names never contain whitespace, but taking the remainder is the
 * conservative read). Returns -1 on a malformed line. */
static inline int fan_sig_parse_line(char *line, char **algo_out,
                                     char **hex_out, char **name_out) {
  char *save = NULL;
  char *algo = strtok_r(line, " \t\n", &save);
  char *hex = strtok_r(NULL, " \t\n", &save);
  char *name = strtok_r(NULL, "\n", &save);
  size_t i;

  if (!algo || !hex || !name)
    return -1;
  while (*name == ' ' || *name == '\t')
    name++;
  if (!name[0])
    return -1;
  *algo_out = algo;
  if (strcmp(algo, "sha256") != 0)
    return 0;
  if (strlen(hex) != 64)
    return -1;
  for (i = 0; i < 64; i++) {
    if (!isxdigit((unsigned char)hex[i]))
      return -1;
    hex[i] = (char)tolower((unsigned char)hex[i]);
  }
  *hex_out = hex;
  *name_out = name;
  return 1;
}

#endif /* AV_FAN_PARSE_H */
