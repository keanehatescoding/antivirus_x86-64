#!/usr/bin/env bash
#
# tests/test_fan_parse.sh - known-answer and adversarial coverage for
# userspace/avd/fan_parse.h (#176): the /proc/self/mountinfo parser that
# decides which filesystems avd's fanotify listener marks, and the
# /proc/kernel_av_signatures parser behind its pre-exec signature
# snapshot. The harness includes the production header directly, same
# arrangement as test_parser_robustness.sh.
#
# Pure userspace, no kernel module or root needed:
#   tests/test_fan_parse.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_fan_parse.XXXXXX")" || exit 1

# shellcheck disable=SC2317,SC2329
# False positive: cleanup() IS invoked via `trap` on the next line.
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

cat > "$BUILD_DIR/harness.c" <<'EOF'
#include <stdio.h>
#include <string.h>

#include "fan_parse.h"

static int PASS, FAIL;

#define CHECK(cond, label) do { \
    if (cond) { printf("  PASS: %s\n", label); PASS++; } \
    else { printf("  FAIL: %s\n", label); FAIL++; } \
} while (0)

struct mi {
    int ret;
    unsigned maj, min;
    char mp[256], fstype[64];
    bool noexec;
};

static struct mi mi_parse(const char *in) {
    char line[1024];
    struct mi r = {0};
    char *mp = NULL, *fs = NULL;

    snprintf(line, sizeof(line), "%s", in);
    r.ret = fan_mountinfo_parse_line(line, &r.maj, &r.min, &mp, &fs, &r.noexec);
    if (r.ret == 0) {
        snprintf(r.mp, sizeof(r.mp), "%s", mp);
        snprintf(r.fstype, sizeof(r.fstype), "%s", fs);
    }
    return r;
}

int main(void) {
    struct mi r;

    printf("=== mountinfo ===\n");
    r = mi_parse("36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue");
    CHECK(r.ret == 0 && r.maj == 98 && r.min == 0, "proc(5) example: device");
    CHECK(!strcmp(r.mp, "/mnt2") && !strcmp(r.fstype, "ext3"),
          "proc(5) example: mount point and fstype");
    CHECK(!r.noexec, "proc(5) example: exec allowed");

    r = mi_parse("25 1 0:22 / / rw,relatime - btrfs /dev/nvme0n1p2 rw");
    CHECK(r.ret == 0 && !strcmp(r.fstype, "btrfs"),
          "no optional fields before the separator");

    r = mi_parse("40 25 0:35 / /tmp rw,nosuid,nodev shared:5 master:3 propagate_from:2 - tmpfs tmpfs rw");
    CHECK(r.ret == 0 && !strcmp(r.fstype, "tmpfs") && !strcmp(r.mp, "/tmp"),
          "several optional fields before the separator");

    r = mi_parse("41 25 0:36 / /dev/shm rw,nosuid,nodev,noexec shared:6 - tmpfs tmpfs rw");
    CHECK(r.ret == 0 && r.noexec, "noexec detected in per-mount options");

    r = mi_parse("42 25 0:37 / /x rw,noexecute - ext4 /dev/sda1 rw");
    CHECK(r.ret == 0 && !r.noexec, "noexec matched as a whole option only");

    r = mi_parse("43 25 8:1 / /media/My\\040Disk\\011x rw - vfat /dev/sdb1 rw");
    CHECK(r.ret == 0 && !strcmp(r.mp, "/media/My Disk\tx"),
          "octal escapes in the mount point are undone");

    r = mi_parse("44 25 8:2 / /a\\134b rw - ext4 /dev/sdb2 rw");
    CHECK(r.ret == 0 && !strcmp(r.mp, "/a\\b"), "escaped backslash");

    r = mi_parse("45 25 8:3 / /bad\\9xx rw - ext4 /dev/sdb3 rw");
    CHECK(r.ret == 0 && !strcmp(r.mp, "/bad\\9xx"),
          "malformed escape is left literal, not decoded");

    CHECK(mi_parse("").ret == -1, "empty line rejected");
    CHECK(mi_parse("36 35 98:0 /mnt1 /mnt2 rw master:1 ext3 /dev/root rw").ret == -1,
          "missing separator rejected");
    CHECK(mi_parse("36 35 98:0 /mnt1 /mnt2 rw -").ret == -1,
          "separator with no fstype rejected");
    CHECK(mi_parse("36 35 98 /mnt1 /mnt2 rw - ext3 /dev/root rw").ret == -1,
          "device without minor rejected");
    CHECK(mi_parse("36 35 x:0 /mnt1 /mnt2 rw - ext3 /dev/root rw").ret == -1,
          "non-numeric major rejected");
    CHECK(mi_parse("36 35 8:0x /mnt1 /mnt2 rw - ext3 /dev/root rw").ret == -1,
          "trailing junk after minor rejected");
    CHECK(mi_parse("36 35 8:0 /mnt1 relative rw - ext3 /dev/root rw").ret == -1,
          "relative mount point rejected");
    CHECK(mi_parse("36 35 8:0 /mnt1").ret == -1, "truncated line rejected");

    printf("=== fstype selection ===\n");
    CHECK(fan_fstype_markable("ext4") && fan_fstype_markable("xfs") &&
          fan_fstype_markable("btrfs") && fan_fstype_markable("vfat"),
          "disk filesystems are marked");
    CHECK(fan_fstype_markable("tmpfs"), "tmpfs (/tmp, /dev/shm droppers) is marked");
    CHECK(!fan_fstype_markable("proc") && !fan_fstype_markable("sysfs") &&
          !fan_fstype_markable("cgroup2") && !fan_fstype_markable("devpts"),
          "pseudo filesystems are skipped");
    CHECK(!fan_fstype_markable("nfs4") && !fan_fstype_markable("cifs"),
          "network filesystems are skipped");
    CHECK(!fan_fstype_markable("fuse") && !fan_fstype_markable("fuse.sshfs") &&
          !fan_fstype_markable("fuse.gvfsd-fuse"),
          "FUSE filesystems are skipped");
    CHECK(!fan_fstype_markable("") && !fan_fstype_markable(NULL),
          "empty fstype is not marked");

    printf("=== signature lines ===\n");
    {
        char line[512];
        char *algo, *hex, *name;
        const char *h = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";

        snprintf(line, sizeof(line), "sha256 %s EICAR_Test\n", h);
        CHECK(fan_sig_parse_line(line, &algo, &hex, &name) == 1 &&
              !strcmp(hex, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") &&
              !strcmp(name, "EICAR_Test"),
              "sha256 entry parsed, hex lowercased");

        snprintf(line, sizeof(line), "md5 44d88612fea8a8f36de82e1278abb02f EICAR_md5");
        CHECK(fan_sig_parse_line(line, &algo, &hex, &name) == 0 &&
              !strcmp(algo, "md5"),
              "md5 entry reported for the kernel, not returned");

        snprintf(line, sizeof(line), "sha256 abcd short");
        CHECK(fan_sig_parse_line(line, &algo, &hex, &name) == -1,
              "short sha256 hex rejected");

        snprintf(line, sizeof(line), "sha256 %.63sg bad_digit", h);
        CHECK(fan_sig_parse_line(line, &algo, &hex, &name) == -1,
              "non-hex digit rejected");

        snprintf(line, sizeof(line), "sha256 %s", h);
        CHECK(fan_sig_parse_line(line, &algo, &hex, &name) == -1,
              "entry without a name rejected");

        snprintf(line, sizeof(line), "%s", "");
        CHECK(fan_sig_parse_line(line, &algo, &hex, &name) == -1,
              "empty line rejected");
    }

    printf("\n===================================\n");
    printf("fan_parse: %d passed, %d failed\n", PASS, FAIL);
    printf("===================================\n");
    return FAIL ? 1 : 0;
}
EOF

if ! cc -Wall -Wextra -O2 -I "$REPO_ROOT/userspace/avd" \
        "$BUILD_DIR/harness.c" -o "$BUILD_DIR/harness" 2>"$BUILD_DIR/build.log"; then
    echo "FAIL: could not build the fan_parse harness - see build log:"
    cat "$BUILD_DIR/build.log"
    exit 1
fi

"$BUILD_DIR/harness"
exit $?
