#!/usr/bin/env bash
#
# test_open_hook_coverage_evasion.sh - baseline for moving the write-intent
# open hook from the __x64_sys_openat kprobe to security_file_open (#105/#94).
#
# Question this answers: does the sensitive-path write-intent heuristic
# ("write-intent open of sensitive path", av/behavior.c) still fire when the
# open does not look like a plain openat() with a resident, literal path?
#
# Every case writes to a file under a private temp dir whose path contains
# "/.ssh/" (a sensitive substring), from a throwaway helper process. A case
# is DETECTED if the helper is SIGKILLed by the module, EVADED if it
# survives the open and the async kill window. Nothing real is touched.
#
#   control   openat(2), literal resident path       must be DETECTED, or the
#                                                    run is INCONCLUSIVE
#   open      raw open(2) syscall                    not hooked today
#   creat     raw creat(2) syscall                   not hooked today
#   openat2   raw openat2(2) syscall                 not hooked today
#   symlink   openat() of a symlink whose target     hook sees the link name,
#             is the sensitive file                  not the resolved target
#   cold      openat() with the path string in a     the kprobe copies the
#             not-yet-faulted-in file mapping        string in atomic context
#                                                    and cannot fault it in
#
# NOT covered: the user-memory TOCTOU (another thread rewriting the path
# string between the hook's copy and the kernel's own). It cannot be made
# deterministic without stalling the kernel's copy, and a flip-flopping
# string trips the heuristic on whichever read happens to see the
# sensitive name, so it would prove nothing either way.
#
# Expected today (syscall-entry kprobe): control DETECTED, the rest EVADED
# except possibly symlink (depends on whether resolve_absolute_path follows
# symlinks - this test is what settles that). Expected after the
# security_file_open swap: everything DETECTED. Use --strict then.
#
# NEEDS THE LIVE KERNEL MODULE - run this in your VM, not standalone.
# Usage: tests/evasion/test_open_hook_coverage_evasion.sh [--strict]
#   --strict  exit 1 if any non-control case is EVADED (use after the fix)
# Exit: 0 ok, 1 strict failure (evasions), 2 inconclusive (control not
#       detected, a non-control case failed to open, module not loaded,
#       or build failure).
#
set -u

STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

if ! lsmod 2>/dev/null | grep -q '^av '; then
    echo "The av kernel module is not loaded (lsmod shows no 'av')."
    echo "Load it in your VM first, e.g. sudo insmod av/av.ko"
    exit 2
fi

# Private mktemp -d, same reasoning as the other scripts in this directory.
TESTDIR="$(mktemp -d -- /tmp/open_coverage_test.XXXXXX)" || exit 2
trap 'rm -rf "$TESTDIR"' EXIT

HELPER="$TESTDIR/openprobe"
cat > "$TESTDIR/openprobe.c" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

struct open_how_local {
	unsigned long long flags, mode, resolve;
};

/* Exit codes: 0 opened and survived, 2 open failed, 3 syscall unsupported. */
int main(int argc, char **argv)
{
	const char *mode, *path;
	long fd = -1;

	if (argc != 3)
		return 2;
	mode = argv[1];
	path = argv[2];

	if (!strcmp(mode, "openat") || !strcmp(mode, "symlink")) {
		fd = syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_CREAT, 0600);
	} else if (!strcmp(mode, "open")) {
#ifdef SYS_open
		fd = syscall(SYS_open, path, O_WRONLY | O_CREAT, 0600);
#else
		errno = ENOSYS;
#endif
	} else if (!strcmp(mode, "creat")) {
#ifdef SYS_creat
		fd = syscall(SYS_creat, path, 0600);
#else
		errno = ENOSYS;
#endif
	} else if (!strcmp(mode, "openat2")) {
		struct open_how_local how = { O_WRONLY | O_CREAT, 0600, 0 };

		fd = syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
	} else if (!strcmp(mode, "cold")) {
		/* path names a file holding the real target path + NUL. Map it
		 * without touching it, so no PTE exists when the kernel's
		 * syscall-entry hook tries to copy the string. */
		int sfd = open(path, O_RDONLY);
		char *map;

		if (sfd < 0)
			return 2;
		map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, sfd, 0);
		if (map == MAP_FAILED)
			return 2;
		fd = syscall(SYS_openat, AT_FDCWD, map, O_WRONLY | O_CREAT, 0600);
	} else {
		return 2;
	}

	if (fd < 0) {
		fprintf(stderr, "open failed: %s\n", strerror(errno));
		return errno == ENOSYS ? 3 : 2;
	}

	/* The verdict is asynchronous (workqueue), so give the kill time. */
	sleep(3);
	puts("SURVIVED");
	return 0;
}
EOF

if ! "${CC:-cc}" -O1 -Wall -o "$HELPER" "$TESTDIR/openprobe.c"; then
    echo "Could not build the helper with ${CC:-cc}."
    exit 2
fi

SENS_DIR="$TESTDIR/.ssh"
TARGET="$SENS_DIR/id_test"
mkdir -p "$SENS_DIR"
# Never open the sensitive target from the coordinator: the write-intent
# hook can queue a SIGKILL against whichever task opens it, which would kill
# this script before it reports the helper results. Each helper creates the
# file itself, and a symlink may point at a not-yet-existing target.
ln -s "$TARGET" "$TESTDIR/innocent_link"
printf '%s' "$TARGET" > "$TESTDIR/pathfile"   # printf: no trailing newline;
printf '\0' >> "$TESTDIR/pathfile"            # NUL-terminate for the kernel

RESULTS=()
EVADED=0
INCONCLUSIVE=0
CONTROL_OK=1

run_case() {
    local name="$1" mode="$2" arg="$3" rc verdict
    "$HELPER" "$mode" "$arg" >/dev/null 2>&1
    rc=$?
    case "$rc" in
        137) verdict="DETECTED" ;;          # 128 + SIGKILL
        0)   verdict="EVADED" ;;
        3)   verdict="SKIPPED (syscall unsupported on this kernel)" ;;
        *)   verdict="INCONCLUSIVE (open failed, rc=$rc)" ;;
    esac
    RESULTS+=("$(printf '%-9s %s' "$name" "$verdict")")
    if [ "$name" = "control" ]; then
        [ "$verdict" = "DETECTED" ] || CONTROL_OK=0
    elif [ "$verdict" = "EVADED" ]; then
        EVADED=$((EVADED + 1))
    elif [ "${verdict%% *}" = "INCONCLUSIVE" ]; then
        INCONCLUSIVE=$((INCONCLUSIVE + 1))
    fi
}

echo "=== Open-hook coverage baseline (sensitive-path write-intent) ==="
echo "Each case runs a helper that opens a path containing /.ssh/ for write,"
echo "then waits 3s for the module's async verdict."
echo

run_case control  openat  "$TARGET"
run_case open     open    "$TARGET"
run_case creat    creat   "$TARGET"
run_case openat2  openat2 "$TARGET"
run_case symlink  symlink "$TESTDIR/innocent_link"
run_case cold     cold    "$TESTDIR/pathfile"

printf '%s\n' "${RESULTS[@]}"
echo

if [ "$CONTROL_OK" -ne 1 ]; then
    echo "INCONCLUSIVE: the control (plain openat of a sensitive path) was not"
    echo "detected, so the other results mean nothing. Check that the module is"
    echo "loaded and healthy ('dmesg | tail') and that nothing trusts this helper."
    exit 2
fi

echo "$EVADED case(s) evaded, $INCONCLUSIVE case(s) inconclusive."
echo "Today's expectation: open/creat/openat2/cold EVADED (hook coverage and"
echo "atomic-context copy gaps); symlink is the open question this settles."
echo "After the security_file_open swap, re-run with --strict: all must be DETECTED."

if [ "$STRICT" -eq 1 ] && [ "$EVADED" -gt 0 ]; then
    exit 1
fi
if [ "$INCONCLUSIVE" -gt 0 ]; then
    echo "INCONCLUSIVE: a non-control case never opened its path; the result"
    echo "for that case was not validated."
    exit 2
fi
exit 0
