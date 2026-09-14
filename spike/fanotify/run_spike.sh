#!/bin/sh
# Drives fanotify_spike, which answers whether FAN_OPEN_EXEC_PERM is the
# blocking-verdict primitive #102 assumes it is.
#
# SAFE ON A LIVE MACHINE, unlike the BPF LSM spike next door. The marks
# this places are FAN_MARK_ADD on individual inodes inside a throwaway
# directory, never FAN_MARK_MOUNT, so the only execs that can block on
# the listener are of files created here. Nothing is installed, nothing
# persists, and closing the fanotify fd (including by process exit)
# releases any pending permission event as ALLOW.
#
# SCOPE OF WHAT THIS PROVES: one listener, one marked inode, a stub
# "verdict" that is just a sleep. It does NOT prove that marking a whole
# mount is safe, that avd can service events without deadlocking against
# its own file access, or anything about throughput. See README.md.
set -eu

D=$(dirname "$0")

if [ "$(id -u)" -ne 0 ]; then
	echo "This needs root: FAN_CLASS_CONTENT (permission events) requires"
	echo "CAP_SYS_ADMIN. Re-run with sudo."
	exit 1
fi

for b in fanotify_spike target_orig target_decoy target_unmarked; do
	if [ ! -x "$D/$b" ]; then
		echo "missing $D/$b - run 'make' first"
		exit 1
	fi
done

# TMPDIR is honoured so this can be pointed at an exec-permitting
# filesystem when /tmp is mounted noexec.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/fanotify-spike.XXXXXX")
cleanup() {
	rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

cp "$D/target_orig" "$D/target_decoy" "$D/target_unmarked" "$WORK/"

# Preflight: run a target by hand, outside fanotify entirely. If the work
# directory is noexec (or the binary is broken), every phase below would
# fail and phase 3's denial would be indistinguishable from a file that
# simply cannot run. Catch that here, where the message is unambiguous.
if "$WORK/target_unmarked"; then
	echo "preflight: unexpected exit 0 from target_unmarked"
	exit 1
else
	rc=$?
	if [ "$rc" -ne 7 ]; then
		echo "preflight FAILED: $WORK/target_unmarked exited $rc, wanted 7."
		echo "  Most likely $WORK is on a noexec mount - set TMPDIR to a"
		echo "  directory that permits exec and re-run."
		exit 1
	fi
fi
echo "preflight: work directory permits exec"
echo

"$D/fanotify_spike" "$WORK"
