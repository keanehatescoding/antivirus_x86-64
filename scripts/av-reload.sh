#!/usr/bin/env bash
#
# scripts/av-reload.sh - reload the av kernel module without losing its
# runtime state: the signature DB, trust list, protected-path list, and
# daemon-unavailable policy (/proc/kernel_av_signatures, _trusted,
# _protected, _daemon_policy) are all in-memory kernel state with no
# persistence of their own - everything vanishes on `rmmod` (see
# README's "Persistence: avctl save/load" section). This wraps the
# save -> rmmod -> insmod -> load sequence documented there into one
# command, for the panic/fix/reload loop this project's manual
# insmod/rmmod workflow implies.
#
# Usage:
#   sudo scripts/av-reload.sh [state-file]
#
# state-file defaults to /etc/hyprav/state.txt (SYSCONFDIR in
# userspace/avd/Makefile - the daemon's config lives under /etc/hyprav,
# not the stale /etc/kernel-av this script previously defaulted to).
# Safe to run on a first-ever load: if the module isn't
# currently loaded, the save step is skipped; if state-file doesn't
# exist yet, the load step is skipped and only the module's own
# auto-seeded EICAR signature will be present.
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "av-reload.sh: needs root (rmmod/insmod/avctl load). Re-run with sudo." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVCTL="$REPO_ROOT/userspace/avctl/avctl"
KO="$REPO_ROOT/av/av.ko"
STATE_FILE="${1:-/etc/hyprav/state.txt}"

if [ ! -x "$AVCTL" ]; then
    echo "av-reload.sh: $AVCTL not built - run 'make' in userspace/avctl first" >&2
    exit 1
fi

if [ ! -f "$KO" ]; then
    echo "av-reload.sh: $KO not built - run 'make' in av/ first" >&2
    exit 1
fi

if ! mkdir -p "$(dirname "$STATE_FILE")"; then
    echo "av-reload.sh: could not create $(dirname "$STATE_FILE")" >&2
    exit 1
fi

# awk instead of `lsmod | grep -q` deliberately: with pipefail set, grep -q
# can exit as soon as it matches, before lsmod has finished writing its
# output - lsmod then gets SIGPIPE and the pipeline's exit status becomes
# lsmod's (nonzero) rather than grep's match, which would make a loaded
# module look unloaded here and skip the save step outright.
if lsmod | awk '$1 == "av" { found = 1 } END { exit !found }'; then
    echo "av-reload.sh: module loaded, saving state to $STATE_FILE"
    if ! "$AVCTL" save "$STATE_FILE"; then
        echo "av-reload.sh: save failed, aborting before rmmod (state would be lost)" >&2
        exit 1
    fi
    if ! rmmod av; then
        echo "av-reload.sh: rmmod failed, aborting (state was saved to $STATE_FILE" \
             "but the old module is still loaded)" >&2
        exit 1
    fi
else
    echo "av-reload.sh: module not currently loaded, skipping save"
fi

if ! insmod "$KO"; then
    echo "av-reload.sh: insmod failed" >&2
    exit 1
fi

# Apply the hyprav trusted-reader group to the IOC /proc entries
# (#143): a bare insmod bypasses the packaged modprobe.d install
# hook, so without this the entries stay root:root 0640 and the GUI
# dashboard (which reads via unprivileged `avctl save -`) breaks
# until someone chgrps by hand. Best-effort - no hyprav group on
# this machine yet just means stay fail-closed (root-owned 0640),
# never block the reload itself.
"$REPO_ROOT/packaging/apply-ioc-group.sh" || true

if [ -s "$STATE_FILE" ]; then
    echo "av-reload.sh: replaying state from $STATE_FILE"
    if ! "$AVCTL" load "$STATE_FILE"; then
        echo "av-reload.sh: load failed - module is up but state may be incomplete," \
             "check the errors above" >&2
        exit 1
    fi
else
    echo "av-reload.sh: no prior state at $STATE_FILE - starting fresh" \
         "(only the auto-seeded EICAR signature and default fail-open" \
         "policy will be present)"
fi

echo "av-reload.sh: done"
