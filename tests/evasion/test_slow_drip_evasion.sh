#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_slow_drip_evasion.sh - evasion test 4 (see docs/evasion-findings.md #4).
#
# Technique: pacing write bursts just beyond the rapid-write-open trailing
# window so total volume over time never trips the per-window threshold.
#
# History: behavior.c's counter originally used a FIXED (discrete) window
# that reset entirely on each boundary (v0.8.x and earlier) - that
# implementation bug is fixed. sliding_window_note() now keeps a real
# trailing window where each tracked write carries its own timestamp and
# ages out individually after WRITE_OPEN_WINDOW_MS, so there is no longer
# a boundary to pace around for free.
#
# What this script demonstrates now is the narrower, inherent remainder:
# bursts paced strictly beyond the window (here 40 files per burst, 2.1s
# apart against a 2.0s window) still evade, because a finite windowed
# counter legitimately forgets writes older than the window - that is what
# makes it a rate counter rather than a lifetime counter. No finite
# window/threshold pair closes this off, only shifts where the evasion
# threshold sits; closing it would need a different mechanism (e.g. total
# volume over a much longer horizon). See docs/evasion-findings.md #4 for
# the re-verified live results distinguishing the fixed implementation bug
# from this inherent limitation.
#
# NEEDS THE LIVE KERNEL MODULE - run this in your VM, not standalone.
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root to check dmesg meaningfully after the test."
    echo "Re-run with sudo, or just run the write loop below manually and"
    echo "check 'dmesg | tail' yourself."
fi

# Private mktemp -d, not a fixed /tmp/slow_drip_test path: predictable
# world-writable-directory names let another local user pre-plant a symlink
# or a pre-created directory with attacker-controlled permissions that this
# root-run script would then write through. Same pattern as
# tests/test_netlink.sh.
TESTDIR="$(mktemp -d -- /tmp/slow_drip_test.XXXXXX)" || exit 1
trap 'rm -rf "$TESTDIR"' EXIT
mkdir -p "$TESTDIR"
cd "$TESTDIR"

echo "=== Evasion test: slow-drip file modification ==="
echo "Writing 200 files total, in bursts of 40 (under the 50 threshold),"
echo "with a 2.1 second pause between bursts (just over the window size)."
echo

dmesg -C 2>/dev/null || true

BURST_SIZE=40
NUM_BURSTS=5

for burst in $(seq 1 "$NUM_BURSTS"); do
    echo "-- burst $burst/$NUM_BURSTS ($BURST_SIZE files --"
    for i in $(seq 1 "$BURST_SIZE"); do
        echo "data" > "burst${burst}_file${i}.txt"
    done
    if [ "$burst" -lt "$NUM_BURSTS" ]; then
        echo "   pausing 2.1s for the window to reset..."
        sleep 2.1
    fi
done

TOTAL=$((BURST_SIZE * NUM_BURSTS))
echo
echo "Wrote $TOTAL files total across $NUM_BURSTS bursts."
echo
echo "--- dmesg since the test started ---"
dmesg 2>/dev/null | tail -20 || echo "(run 'dmesg | tail -20' manually if not root)"

echo
echo "EXPECTED RESULT: no 'rapid file modification' kill, despite modifying"
echo "$TOTAL files total - each individual burst stayed under the 50-open"
echo "threshold, and bursts were paced beyond (not merely at) the 2s trailing"
echo "window so earlier bursts had aged out. This is the inherent remainder:"
echo "total volume over time isn't tracked, only volume within the trailing"
echo "window - see docs/evasion-findings.md #4."  
