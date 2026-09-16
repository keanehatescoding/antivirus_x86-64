#!/usr/bin/env bash
#
# tests/test_avd_socket.sh - exercises avd's control socket protocol
# (see docs/avd-socket-protocol.md): STATUS, VERDICTS RECENT, SCAN,
# and QUARANTINE LIST/RESTORE/DELETE. Runs everything as root (this
# script requires root anyway, for insmod/rmmod), but the SO_PEERCRED
# permission gate that rejects SCAN/QUARANTINE RESTORE/DELETE from a
# non-root peer is still covered: the "unprivileged peer rejected"
# section below makes a second connection with setpriv-dropped
# credentials (uid "nobody", never 0) alongside the root one the rest
# of this script uses.
#
# Unlike test_sigtable.sh (which expects the module already loaded and
# never touches avd), this script builds and loads the module AND
# starts avd itself, against a throwaway quarantine dir and control
# socket path - it does not touch your real /var/lib/av-quarantine or
# /run/avd/control.sock.
#
# RUN THIS ONLY IN YOUR VM, ideally from a fresh snapshot - it loads a
# kernel module, same caveat as test_detection.sh.
#
# Usage: sudo tests/test_avd_socket.sh
#
set -u

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root (insmod/rmmod, and to exercise avd's"
    echo "root-only SCAN/QUARANTINE RESTORE/QUARANTINE DELETE verbs as root)."
    echo "Re-run with sudo."
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AV_DIR="$REPO_ROOT/av"
AVD_DIR="$REPO_ROOT/userspace/avd"
AVCTL_DIR="$REPO_ROOT/userspace/avctl"
AVCTL="$AVCTL_DIR/avctl"

# One private mktemp -d holding quarantine dir, socket, and sample file -
# not PID-derived /tmp/av_test_*_$$ paths: $$ is guessable and reusable,
# so a local attacker could pre-create any of these as a symlink and have
# the root-run test write through it (classic /tmp race). A random-suffix
# 0700 directory closes that off - same pattern as TEST_RULES_DIR below
# and tests/test_netlink.sh. The socket path stays under 108 bytes for
# AF_UNIX sun_path either way (mktemp suffix is only 6 random chars).
TEST_TMP_DIR="$(mktemp -d -- /tmp/av_test_socket.XXXXXX)" || exit 1
# 0711, not mktemp's default 0700: the unprivileged-peer section below
# connects as "nobody" to exercise avd's SO_PEERCRED gate, and a 0700
# root-owned dir would block that connect at path traversal (empty
# response, not the expected ERR permission denied). 0711 lets nobody
# traverse to the socket without listing the dir, and the random mktemp
# suffix keeps the full paths unguessable to anyone else.
chmod 0711 "$TEST_TMP_DIR"
TEST_QUARANTINE_DIR="$TEST_TMP_DIR/quarantine"
TEST_SOCK_PATH="$TEST_TMP_DIR/control.sock"
TEST_FILE="$TEST_TMP_DIR/sample.bin"
# Staged rules dir: production rules plus the tests/fixtures/test.yar
# fixture (EICAR_Test_String, needed by the SCAN-malicious section
# below). The fixture is deliberately NOT part of rules/ anymore (it
# never ships to production - see tests/fixtures/test.yar), so stage
# it here rather than pointing avd at rules/ directly.
TEST_RULES_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_rules.XXXXXX")" || exit 1
AVD_PID=""

# mktemp, not a fixed /tmp/av_socket_*.log path - this script runs as
# root, and a fixed world-writable-directory path is a classic
# symlink-planting target: another local user could pre-create a
# symlink there pointing anywhere, and a root redirect into it would
# truncate/overwrite whatever it points to. Same reasoning as
# userspace/avd/Makefile's checkdeps target.
BUILD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_build.XXXXXX")" || exit 1
INSMOD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_insmod.XXXXXX")" || exit 1
AVD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_avd.XXXXXX")" || exit 1
SOCAT_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_socat.XXXXXX")" || exit 1
AVCTL_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_avctl.XXXXXX")" || exit 1
RMMOD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_rmmod.XXXXXX")" || exit 1

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
section() { echo; echo "== $1 =="; }

# Same toolchain-detection rationale as test_detection.sh - sudo
# strips any CC=clang LLVM=1 the caller's shell had exported, so
# detect the running kernel's actual build toolchain directly instead
# of trusting inherited environment variables.
MAKE_ARGS=()
if grep -q "clang version" /proc/version 2>/dev/null; then
    echo "Detected a Clang-built running kernel ($(uname -r)) - building with CC=clang LLVM=1"
    MAKE_ARGS=(CC=clang LLVM=1)
fi

cleanup() {
    section "cleanup"
    if [ -n "$AVD_PID" ] && kill -0 "$AVD_PID" 2>/dev/null; then
        kill "$AVD_PID" 2>/dev/null
        wait "$AVD_PID" 2>/dev/null
        echo "  avd stopped"
    fi
    rmmod av 2>/dev/null && echo "  module unloaded" || echo "  module already unloaded"
    rm -rf "$TEST_TMP_DIR" "$TEST_RULES_DIR"
    rm -f "$BUILD_LOG" "$INSMOD_LOG" "$AVD_LOG" "$SOCAT_LOG" "$AVCTL_LOG" "$RMMOD_LOG"
}
trap cleanup EXIT

section "build"
if make -C "$AV_DIR" "${MAKE_ARGS[@]}" clean >"$BUILD_LOG" 2>&1 && \
   make -C "$AV_DIR" "${MAKE_ARGS[@]}" >>"$BUILD_LOG" 2>&1 && \
   make -C "$AVD_DIR" >>"$BUILD_LOG" 2>&1 && \
   make -C "$AVCTL_DIR" >>"$BUILD_LOG" 2>&1; then
    pass "av.ko, avd, and avctl built"
else
    fail "build failed - see $BUILD_LOG"
    cat "$BUILD_LOG"
    exit 1
fi

section "load module"
if insmod "$AV_DIR/av.ko" 2>"$INSMOD_LOG"; then
    pass "module loaded"
else
    fail "insmod failed: $(cat "$INSMOD_LOG")"
    exit 1
fi
sleep 1

section "start avd (throwaway quarantine dir + control socket)"
mkdir -p "$TEST_QUARANTINE_DIR"
cp "$REPO_ROOT"/rules/*.yar "$TEST_RULES_DIR"/
cp "$REPO_ROOT"/tests/fixtures/test.yar "$TEST_RULES_DIR"/
(
    cd "$REPO_ROOT" || exit 1
    exec "$AVD_DIR/avd" "$TEST_RULES_DIR" corpus/fuzzy_hashes.txt "$TEST_QUARANTINE_DIR" \
        corpus/tlsh_hashes.txt "$TEST_SOCK_PATH" >"$AVD_LOG" 2>&1
) &
AVD_PID=$!

for _ in $(seq 1 20); do
    [ -S "$TEST_SOCK_PATH" ] && break
    sleep 0.5
done
if [ -S "$TEST_SOCK_PATH" ]; then
    pass "avd started and control socket exists"
else
    fail "avd did not create the control socket in time - see $AVD_LOG"
    cat "$AVD_LOG"
    exit 1
fi

export AVD_SOCK_PATH="$TEST_SOCK_PATH"

# STATUS/VERDICTS RECENT have no avctl subcommand (the GUI talks to
# them directly - see docs/avd-socket-protocol.md), so exercise the
# raw wire protocol with socat if it's available. Not a hard
# dependency: skip gracefully rather than failing the whole suite over
# a missing optional tool, since avctl already covers the
# security-relevant verbs (SCAN, QUARANTINE *) below either way.
section "STATUS / VERDICTS RECENT (raw protocol via socat)"
if command -v socat >/dev/null 2>&1; then
    STATUS_RESP="$(printf 'STATUS\n' | socat - "UNIX-CONNECT:$TEST_SOCK_PATH" 2>"$SOCAT_LOG")"
    if echo "$STATUS_RESP" | grep -q '^OK$' && echo "$STATUS_RESP" | grep -q '^COUNT 1$'; then
        pass "STATUS returns OK/COUNT 1"
    else
        fail "STATUS response malformed: $STATUS_RESP"
    fi

    VERDICTS_RESP="$(printf 'VERDICTS RECENT 5\n' | socat - "UNIX-CONNECT:$TEST_SOCK_PATH" 2>>"$SOCAT_LOG")"
    if echo "$VERDICTS_RESP" | grep -q '^OK$'; then
        pass "VERDICTS RECENT 5 returns OK"
    else
        fail "VERDICTS RECENT response malformed: $VERDICTS_RESP"
    fi

    BOGUS_RESP="$(printf 'NOT A REAL COMMAND\n' | socat - "UNIX-CONNECT:$TEST_SOCK_PATH" 2>>"$SOCAT_LOG")"
    if echo "$BOGUS_RESP" | grep -q '^ERR '; then
        pass "unknown command rejected with ERR"
    else
        fail "unknown command not rejected as expected: $BOGUS_RESP"
    fi
else
    echo "  SKIP: socat not installed - skipping raw-protocol STATUS/VERDICTS checks"
    echo "  (Arch/CachyOS: sudo pacman -S socat / Debian/Ubuntu: sudo apt install socat)"
fi

section "unprivileged peer rejected on SCAN/QUARANTINE RESTORE/QUARANTINE DELETE"
# Connects as an actual non-root peer (not just "pass a fake uid
# somewhere") so the daemon's real SO_PEERCRED gate - which reads the
# kernel-captured credentials of whoever connect()'d, not anything the
# client itself can claim - is what's under test. setpriv drops this
# root test script's privileges just for the socat child; the "nobody"
# user is used as a UID guaranteed to exist and never be 0 on any
# Linux system. Its primary GID is resolved numerically via `id -g`
# rather than passed to --regid as the literal name "nobody" - that
# name resolves fine on Arch/CachyOS (whose nobody user's own group is
# also named "nobody"), but Debian/Ubuntu's nobody user's primary
# group is "nogroup", not "nobody", so --regid=nobody would fail
# there with no group by that name to resolve, silently breaking this
# whole section. Unlike the STATUS/VERDICTS raw-protocol checks above
# (which are best-effort coverage for GUI convenience verbs), this section
# covers the SO_PEERCRED auth gate on security-relevant verbs - silently
# skipping it when socat/setpriv/nobody is missing would let a real
# auth-gate regression pass CI unnoticed, so missing tooling is a hard
# failure here, not a SKIP.
if command -v socat >/dev/null 2>&1 && command -v setpriv >/dev/null 2>&1 && \
   NOBODY_UID="$(id -u nobody 2>/dev/null)" && NOBODY_GID="$(id -g nobody 2>/dev/null)"; then
    unpriv_send() {
        # $1 = command line to send
        setpriv --reuid="$NOBODY_UID" --regid="$NOBODY_GID" --clear-groups \
            socat -t2 - "UNIX-CONNECT:$TEST_SOCK_PATH" <<<"$1" 2>>"$SOCAT_LOG"
    }

    UNPRIV_SCAN_RESP="$(unpriv_send "SCAN $TEST_FILE")"
    if echo "$UNPRIV_SCAN_RESP" | grep -q '^ERR permission denied'; then
        pass "unprivileged SCAN rejected"
    else
        fail "unprivileged SCAN not rejected as expected: $UNPRIV_SCAN_RESP"
    fi

    UNPRIV_RESTORE_RESP="$(unpriv_send "QUARANTINE RESTORE bogus-id")"
    if echo "$UNPRIV_RESTORE_RESP" | grep -q '^ERR permission denied'; then
        pass "unprivileged QUARANTINE RESTORE rejected"
    else
        fail "unprivileged QUARANTINE RESTORE not rejected as expected: $UNPRIV_RESTORE_RESP"
    fi

    UNPRIV_DELETE_RESP="$(unpriv_send "QUARANTINE DELETE bogus-id")"
    if echo "$UNPRIV_DELETE_RESP" | grep -q '^ERR permission denied'; then
        pass "unprivileged QUARANTINE DELETE rejected"
    else
        fail "unprivileged QUARANTINE DELETE not rejected as expected: $UNPRIV_DELETE_RESP"
    fi
else
    fail "socat/setpriv missing or \"nobody\" user/group unresolvable - cannot exercise unprivileged-peer auth gate"
    echo "  (Arch/CachyOS: sudo pacman -S socat util-linux / Debian/Ubuntu: sudo apt install socat util-linux)"
fi

section "SCAN a clean file"
printf 'just some harmless test bytes\n' > "$TEST_FILE"
if "$AVCTL" scan "$TEST_FILE" 2>"$AVCTL_LOG" | grep -q '^CLEAN:'; then
    pass "scan of a harmless file reports CLEAN"
else
    fail "expected CLEAN, got: $(cat "$AVCTL_LOG")"
fi

section "SCAN queueing (second SCAN waits on the shared worker pool)"
# Runs avd with AVD_SCAN_THREADS=1 plus a test-only hold gate
# (AVD_TEST_SCAN_HOLD_PATH, see avd.c): the first on-demand scan
# creates "$dir/entered" and polls for "$dir/release", pinning the
# single worker while the second SCAN must sit queued behind it.
# Under the old synchronous design both connection threads would scan
# inline and the second client would complete before the release - so
# "second client still pending at release time, then both CLEAN" is
# the assertion that actually observes queueing rather than mere
# parallelism. Flag files, not a FIFO: a FIFO writer-open blocks for
# a reader that only appears after scan 1 arrives (hang), and a dummy
# reader of its own defeats the EOF release (hang the other way).
# Restart avd specially for this section (single worker + hold gate),
# then restore the normal instance afterwards - the rest of the suite
# keeps the default pool.
kill "$AVD_PID" 2>/dev/null
# wait alone is not enough: this script runs as root under pkexec and
# avd's shutdown path joins its worker pool first, so a waved-off kill
# without a reap can leave the old daemon still bound to the socket
# when the new one starts below (bind fails, section hangs on a -S
# that never appears). Reap, then poll until the pid is really gone.
wait "$AVD_PID" 2>/dev/null
for _ in $(seq 1 50); do
    kill -0 "$AVD_PID" 2>/dev/null || break
    sleep 0.1
done
# Fresh socket path: the old avd unlinks its control socket on shutdown,
# and a stale -S test would otherwise pass instantly against the dead
# instance's file while the new one never got to bind it.
TEST_HOLD_DIR="$TEST_TMP_DIR/scan_hold"
mkdir -p "$TEST_HOLD_DIR"
(
    cd "$REPO_ROOT" || exit 1
    exec env AVD_SCAN_THREADS=1 AVD_TEST_SCAN_HOLD_PATH="$TEST_HOLD_DIR" \
        "$AVD_DIR/avd" "$TEST_RULES_DIR" corpus/fuzzy_hashes.txt "$TEST_QUARANTINE_DIR" \
        corpus/tlsh_hashes.txt "$TEST_SOCK_PATH" >"$AVD_LOG" 2>&1
) &
AVD_PID=$!
# If the new avd dies at startup (e.g. bind fails because the old
# daemon hasn't released the socket), -S never appears and this loop
# would burn 10s before failing. Break early once the pid is gone so
# the log below shows the real error immediately.
for _ in $(seq 1 20); do
    [ -S "$TEST_SOCK_PATH" ] && break
    kill -0 "$AVD_PID" 2>/dev/null || break
    sleep 0.5
done
printf 'queueing fixture one, harmless bytes\n' > "$TEST_TMP_DIR/qscan_1.bin"
printf 'queueing fixture two, harmless bytes\n' > "$TEST_TMP_DIR/qscan_2.bin"
"$AVCTL" scan "$TEST_TMP_DIR/qscan_1.bin" >"$TEST_TMP_DIR/qscan_1.out" 2>&1 &
QSCAN1_PID=$!
QSCAN_STARTED=0
# Let scan 1 reach the hold gate before starting scan 2: poll for the
# entered flag rather than sleeping a fixed amount.
for _ in $(seq 1 100); do
    if [ -e "$TEST_HOLD_DIR/entered" ]; then
        QSCAN_STARTED=1
        break
    fi
    sleep 0.1
done
"$AVCTL" scan "$TEST_TMP_DIR/qscan_2.bin" >"$TEST_TMP_DIR/qscan_2.out" 2>&1 &
QSCAN2_PID=$!
# Give scan 2 time to arrive and enqueue behind the held worker - then
# assert it is still pending. A synchronous design would have finished
# it on its own connection thread by now. kill -0 alone only proves
# the avctl client process still exists, not that avd admitted the
# request - so also poll STATUS (field 5 = queued + in-service scans)
# until the server itself reports both scans inside. A synchronous
# design never enqueues, so the count stays 0 and this fails loudly
# instead of passing on a delayed client.
sleep 2
QSCAN_QUEUED=0
for _ in $(seq 1 50); do
    QSTATUS="$(printf 'STATUS\n' | socat - "UNIX-CONNECT:$TEST_SOCK_PATH" 2>/dev/null)"
    if echo "$QSTATUS" | awk -F'\t' 'NR==3 { exit ($5 == 2 ? 0 : 1) }'; then
        QSCAN_QUEUED=1
        break
    fi
    sleep 0.1
done
QSCAN_FAIL=0
if [ "$QSCAN_STARTED" -eq 0 ]; then
    echo "  note: scan 1 never reached the hold gate - queueing not exercised"
    QSCAN_FAIL=1
fi
if [ "$QSCAN_QUEUED" -eq 0 ]; then
    echo "  note: server never reported 2 scans inside - second SCAN not queued"
    QSCAN_FAIL=1
fi
if ! kill -0 "$QSCAN2_PID" 2>/dev/null; then
    echo "  note: second SCAN completed before the release - not queued"
    QSCAN_FAIL=1
fi
# Release: touch the release flag; the held worker's poll sees it and
# both scans proceed to CLEAN.
: > "$TEST_HOLD_DIR/release"
if ! wait "$QSCAN1_PID"; then
    QSCAN_FAIL=1
fi
if ! wait "$QSCAN2_PID"; then
    QSCAN_FAIL=1
fi
for i in 1 2; do
    if ! grep -q '^CLEAN:' "$TEST_TMP_DIR/qscan_$i.out" 2>/dev/null; then
        QSCAN_FAIL=1
    fi
    rm -f "$TEST_TMP_DIR/qscan_$i.bin" "$TEST_TMP_DIR/qscan_$i.out"
done
rm -rf "$TEST_HOLD_DIR"
# Restore the normal multi-worker avd for the rest of the suite.
kill "$AVD_PID" 2>/dev/null
wait "$AVD_PID" 2>/dev/null
for _ in $(seq 1 50); do
    kill -0 "$AVD_PID" 2>/dev/null || break
    sleep 0.1
done
rm -f "$TEST_SOCK_PATH"
(
    cd "$REPO_ROOT" || exit 1
    exec "$AVD_DIR/avd" "$TEST_RULES_DIR" corpus/fuzzy_hashes.txt "$TEST_QUARANTINE_DIR" \
        corpus/tlsh_hashes.txt "$TEST_SOCK_PATH" >"$AVD_LOG" 2>&1
) &
AVD_PID=$!
for _ in $(seq 1 20); do
    [ -S "$TEST_SOCK_PATH" ] && break
    kill -0 "$AVD_PID" 2>/dev/null || break
    sleep 0.5
done
if [ ! -S "$TEST_SOCK_PATH" ]; then
    fail "avd did not restart after the queueing section - see $AVD_LOG"
    cat "$AVD_LOG"
    exit 1
fi
if [ "$QSCAN_FAIL" -eq 0 ]; then
    pass "second SCAN queued behind held worker, both report CLEAN"
else
    fail "queueing not observed (second SCAN finished before release, errored, or misreported)"
fi

section "SCAN the EICAR test string (should convict via YARA)"
# shellcheck disable=SC2016
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TEST_FILE"
SCAN_OUT="$("$AVCTL" scan "$TEST_FILE" 2>"$AVCTL_LOG")"
if echo "$SCAN_OUT" | grep -q '^MALICIOUS:'; then
    pass "EICAR scan reports MALICIOUS"
else
    fail "expected MALICIOUS, got: $SCAN_OUT ($(cat "$AVCTL_LOG"))"
fi
if [ ! -e "$TEST_FILE" ]; then
    pass "EICAR file was quarantined (original path gone)"
else
    fail "EICAR file still present at original path after a MALICIOUS scan"
fi

section "QUARANTINE LIST shows the quarantined EICAR file"
LIST_OUT="$("$AVCTL" quarantine list 2>"$AVCTL_LOG")"
if echo "$LIST_OUT" | grep -q "$TEST_FILE"; then
    pass "quarantine list shows the original path"
else
    fail "quarantine list missing expected entry: $LIST_OUT"
fi
QID="$(echo "$LIST_OUT" | tail -n +2 | awk -v f="$TEST_FILE" '$0 ~ f {print $1}' | head -1)"

section "QUARANTINE RESTORE puts it back"
if [ -n "$QID" ] && "$AVCTL" quarantine restore "$QID" >"$AVCTL_LOG" 2>&1; then
    pass "restore command succeeded"
else
    fail "restore command failed: $(cat "$AVCTL_LOG" 2>/dev/null) (id=$QID)"
fi
if [ -e "$TEST_FILE" ]; then
    pass "file exists at original path after restore"
else
    fail "file missing at original path after restore"
fi

section "re-scan + QUARANTINE DELETE removes it for good"
"$AVCTL" scan "$TEST_FILE" >/dev/null 2>&1  # re-quarantine (still the EICAR content)
LIST_OUT="$("$AVCTL" quarantine list 2>/dev/null)"
QID="$(echo "$LIST_OUT" | tail -n +2 | awk -v f="$TEST_FILE" '$0 ~ f {print $1}' | head -1)"
if [ -n "$QID" ] && "$AVCTL" quarantine delete "$QID" >"$AVCTL_LOG" 2>&1; then
    pass "delete command succeeded"
else
    fail "delete command failed: $(cat "$AVCTL_LOG" 2>/dev/null) (id=$QID)"
fi
if "$AVCTL" quarantine list 2>/dev/null | grep -q "$TEST_FILE"; then
    fail "quarantine list still shows the deleted entry"
else
    pass "quarantine list no longer shows the deleted entry"
fi
rm -f "$TEST_FILE"

section "unload"
if kill "$AVD_PID" 2>/dev/null; then
    wait "$AVD_PID" 2>/dev/null
    AVD_PID=""
    pass "avd stopped"
else
    fail "could not stop avd"
fi
if rmmod av 2>"$RMMOD_LOG"; then
    pass "module unloaded cleanly"
else
    fail "rmmod failed: $(cat "$RMMOD_LOG")"
fi

echo
echo "==================================="
echo "avd socket tests: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
