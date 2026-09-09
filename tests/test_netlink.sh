#!/usr/bin/env bash
#
# tests/test_netlink.sh - exercises the kernel<->avd Generic Netlink
# channel (see docs/netlink-protocol.md), which SECURITY.md calls out
# as one of the most security-critical surfaces in the project but
# which - unlike the Unix control socket (test_avd_socket.sh) and the
# procfs signature interface (test_sigtable.sh) - had no automated
# coverage at all before this script.
#
# Covers, in order:
#   - a non-CAP_NET_ADMIN process can't send AV_C_REGISTER/AV_C_VERDICT
#   - a malformed (missing required attribute) or oversized-attribute
#     AV_C_VERDICT is rejected without wedging the module
#   - only the currently-registered daemon's portid is honored for
#     AV_C_VERDICT ("portid pinning")
#   - a second AV_C_REGISTER from a different portid while one is live
#     is rejected with -EBUSY (no silent replacement - see
#     docs/netlink-protocol.md)
#   - a real end-to-end AV_C_SCAN_REQUEST/AV_C_VERDICT round trip via
#     the real avd binary, for both a clean and a malicious (YARA-only,
#     not signature-table) exec
#
# Uses tests/netlink_test_helper.c, a throwaway genl client built only
# by this script (never linked into avd or any shipped binary) -
# avd's own AV_C_REGISTER/AV_C_VERDICT sends are fire-and-forget
# (nl_send_auto(), no ack requested), which is fine for avd itself but
# useless for a test that needs to observe *rejections*.
#
# RUN THIS ONLY IN YOUR VM, ideally from a fresh snapshot - it loads a
# kernel module, same caveat as test_detection.sh/test_avd_socket.sh.
#
# Usage: sudo tests/test_netlink.sh
#
set -u

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root (insmod/rmmod, CAP_NET_ADMIN netlink"
    echo "sends, and to start avd). Re-run with sudo."
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AV_DIR="$REPO_ROOT/av"
AVD_DIR="$REPO_ROOT/userspace/avd"
AVCTL_DIR="$REPO_ROOT/userspace/avctl"
TESTS_DIR="$REPO_ROOT/tests"
HELPER="$TESTS_DIR/netlink_test_helper"

# A private, atomically-created directory, not predictable PID-derived
# /tmp paths - this runs as root, and a world-writable /tmp means a
# local user could otherwise pre-create CLEAN_PATH/MALICIOUS_PATH as a
# symlink and have the `cat >` below follow it, truncating an
# attacker-chosen file as root. mktemp -d's random suffix plus its
# 0700 mode close both the guessable-name and the anyone-can-write
# angles at once.
TEST_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_nl.XXXXXX")" || exit 1
TEST_QUARANTINE_DIR="$TEST_TMP_DIR/quarantine"
# Staged rules dir: production rules plus the tests/fixtures/test.yar
# fixture (Suspicious_Shell_Reverse_Shell_String, needed by the
# malicious round-trip section below). The fixture is deliberately NOT
# part of rules/ anymore (it never ships to production - see
# tests/fixtures/test.yar), so stage it here rather than pointing avd
# at rules/ directly. Covered by the existing rm -rf "$TEST_TMP_DIR"
# in cleanup().
TEST_RULES_DIR="$TEST_TMP_DIR/rules"
TEST_SOCK_PATH="$TEST_TMP_DIR/control.sock"
CLEAN_PATH="$TEST_TMP_DIR/clean.sh"
MALICIOUS_PATH="$TEST_TMP_DIR/shell.sh"
AVD_PID=""
DAEMON_X_PID=""
DAEMON_Y_PID=""

# mktemp, not fixed /tmp paths - this runs as root, see
# test_avd_socket.sh's identical comment on why.
BUILD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_netlink_build.XXXXXX")" || exit 1
INSMOD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_netlink_insmod.XXXXXX")" || exit 1
AVD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_netlink_avd.XXXXXX")" || exit 1
RMMOD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_netlink_rmmod.XXXXXX")" || exit 1

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
section() { echo; echo "== $1 =="; }

# Same toolchain-detection rationale as the other integration tests -
# sudo strips any CC=clang LLVM=1 the caller's shell had exported.
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
    # Only reached if a "daemon re-registration" assertion above failed
    # before the section's own close-fd/wait cleanup ran (set -u, not
    # set -e - the script keeps going past a `fail`) - normal runs have
    # already reaped both by the time cleanup() fires.
    for p in "$DAEMON_X_PID" "$DAEMON_Y_PID"; do
        if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
            kill "$p" 2>/dev/null
        fi
    done
    rmmod av 2>/dev/null && echo "  module unloaded" || echo "  module already unloaded"
    rm -rf "$TEST_TMP_DIR"
    rm -f "$BUILD_LOG" "$INSMOD_LOG" "$AVD_LOG" "$RMMOD_LOG"
}
trap cleanup EXIT

section "build"
# Arrays, not bare $(pkg-config ...) inline, so the flags word-split
# deliberately (they're genuinely multi-token) without tripping a
# lint warning about unquoted, unintended word splitting.
IFS=' ' read -r -a NL_CFLAGS <<< "$(pkg-config --cflags libnl-genl-3.0)"
IFS=' ' read -r -a NL_LIBS <<< "$(pkg-config --libs libnl-genl-3.0)"
if make -C "$AV_DIR" "${MAKE_ARGS[@]}" clean >"$BUILD_LOG" 2>&1 && \
   make -C "$AV_DIR" "${MAKE_ARGS[@]}" >>"$BUILD_LOG" 2>&1 && \
   make -C "$AVD_DIR" >>"$BUILD_LOG" 2>&1 && \
   make -C "$AVCTL_DIR" >>"$BUILD_LOG" 2>&1 && \
   gcc -Wall -Wextra -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
       -Wformat -Wformat-security \
       "${NL_CFLAGS[@]}" \
       -o "$HELPER" "$TESTS_DIR/netlink_test_helper.c" \
       "${NL_LIBS[@]}" >>"$BUILD_LOG" 2>&1; then
    pass "av.ko, avd, avctl, and netlink_test_helper built"
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

# Same "nobody" rationale as test_avd_socket.sh's unprivileged-peer
# section: a real non-root process, not just a claimed uid, so
# GENL_ADMIN_PERM's actual capable(CAP_NET_ADMIN) check is what's
# under test.
if command -v setpriv >/dev/null 2>&1 && \
   NOBODY_UID="$(id -u nobody 2>/dev/null)" && NOBODY_GID="$(id -g nobody 2>/dev/null)"; then
    HAVE_SETPRIV=1
else
    HAVE_SETPRIV=0
fi

section "unprivileged AV_C_REGISTER/AV_C_VERDICT rejected"
if [ "$HAVE_SETPRIV" -eq 1 ]; then
    # $HELPER lives under the repo tree, unlike test_avd_socket.sh's
    # equivalent check (which only connects to a socket path, never
    # execs a repo binary as "nobody"). If any parent directory isn't
    # traversable by "nobody" (e.g. a home directory checked out at
    # its common 0750 default), setpriv fails with "Permission
    # denied" before av_nl_register_doit() ever runs - which doesn't
    # contain "permitted", so the greps below would misreport a real
    # environment limitation as a detection FAIL. Probe once and
    # downgrade to SKIP instead.
    UNPRIV_PROBE="$(setpriv --reuid="$NOBODY_UID" --regid="$NOBODY_GID" --clear-groups "$HELPER" resolve 2>&1)"
    if echo "$UNPRIV_PROBE" | grep -qi 'permission denied'; then
        echo "  SKIP: \"nobody\" cannot execute $HELPER (a parent directory isn't"
        echo "  traversable by it, e.g. a repo checked out under a 0750 home dir)"
        HAVE_SETPRIV=0
        SKIPPED_VIA_PROBE=1
    fi
fi

if [ "$HAVE_SETPRIV" -eq 1 ]; then
    UNPRIV_REGISTER="$(setpriv --reuid="$NOBODY_UID" --regid="$NOBODY_GID" --clear-groups "$HELPER" register 2>&1)"
    if echo "$UNPRIV_REGISTER" | grep -qi 'permitted'; then
        pass "unprivileged AV_C_REGISTER rejected"
    else
        fail "unprivileged AV_C_REGISTER not rejected as expected: $UNPRIV_REGISTER"
    fi

    UNPRIV_VERDICT="$(setpriv --reuid="$NOBODY_UID" --regid="$NOBODY_GID" --clear-groups "$HELPER" verdict 1 0 2>&1)"
    if echo "$UNPRIV_VERDICT" | grep -qi 'permitted'; then
        pass "unprivileged AV_C_VERDICT rejected"
    else
        fail "unprivileged AV_C_VERDICT not rejected as expected: $UNPRIV_VERDICT"
    fi
elif [ "${SKIPPED_VIA_PROBE:-0}" -ne 1 ]; then
    echo "  SKIP: setpriv not installed, or the \"nobody\" user/group could not"
    echo "  be resolved - skipping unprivileged-sender checks"
    echo "  (Arch/CachyOS: sudo pacman -S util-linux / Debian/Ubuntu: sudo apt install util-linux)"
fi

section "malformed/oversized AV_C_VERDICT rejected without wedging the module"
MALFORMED_OUT="$("$HELPER" malformed-verdict 2>&1)"
if echo "$MALFORMED_OUT" | grep -qi 'invalid'; then
    pass "AV_C_VERDICT missing AV_A_REQID rejected"
else
    fail "malformed AV_C_VERDICT not rejected as expected: $MALFORMED_OUT"
fi

OVERSIZED_OUT="$("$HELPER" oversized-verdict 2>&1)"
# Unlike malformed-verdict (av_nl_verdict_doit() returns -EINVAL
# directly), this one is rejected by genl's own nla_policy length
# check in the kernel's validate_nla() before doit() ever runs, which
# reports a string past its policy .len as -ERANGE ("Input data out
# of range" via libnl's nl_geterror()), not -EINVAL - match either.
if echo "$OVERSIZED_OUT" | grep -qi 'invalid\|out of range'; then
    pass "AV_C_VERDICT with an over-limit AV_A_RULE_NAME rejected"
else
    fail "oversized AV_C_VERDICT not rejected as expected: $OVERSIZED_OUT"
fi

# Sanity: the module is still alive and answering after two bad
# messages, not wedged/crashed.
if "$HELPER" resolve >/dev/null 2>&1; then
    pass "module still responsive after malformed/oversized messages"
else
    fail "module did not respond to a well-formed request after malformed/oversized ones"
fi

section "portid pinning: only the registered daemon's portid is honored"
dmesg -C
REGISTER_A="$("$HELPER" register 2>&1)"
if echo "$REGISTER_A" | grep -q '^OK'; then
    pass "first AV_C_REGISTER (fake daemon A) accepted"
else
    fail "first AV_C_REGISTER unexpectedly rejected: $REGISTER_A"
fi
# A fresh process = a fresh netlink socket = a different portid, even
# though it's just as privileged (root) as the one that just
# registered - av_nl_verdict_doit() must reject this on portid alone.
VERDICT_B="$("$HELPER" verdict 1 0 2>&1)"
if echo "$VERDICT_B" | grep -qi 'permitted'; then
    pass "AV_C_VERDICT from a different (non-registered) portid rejected"
else
    fail "AV_C_VERDICT from a non-registered portid not rejected as expected: $VERDICT_B"
fi
if dmesg | grep -q 'AV_C_VERDICT from portid .* ignored (not the registered daemon)'; then
    pass "kernel logged the portid-mismatch rejection"
else
    fail "expected portid-mismatch log line not found in dmesg"
    dmesg | tail -10
fi

section "daemon re-registration: a second AV_C_REGISTER is rejected (no hijack)"
# `"$HELPER" batch` keeps one connection (and therefore one stable
# portid) open across multiple commands via a bash coproc, so daemon
# X's portid can be re-tested for real *after* daemon Y attempts to
# register - proving X stays pinned and Y is rejected, not overwritten.
# 2>&1 here, not just on the single-shot invocations elsewhere in this
# script: send_and_report() in netlink_test_helper.c prints "OK" to
# stdout but "ERR ..." to stderr, and a coproc's pipe only carries its
# stdout by default - without this, the rejection replies this section
# most needs to observe (DAEMON_Y_REG, DAEMON_Y_VERDICT) would never
# reach the read end, and `read -u` would hang forever instead of
# failing loudly.
coproc DAEMON_X { "$HELPER" batch 2>&1; }
# bash sets DAEMON_X_PID itself for a named coproc (only an unnamed
# `coproc` without NAME uses $COPROC_PID) - already declared above so
# `set -u` doesn't choke if cleanup() runs before this line does.

# -t 10 on every read below: if a helper process ever exited or wedged
# without printing a reply line, an untimed `read -u` would block this
# whole script (and therefore run_all.sh/the pre-push hook) forever
# instead of failing loudly. A timeout just leaves the target variable
# empty, which the existing pass/fail checks below already treat as a
# failure - no separate handling needed.
# Every register/verdict below is preceded by a `drain` (see the `drain`
# verb in netlink_test_helper.c): while a fake daemon is pinned, *every*
# exec on the system - including this script's own external commands -
# makes the kernel unicast an async SCAN_REQUEST at that portid, and a
# queued upcall makes the next synchronous nl_send_sync() fail with
# "Message sequence number mismatch" (plus stale replies corrupting
# later reads). Draining first, with builtins only ([[ ]], never grep)
# between the drain and its reply, keeps each exchange exact.
# drain_batch takes the coproc's write/read fds as plain numbers -
# `>&"$wfd"` / `-u "$rfd"` resolve them exactly like the literal
# >&"${DAEMON_X[1]}" forms below (all builtins - no exec, no poison).
drain_batch() {
    local wfd="$1" rfd="$2" reply=""
    printf 'drain\n' >&"$wfd"
    read -r -t 10 -u "$rfd" reply
    [[ $reply == OK ]]
}
DAEMON_X_REG=""
drain_batch "${DAEMON_X[1]}" "${DAEMON_X[0]}" || fail "drain of X before register failed"
printf 'register\n' >&"${DAEMON_X[1]}"
read -r -t 10 -u "${DAEMON_X[0]}" DAEMON_X_REG
if [[ $DAEMON_X_REG == OK ]]; then
    pass "daemon X's AV_C_REGISTER accepted"
else
    fail "daemon X's AV_C_REGISTER unexpectedly rejected: $DAEMON_X_REG"
fi

DAEMON_X_VERDICT_BEFORE=""
drain_batch "${DAEMON_X[1]}" "${DAEMON_X[0]}" || fail "drain of X before verdict failed"
printf 'verdict 1 0\n' >&"${DAEMON_X[1]}"
read -r -t 10 -u "${DAEMON_X[0]}" DAEMON_X_VERDICT_BEFORE
if [[ $DAEMON_X_VERDICT_BEFORE == OK ]]; then
    pass "AV_C_VERDICT from X accepted while X is still the pinned daemon"
else
    fail "AV_C_VERDICT from X unexpectedly rejected while X should be pinned: $DAEMON_X_VERDICT_BEFORE"
fi

coproc DAEMON_Y { "$HELPER" batch 2>&1; }

# A second REGISTER from a live second portid must NOT overwrite the
# first (see docs/netlink-protocol.md): expect -EBUSY ("Device or
# resource busy" via nl_geterror), reported as an ERR line on the
# coproc's merged 2>&1 stream.
DAEMON_Y_REG=""
dmesg -C
drain_batch "${DAEMON_Y[1]}" "${DAEMON_Y[0]}" || fail "drain of Y before register failed"
printf 'register\n' >&"${DAEMON_Y[1]}"
read -r -t 10 -u "${DAEMON_Y[0]}" DAEMON_Y_REG
if [[ ${DAEMON_Y_REG,,} == *busy* ]]; then
    pass "daemon Y's AV_C_REGISTER (second registration) rejected with EBUSY"
else
    fail "daemon Y's AV_C_REGISTER unexpectedly accepted (hijack not rejected): $DAEMON_Y_REG"
fi
if dmesg | grep -q 'AV_C_REGISTER from portid .* rejected'; then
    pass "kernel logged the REGISTER hijack rejection at pr_alert"
else
    fail "expected REGISTER-rejection log line not found in dmesg"
    dmesg | tail -10
fi

# The actual proof of non-replacement: X's portid, which was accepted
# above, must still be accepted, and Y's must be rejected.
DAEMON_X_VERDICT_AFTER=""
drain_batch "${DAEMON_X[1]}" "${DAEMON_X[0]}" || fail "drain of X before re-verdict failed"
printf 'verdict 1 0\n' >&"${DAEMON_X[1]}"
read -r -t 10 -u "${DAEMON_X[0]}" DAEMON_X_VERDICT_AFTER
if [[ $DAEMON_X_VERDICT_AFTER == OK ]]; then
    pass "AV_C_VERDICT from X (original daemon) still accepted after Y rejected - portid was not replaced"
else
    fail "AV_C_VERDICT from X rejected after Y attempt - pinning was lost: $DAEMON_X_VERDICT_AFTER"
fi

DAEMON_Y_VERDICT=""
drain_batch "${DAEMON_Y[1]}" "${DAEMON_Y[0]}" || fail "drain of Y before verdict failed"
printf 'verdict 1 0\n' >&"${DAEMON_Y[1]}"
read -r -t 10 -u "${DAEMON_Y[0]}" DAEMON_Y_VERDICT
if [[ ${DAEMON_Y_VERDICT,,} == *permitted* ]]; then
    pass "AV_C_VERDICT from Y (rejected daemon) rejected - never pinned"
else
    fail "AV_C_VERDICT from Y unexpectedly accepted: $DAEMON_Y_VERDICT"
fi

# Capture both PIDs before waiting on either - empirically, once the
# first `wait` reaps a terminated coproc, bash's job-control
# bookkeeping unsets *both* DAEMON_X_PID and DAEMON_Y_PID (not just
# the one just reaped), which would make the second `wait "$DAEMON_
# Y_PID"` below fail under `set -u` ("unbound variable") rather than
# actually wait.
X_WAIT_PID="$DAEMON_X_PID"
Y_WAIT_PID="$DAEMON_Y_PID"
# EOF on stdin ends batch mode's read loop cleanly (see
# netlink_test_helper.c) - no signal needed for the normal case.
# shellcheck disable=SC2093,SC1083
# ^ closing a coproc's fd this way isn't "exec replacing the shell"
#   (no command follows the redirection) and the {name[index]} form is
#   real bash syntax for the fd stored in that array slot, not a
#   literal brace - shellcheck's parser doesn't know this form.
exec {DAEMON_X[1]}>&-
# shellcheck disable=SC2093,SC1083
exec {DAEMON_Y[1]}>&-
wait "$X_WAIT_PID" 2>/dev/null
wait "$Y_WAIT_PID" 2>/dev/null
DAEMON_X_PID=""
DAEMON_Y_PID=""

section "start avd (throwaway quarantine dir + control socket)"
mkdir -p "$TEST_QUARANTINE_DIR" "$TEST_RULES_DIR"
cp "$REPO_ROOT"/rules/*.yar "$TEST_RULES_DIR"/
cp "$REPO_ROOT"/tests/fixtures/test.yar "$TEST_RULES_DIR"/
dmesg -C
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
# avd's own AV_C_REGISTER on startup should now be the pinned daemon -
# both fake daemons exited above, so NETLINK_URELEASE already cleared
# the slot (a live second REGISTER would be rejected with -EBUSY).
sleep 1
if dmesg | grep -q 'kernel-av: netlink daemon registered'; then
    pass "avd re-registered itself as the pinned daemon"
else
    fail "expected avd's own AV_C_REGISTER log line not found in dmesg"
fi

section "scan-request round trip end to end (clean)"
cat > "$CLEAN_PATH" <<'EOF'
#!/bin/sh
echo "just a harmless test script for tests/test_netlink.sh"
EOF
chmod +x "$CLEAN_PATH"
# The clean-verdict log line is pr_info_ratelimited() (see its comment
# in av_work_fn() - it fires for every daemon-path exec system-wide,
# so it's rate-limited to avoid a dmesg line per exec), unlike the
# non-rate-limited pr_alert() a kill uses below. On a busy machine with
# other exec activity sharing that same rate-limit budget, one attempt
# can be suppressed even though the round trip itself succeeded -
# retry a few times rather than treating that as a real failure.
CLEAN_OK=0
for _ in 1 2 3; do
    dmesg -C
    "$CLEAN_PATH" >/dev/null 2>&1
    sleep 1
    if dmesg | grep -q "event=clean type=daemon path=\"$CLEAN_PATH\""; then
        CLEAN_OK=1
        break
    fi
done
if [ "$CLEAN_OK" -eq 1 ]; then
    pass "clean exec round-tripped through avd and logged clean"
else
    fail "expected daemon-path clean log line not found in dmesg after retries"
    dmesg | tail -10
fi

section "scan-request round trip end to end (malicious, YARA-only - no sigtable entry)"
# Matches tests/fixtures/test.yar's Suspicious_Shell_Reverse_Shell_String rule
# ("/bin/sh -i") - deliberately inert (just echoes the string, never
# actually execs a shell) so this test can't accidentally open a real
# shell if detection fails for some other reason. This has no sigtable
# entry (unique content -> unique hash), so a kill here can only have
# come from the daemon/YARA path, not the kernel-side signature table -
# unlike test_detection.sh's EICAR case, which is deliberately a
# signature-table hit and never reaches the netlink channel at all.
cat > "$MALICIOUS_PATH" <<'EOF'
#!/bin/sh
echo "/bin/sh -i"
EOF
chmod +x "$MALICIOUS_PATH"
dmesg -C
"$MALICIOUS_PATH" >/dev/null 2>&1
sleep 1
# avd comma-joins every rule name that crossed the score threshold
# (see rules/heuristics.yar's WEIGHT META comment), not just the one
# this test cares about - some other rule (e.g. an ELF/entry-point
# heuristic) may also fire on this file, so match the rule name as a
# substring of `reason`, not the whole field.
if dmesg | grep -qi "event=detected action=kill type=daemon path=\"$MALICIOUS_PATH\".*reason=\"daemon:[^\"]*Suspicious_Shell_Reverse_Shell_String"; then
    pass "malicious exec round-tripped through avd/YARA and was killed"
else
    fail "expected daemon-path detected/kill log line not found in dmesg"
    dmesg | tail -10
fi

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
echo "netlink tests: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
