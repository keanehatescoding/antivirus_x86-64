#!/usr/bin/env bash
#
# tests/test_fanotify_exec.sh - end-to-end coverage for avd's fanotify
# pre-exec enforcement (#176, docs/fanotify-enforcement.md): with
# AVD_FANOTIFY=1 avd puts FAN_MARK_FILESYSTEM exec-permission marks on
# every local filesystem and every exec on the machine waits for its
# verdict. That is exactly why this script REFUSES TO RUN OUTSIDE A
# VIRTUAL MACHINE: a bug here wedges or denies execs system-wide.
#
# Covers, in order:
#   - baseline exec cost with avd running but enforcement off
#   - enforcement comes up, STATUS reports fanotify_active
#   - a filesystem mounted after startup gets marked (mountinfo POLLPRI)
#   - a clean exec runs; repeat execs are answered from the verdict
#     cache (fan_cache_hits moves)
#   - EICAR (kernel-seeded sha256 signature, snapshotted by avd) and a
#     YARA-matching script are refused with EPERM before they run
#   - a sha256 signature added via avctl after a binary was cached
#     clean is enforced on that binary's next exec (signature refresh
#     invalidates the cache)
#   - exec cost with enforcement on, cached and uncached
#   - watchdog: with the only worker pinned, an exec is answered by the
#     daemon policy after AVD_FANOTIFY_TIMEOUT_MS - allowed under
#     fail-open, EPERM under fail-closed
#
# Usage, from the host (boots the running kernel in a throwaway
# virtme-ng guest - see tests/run_fanotify_vng.sh):
#   tests/run_fanotify_vng.sh
# or, inside a VM you are happy to break:
#   sudo tests/test_fanotify_exec.sh
#
set -u

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root (insmod, fanotify marks). Re-run with sudo."
    exit 1
fi

# systemd-detect-virt --vm is not available in every minimal guest, so
# an explicit opt-in exists - but it has to be spelled out, never a
# default.
if ! systemd-detect-virt --vm --quiet 2>/dev/null && \
   [ "${AV_FANOTIFY_TEST_I_AM_IN_A_VM:-}" != "yes" ]; then
    echo "REFUSING: this test mount-marks every local filesystem with"
    echo "FAN_OPEN_EXEC_PERM and must only run inside a VM."
    echo "Use tests/run_fanotify_vng.sh, or set"
    echo "AV_FANOTIFY_TEST_I_AM_IN_A_VM=yes if detection misses your VM."
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091 # sourced at runtime; lint it on its own
. "$REPO_ROOT/tests/avd_guard.sh"
avd_guard || exit 1
AV_DIR="$REPO_ROOT/av"
AVD_DIR="$REPO_ROOT/userspace/avd"
AVCTL="$REPO_ROOT/userspace/avctl/avctl"
POLICY_PROC=/proc/kernel_av_daemon_policy

TEST_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_fan.XXXXXX")" || exit 1
TEST_RULES_DIR="$TEST_TMP_DIR/rules"
TEST_QUARANTINE_DIR="$TEST_TMP_DIR/quarantine"
TEST_SOCK_PATH="$TEST_TMP_DIR/control.sock"
AVD_LOG="$TEST_TMP_DIR/avd.log"
BUILD_LOG="$TEST_TMP_DIR/build.log"
# Fixtures live on tmpfs mounts this script owns, not on whatever /tmp
# happens to be (an overlay under virtme-ng), so what gets marked and
# executed is under test control.
FIX="$TEST_TMP_DIR/fix"
HOT="$TEST_TMP_DIR/hot"
HOLD="$TEST_TMP_DIR/hold"
AVD_PID=""
MOUNTED=()

# shellcheck disable=SC2016 # literal $, not an expansion
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

N_CACHED="${AV_FAN_BENCH_N:-1000}"
N_COLD=40

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
section() { echo; echo "== $1 =="; }

# A sleep that execs nothing: while the watchdog section has the only
# scan worker pinned, every uncached exec - including /usr/bin/sleep -
# waits on avd, so the polling loops use a builtin read timeout.
exec 9<> <(:)
nap() { read -r -t "$1" -u 9 _ 2>/dev/null; true; }

now_us() { local t=${EPOCHREALTIME/./}; echo "$t"; }

# Runs $1 directly from bash (fork + execve, no helper binary) and
# prints "rc=N" or "EPERM". bash reports an execve() EPERM as
# "Operation not permitted" with status 126; a file the kernel cannot
# exec (ENOEXEC, e.g. EICAR without enforcement) is instead run as a
# shell script, which never says that.
try_exec() {
    local err rc
    err="$( { "$1" >/dev/null; } 2>&1 )"
    rc=$?
    if [ "$rc" -eq 126 ] && [[ "$err" == *"Operation not permitted"* ]]; then
        echo EPERM
    else
        echo "rc=$rc"
    fi
}

# STATUS data row field N (1-based). python rather than socat: it is
# already in every virtme-ng guest (shared host /usr).
status_field() {
    python3 - "$TEST_SOCK_PATH" "$1" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(b"STATUS\n")
buf = b""
while not buf.endswith(b"END\n"):
    d = s.recv(4096)
    if not d:
        break
    buf += d
rows = buf.decode().split("\n")
print(rows[2].split("\t")[int(sys.argv[2]) - 1] if len(rows) > 2 else "")
EOF
}

# Bounded: a shutdown that wedges is a bug worth a FAIL with the
# threads' kernel stacks, not a hung test.
stop_avd() {
    local t
    if [ -n "$AVD_PID" ] && kill -0 "$AVD_PID" 2>/dev/null; then
        kill "$AVD_PID" 2>/dev/null
        for _ in {1..40}; do
            kill -0 "$AVD_PID" 2>/dev/null || break
            nap 0.25
        done
        if kill -0 "$AVD_PID" 2>/dev/null; then
            fail "avd did not exit within 10 s of SIGTERM"
            for t in /proc/"$AVD_PID"/task/*; do
                echo "    thread $(cat "$t/comm") wchan=$(cat "$t/wchan")"
                sed 's/^/      /' "$t/stack" 2>/dev/null
            done
            tail -5 "$AVD_LOG" | sed 's/^/    log: /'
            kill -9 "$AVD_PID" 2>/dev/null
        fi
        wait "$AVD_PID" 2>/dev/null
    fi
    AVD_PID=""
}

# start_avd [ENV=VAL ...] - fresh socket each time; stdout line-buffered
# so the log can be polled.
start_avd() {
    rm -f "$TEST_SOCK_PATH"
    : > "$AVD_LOG"
    (
        cd "$REPO_ROOT" || exit 1
        exec env "$@" stdbuf -oL "$AVD_DIR/avd" "$TEST_RULES_DIR" \
            corpus/fuzzy_hashes.txt "$TEST_QUARANTINE_DIR" \
            corpus/tlsh_hashes.txt "$TEST_SOCK_PATH" >>"$AVD_LOG" 2>&1
    ) &
    AVD_PID=$!
    for _ in {1..40}; do
        [ -S "$TEST_SOCK_PATH" ] && return 0
        kill -0 "$AVD_PID" 2>/dev/null || break
        nap 0.25
    done
    return 1
}

wait_log() {
    local pattern="$1" tries="$2" i
    for ((i = 0; i < tries; i++)); do
        grep -qF -- "$pattern" "$AVD_LOG" && return 0
        nap 0.25
    done
    return 1
}

# A runnable ELF whose hash nothing has seen: /bin/true padded with a
# unique number of trailing zero bytes (ignored by the loader). The
# padding is done by truncate, not a bash `>>`: av.ko's behavioral
# engine counts writes per pid, and this shell writing a hundred-odd
# files in a burst gets it killed as a ransomware pattern.
FRESH_N=0
fresh_true() {
    FRESH_N=$((FRESH_N + 1))
    cp /bin/true "$1" && truncate -s "+$FRESH_N" "$1" && chmod 755 "$1"
}

# Average microseconds per exec: loop_us N BIN execs one binary N
# times (cache hits once warm); cold_us BIN... execs each once.
loop_us() {
    local n="$1" bin="$2" t0 t1 i
    t0=$(now_us)
    for ((i = 0; i < n; i++)); do "$bin"; done
    t1=$(now_us)
    echo $(( (t1 - t0) / n ))
}
cold_us() {
    local t0 t1 f
    t0=$(now_us)
    for f in "$@"; do "$f"; done
    t1=$(now_us)
    echo $(( (t1 - t0) / $# ))
}

cleanup() {
    section "cleanup"
    [ -w "$POLICY_PROC" ] && echo fail-open > "$POLICY_PROC" 2>/dev/null
    : > "$HOLD/release" 2>/dev/null
    stop_avd
    echo "  avd stopped"
    for ((i = ${#MOUNTED[@]} - 1; i >= 0; i--)); do
        umount "${MOUNTED[$i]}" 2>/dev/null
    done
    rmmod av 2>/dev/null && echo "  module unloaded"
    rm -rf "$TEST_TMP_DIR"
}
trap cleanup EXIT

section "build"
MAKE_ARGS=()
if grep -q "clang version" /proc/version 2>/dev/null; then
    MAKE_ARGS=(CC=clang LLVM=1)
fi
if make -C "$AV_DIR" "${MAKE_ARGS[@]}" clean >"$BUILD_LOG" 2>&1 && \
   make -C "$AV_DIR" "${MAKE_ARGS[@]}" >>"$BUILD_LOG" 2>&1 && \
   make -C "$AVD_DIR" >>"$BUILD_LOG" 2>&1 && \
   make -C "$REPO_ROOT/userspace/avctl" >>"$BUILD_LOG" 2>&1; then
    pass "av.ko, avd and avctl built"
else
    fail "build failed"
    cat "$BUILD_LOG"
    exit 1
fi

section "load module"
if insmod "$AV_DIR/av.ko" 2>"$TEST_TMP_DIR/insmod.log"; then
    pass "module loaded"
else
    fail "insmod failed: $(cat "$TEST_TMP_DIR/insmod.log")"
    exit 1
fi

mkdir -p "$TEST_RULES_DIR" "$TEST_QUARANTINE_DIR" "$FIX" "$HOT" "$HOLD"
cp "$REPO_ROOT"/rules/*.yar "$REPO_ROOT"/tests/fixtures/test.yar "$TEST_RULES_DIR"/
mount -t tmpfs -o mode=0755,size=64m avtest-fix "$FIX" && MOUNTED+=("$FIX")

CLEAN="$FIX/clean_true"
fresh_true "$CLEAN"
COLD_A=() COLD_B=() COLD_C=()
for i in $(seq 1 "$N_COLD"); do
    fresh_true "$FIX/cold_a_$i"; COLD_A+=("$FIX/cold_a_$i")
    fresh_true "$FIX/cold_b_$i"; COLD_B+=("$FIX/cold_b_$i")
    fresh_true "$FIX/cold_c_$i"; COLD_C+=("$FIX/cold_c_$i")
done

section "baseline: avd running, enforcement off"
if start_avd AVD_FANOTIFY=0; then
    pass "avd started without fanotify"
else
    fail "avd did not start"; cat "$AVD_LOG"; exit 1
fi
if [ "$(status_field 12)" = "0" ]; then
    pass "STATUS fanotify_active = 0 when AVD_FANOTIFY is off"
else
    fail "STATUS fanotify_active not 0 with enforcement off"
fi
"$CLEAN"
BASE_HOT=$(loop_us "$N_CACHED" "$CLEAN")
BASE_COLD=$(cold_us "${COLD_A[@]}")
echo "  baseline: ${BASE_HOT} us/exec repeated, ${BASE_COLD} us/exec first-seen"
stop_avd

section "enforcement on"
if start_avd AVD_FANOTIFY=1 && wait_log "fanotify pre-exec enforcement active" 20; then
    pass "avd started with pre-exec enforcement active"
else
    fail "enforcement did not come up"; cat "$AVD_LOG"; exit 1
fi
if grep -qF "enforcing pre-exec scans on $FIX " "$AVD_LOG"; then
    pass "fixture tmpfs marked at startup"
else
    fail "fixture tmpfs not marked: $(grep fanotify "$AVD_LOG")"
fi
if [ "$(status_field 12)" = "1" ]; then
    pass "STATUS fanotify_active = 1"
else
    fail "STATUS fanotify_active not 1"
fi

section "filesystem mounted after startup is marked"
mount -t tmpfs -o mode=0755,size=16m avtest-hot "$HOT" && MOUNTED+=("$HOT")
if wait_log "enforcing pre-exec scans on $HOT " 20; then
    pass "new mount picked up from mountinfo and marked"
else
    fail "new mount was not marked"
fi
printf '%s' "$EICAR" > "$HOT/eicar.com"
chmod 755 "$HOT/eicar.com"
R="$(try_exec "$HOT/eicar.com")"
if [ "$R" = EPERM ]; then
    pass "EICAR exec on the hot-marked mount refused with EPERM"
else
    fail "EICAR exec on the hot-marked mount: $R (expected EPERM)"
fi

section "clean exec and verdict cache"
R="$(try_exec "$CLEAN")"
if [ "$R" = "rc=0" ]; then
    pass "clean binary runs"
else
    fail "clean binary: $R"
fi
HITS0="$(status_field 14)"
for _ in 1 2 3 4 5; do "$CLEAN"; done
HITS1="$(status_field 14)"
if [ -n "$HITS0" ] && [ -n "$HITS1" ] && [ "$HITS1" -ge $((HITS0 + 5)) ]; then
    pass "repeat execs answered from the cache (fan_cache_hits $HITS0 -> $HITS1)"
else
    fail "fan_cache_hits did not move by 5: '$HITS0' -> '$HITS1'"
fi

section "malicious execs refused before they run"
printf '%s' "$EICAR" > "$FIX/eicar.com"
chmod 755 "$FIX/eicar.com"
R="$(try_exec "$FIX/eicar.com")"
if [ "$R" = EPERM ]; then
    pass "EICAR (kernel-seeded sha256 signature) refused with EPERM"
else
    fail "EICAR: $R (expected EPERM)"
fi
MARKER="$FIX/yara_ran"
printf '#!/bin/sh\n# test fixture: /bin/sh -i\n: > %s\n' "$MARKER" > "$FIX/rev.sh"
chmod 755 "$FIX/rev.sh"
R="$(try_exec "$FIX/rev.sh")"
if [ "$R" = EPERM ] && [ ! -e "$MARKER" ]; then
    pass "YARA-matching script refused with EPERM and never ran"
else
    fail "YARA-matching script: $R, ran=$([ -e "$MARKER" ] && echo yes || echo no)"
fi
if grep -q "BLOCKED exec of \"$FIX/rev.sh\"" "$AVD_LOG"; then
    pass "avd logged the block"
else
    fail "no BLOCKED line for rev.sh in the avd log"
fi
DENIED="$(status_field 15)"
if [ -n "$DENIED" ] && [ "$DENIED" -ge 3 ]; then
    pass "STATUS fan_denied counts the refusals ($DENIED)"
else
    fail "STATUS fan_denied = '$DENIED', expected >= 3"
fi

section "signature added at runtime overrides a cached clean verdict"
SIGBIN="$FIX/sig_true"
fresh_true "$SIGBIN"
R="$(try_exec "$SIGBIN")"
"$SIGBIN"   # second exec: cached
if [ "$R" = "rc=0" ]; then
    pass "binary runs (and is now cached clean)"
else
    fail "binary before signature: $R"
fi
SIGHEX="$(sha256sum "$SIGBIN" | cut -d' ' -f1)"
if "$AVCTL" add sha256 "$SIGHEX" FanTest_RuntimeSig >/dev/null; then
    pass "sha256 signature added via avctl"
else
    fail "avctl add failed"
fi
R=""
for _ in {1..30}; do
    [ -e "$SIGBIN" ] || break
    R="$(try_exec "$SIGBIN")"
    [ "$R" = EPERM ] && break
    nap 0.25
done
if [ "$R" = EPERM ]; then
    pass "same binary refused with EPERM once avd refreshed its snapshot"
else
    fail "binary still runs after the signature was added: $R"
fi
"$AVCTL" del sha256 "$SIGHEX" >/dev/null 2>&1

section "exec cost with enforcement on"
"$CLEAN"
FAN_HOT=$(loop_us "$N_CACHED" "$CLEAN")
FAN_COLD=$(cold_us "${COLD_B[@]}")
echo "  enforcing: ${FAN_HOT} us/exec repeated (cache hit), ${FAN_COLD} us/exec first-seen (full scan)"
echo "  delta vs enforcement off: $((FAN_HOT - BASE_HOT)) us/exec cached, $((FAN_COLD - BASE_COLD)) us/exec uncached"
pass "exec cost measured (${N_CACHED} cached, ${N_COLD} uncached execs)"
stop_avd

section "watchdog answers by daemon policy when no verdict arrives"
# One worker, pinned by the test hold gate on the first scan to arrive;
# every later cache miss queues behind it and must be answered by the
# watchdog. From here until the release, nothing in this section may
# exec an uncached binary it relies on (they would wait too) - only
# builtins, and writes to the policy file via echo.
TIMEOUT_MS=600
if start_avd AVD_FANOTIFY=1 AVD_SCAN_THREADS=1 AVD_TEST_SCAN_HOLD_PATH="$HOLD" \
        AVD_FANOTIFY_TIMEOUT_MS=$TIMEOUT_MS && \
   wait_log "fanotify pre-exec enforcement active" 20; then
    pass "avd restarted with one worker, hold gate and ${TIMEOUT_MS} ms watchdog"
else
    fail "avd did not restart for the watchdog section"; cat "$AVD_LOG"; exit 1
fi
"${COLD_C[0]}" &   # takes the hold (or queues behind whatever did)
TRIGGER_PID=$!
for _ in {1..40}; do
    [ -e "$HOLD/entered" ] && break
    nap 0.25
done
wait "$TRIGGER_PID"
if [ -e "$HOLD/entered" ]; then
    pass "scan worker pinned"
else
    fail "hold gate never entered"
fi

T0=$(now_us)
R="$(try_exec "${COLD_C[1]}")"
EL=$(( ($(now_us) - T0) / 1000 ))
if [ "$R" = "rc=0" ] && [ "$EL" -ge $((TIMEOUT_MS - 50)) ]; then
    pass "fail-open: exec allowed by the watchdog after ${EL} ms"
else
    fail "fail-open: $R after ${EL} ms (expected rc=0 after >= ${TIMEOUT_MS} ms)"
fi

echo fail-closed > "$POLICY_PROC"
T0=$(now_us)
R="$(try_exec "${COLD_C[2]}")"
EL=$(( ($(now_us) - T0) / 1000 ))
echo fail-open > "$POLICY_PROC"
if [ "$R" = EPERM ] && [ "$EL" -ge $((TIMEOUT_MS - 50)) ]; then
    pass "fail-closed: exec refused by the watchdog after ${EL} ms"
else
    fail "fail-closed: $R after ${EL} ms (expected EPERM after >= ${TIMEOUT_MS} ms)"
fi
: > "$HOLD/release"

if grep -q "allowed by daemon policy (fail-open)" "$AVD_LOG" && \
   grep -q "DENIED by daemon policy (fail-closed)" "$AVD_LOG"; then
    pass "both watchdog answers logged"
else
    fail "watchdog log lines missing"
fi
FALLBACKS="$(status_field 16)"
if [ -n "$FALLBACKS" ] && [ "$FALLBACKS" -ge 2 ]; then
    pass "STATUS fan_fallbacks counts them ($FALLBACKS)"
else
    fail "STATUS fan_fallbacks = '$FALLBACKS', expected >= 2"
fi
R="$(try_exec "${COLD_C[3]}")"
if [ "$R" = "rc=0" ]; then
    pass "execs flow normally after the worker is released"
else
    fail "exec after release: $R"
fi

stop_avd
# avd quarantined (removed) the earlier eicar.com; without a fresh copy
# a missing file would pass this check without any exec happening.
# Expect the kernel's post-exec bprm_check fallback (SIGKILL, rc=137)
# rather than a pre-exec EPERM.
printf '%s' "$EICAR" > "$FIX/eicar.com"
chmod 755 "$FIX/eicar.com"
if [ ! -e "$FIX/eicar.com" ]; then
    fail "could not recreate the EICAR fixture"
else
    R="$(try_exec "$FIX/eicar.com")"
    if [ "$R" != EPERM ]; then
        pass "marks go away with avd (EICAR no longer refused pre-exec, $R)"
    else
        fail "exec still refused after avd exited"
    fi
fi

echo
echo "==================================="
echo "fanotify exec enforcement: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
