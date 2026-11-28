#!/usr/bin/env bash
# shellcheck disable=SC1091 # /etc/os-release is a guest file, not in this checkout
# avd_unit_vm_guest.sh - runs inside a throwaway Ubuntu or Fedora cloud VM
# booted by .github/workflows/avd-unit-systemd.yml.
#
# Builds avd from this checkout, installs it through the real `make install`
# (which renders packaging/avd.service), loads av.ko, starts avd.service and
# checks that it really scans under the shipped unit. This is the check the
# privilege-separation default needed before #252: the end-to-end tests run
# avd outside systemd under setpriv, which cannot reproduce what systemd
# 258/259/262 do to a root service's capability sets (see #254).
#
# Usage: sudo bash avd_unit_vm_guest.sh ubuntu|fedora [checkout-dir]
set -euo pipefail

DISTRO=${1:?ubuntu|fedora}
REPO=${2:-/tmp/avtest}
SINCE=$(date +%s)

log() { printf '\n=== %s ===\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    journalctl -u avd.service --no-pager -n 80 2>/dev/null || true
    exit 1
}

log "environment"
. /etc/os-release
echo "distro=$PRETTY_NAME kernel=$(uname -r) systemd=$(systemctl --version | head -1)"
[ "$(id -u)" -eq 0 ] || fail "must run as root"

log "build dependencies"
case "$DISTRO" in
    ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq build-essential "linux-headers-$(uname -r)" \
            git pkg-config libseccomp-dev libnl-genl-3-dev libyara-dev \
            libfuzzy-dev auditd >/dev/null
        ;;
    fedora)
        dnf install -y -q --skip-unavailable gcc make \
            "kernel-devel-$(uname -r)" git pkgconf-pkg-config \
            libseccomp-devel libnl3-devel yara-devel ssdeep-devel audit >/dev/null
        ;;
    *) fail "unknown distro: $DISTRO" ;;
esac

log "build from the checkout"
cd "$REPO"
make -C av >/dev/null
make -C userspace/avctl >/dev/null
make -C userspace/avd >/dev/null

log "install avd and its unit, then check what was installed"
make -C userspace/avd install PREFIX=/usr >/dev/null
UNIT=/usr/lib/systemd/system/avd.service
grep -q '^Environment=AVD_PRIVSEP=1' "$UNIT" || fail "unit does not enable AVD_PRIVSEP=1"
grep -q '^NoNewPrivileges=yes' "$UNIT" || fail "unit lost NoNewPrivileges=yes"
if grep -q '^AmbientCapabilities=' "$UNIT"; then
    echo "unit: $(grep -E '^(Environment=AVD_PRIVSEP|AmbientCapabilities|NoNewPrivileges)' "$UNIT" | tr '\n' ' ')"
fi

log "create the unprivileged worker user before loading the module"
getent passwd hyprav-scan >/dev/null || useradd -r -s /usr/sbin/nologin -d / hyprav-scan
getent group hyprav >/dev/null || groupadd -r hyprav
id hyprav-scan

log "load module, start the shipped unit"
cd "$REPO/av"
rmmod av 2>/dev/null || true
insmod av.ko
lsmod | grep -E '^av[[:space:]]' || fail "av.ko is not loaded"
systemctl daemon-reload
systemctl enable avd.service >/dev/null 2>&1 || true
systemctl restart avd.service
for _ in $(seq 1 30); do
    systemctl is-active --quiet avd.service && break
    sleep 1
done
state=$(systemctl is-active avd.service)
[ "$state" = active ] || fail "avd.service is $state, not active"
pid=$(systemctl show -p MainPID --value avd.service)
[ -n "$pid" ] && [ "$pid" != 0 ] || fail "no avd MainPID"

JOURNAL="journalctl -u avd.service --since @$SINCE --no-pager"
log "assert the daemon is under the unit"
# Do not assert on journal startup lines: with av.ko loaded, the scan flood
# can make journald rate-limit them away. The live process state below is
# the evidence that privsep actually came up.
if journalctl -u avd.service --no-pager | grep -q 'lockdown step 2 failed'; then
    fail "spawner failed capset() at lockdown step 2"
fi
tr '\0' '\n' <"/proc/$pid/environ" | grep -qx 'AVD_PRIVSEP=1' || fail "AVD_PRIVSEP=1 not in avd's environment"
nnp=$(awk '/^NoNewPrivs/{print $2}' "/proc/$pid/status")
[ "$nnp" = 1 ] || fail "NoNewPrivs=$nnp, expected 1"
# The parent narrows its own capabilities after the spawner starts, so the
# CAP_SETUID check belongs on the spawner (the child that does capset()).
spawner=""
for _ in $(seq 1 10); do
    spawner=$(pgrep -P "$pid" -x avd | head -1 || true)
    [ -n "$spawner" ] && break
    sleep 1
done
[ -n "$spawner" ] || fail "no spawner child of avd pid $pid"
sprm=$(awk '/^CapPrm/{print $2}' "/proc/$spawner/status")
[ -n "$sprm" ] || fail "no CapPrm in /proc/$spawner/status"
if [ $(( (16#$sprm & 0x1e0) != 0x1e0 )) -ne 0 ]; then
    fail "spawner lacks one of its four capabilities (CapPrm=$sprm)"
fi
snnp=$(awk '/^NoNewPrivs/{print $2}' "/proc/$spawner/status")
[ "$snnp" = 1 ] || fail "spawner NoNewPrivs=$snnp, expected 1"
echo "pid=$pid NNP=$nnp CapPrm=$(awk '/^CapPrm/{print $2}' "/proc/$pid/status")"
echo "spawner=$spawner NNP=$snnp CapPrm=$sprm"

log "real scan workload (module loaded, worker user present)"
for _ in $(seq 1 60); do
    /usr/bin/ls /usr/bin >/dev/null 2>&1
    /usr/bin/cat /etc/os-release >/dev/null
    /usr/bin/id >/dev/null
done
sleep 3
scans=$($JOURNAL | grep -c 'scan request' || true)
inconclusive=$($JOURNAL | grep -ci 'result inconclusive' || true)
workers=$(ps -eo user:20,comm | awk '$1 == "hyprav-scan" && $2 == "avd" {n++} END {print n+0}')
sigsys=$(dmesg | grep -ic SIGSYS || true)
seccomp=0
if [ -f /var/log/audit/audit.log ]; then
    seccomp=$(grep -c type=SECCOMP /var/log/audit/audit.log || true)
fi
echo "scans=$scans inconclusive=$inconclusive workers=$workers audit_seccomp=$seccomp sigsys=$sigsys"
[ "$scans" -gt 0 ] || fail "no scan requests reached avd"
[ "$inconclusive" -eq 0 ] || fail "scans were inconclusive"
[ "$workers" -gt 0 ] || fail "no hyprav-scan workers"
[ "$seccomp" -eq 0 ] || fail "SECCOMP audit records appeared"
[ "$sigsys" -eq 0 ] || fail "SIGSYS appeared in dmesg"

log "PASS: avd ran real scans under the shipped unit on $(. /etc/os-release; echo "$PRETTY_NAME")"
systemctl stop avd.service
rmmod av 2>/dev/null || true
