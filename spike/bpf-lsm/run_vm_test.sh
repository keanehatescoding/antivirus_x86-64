#!/usr/bin/env bash
#
# run_vm_test.sh - prove the spike's BPF LSM program actually DENIES an
# exec, by attaching it inside a throwaway QEMU VM.
#
# This is the companion to run_spike.sh, and exists because of that
# script's stated limit: run_spike.sh loads the program and shows the
# verifier accepts a negative return from a sleepable lsm.s/ hook, but
# it attaches nothing, so it cannot show enforcement. This does.
#
# What it proves:
#   - the program attaches to bprm_check_security on a real kernel
#   - an exec of a file NOT in blocked_files still succeeds (control)
#   - an exec of a file IN blocked_files fails with EPERM
#
# The control matters: a program that broke exec outright would deny
# the blocked target too, and without the control that failure would
# read as a pass.
#
# Why a VM and not the host: a bad program on bprm_check_security denies
# every exec on the machine, and once no exec works you cannot run
# bpftool to detach it. There is no safe way to try this on a live host,
# so the enforcement half of the spike lives here.
#
# Rather than building a kernel, this boots the HOST's kernel image,
# which already has the needed CONFIG_BPF_LSM=y and CONFIG_DEBUG_INFO_BTF=y
# (BPF LSM attach needs vmlinux BTF; the tinyconfig kernel the CI boot
# test builds has neither). Nothing from the host filesystem is mounted -
# the VM gets only the initramfs assembled below.
#
# Usage: ./run_vm_test.sh [/boot/vmlinuz-...]
# No root needed: QEMU runs unprivileged, and the program is only ever
# loaded inside the guest, where it is already root.

set -uo pipefail

cd "$(dirname "$0")" || exit 1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# --- locate a usable kernel image -------------------------------------

KERNEL="${1:-}"
if [ -z "$KERNEL" ]; then
    for candidate in /boot/vmlinuz-linux-cachyos /boot/vmlinuz-linux-zen \
                     /boot/vmlinuz-linux /boot/vmlinuz "/boot/vmlinuz-$(uname -r)"; do
        if [ -r "$candidate" ]; then
            KERNEL="$candidate"
            break
        fi
    done
fi
[ -n "$KERNEL" ] || fail "no readable kernel image found; pass one as \$1"
[ -r "$KERNEL" ] || fail "kernel image not readable: $KERNEL"

command -v qemu-system-x86_64 >/dev/null || fail "qemu-system-x86_64 not installed"
command -v cpio >/dev/null || fail "cpio not installed"

echo "==> kernel image: $KERNEL"

# The .bpf.o is generated against the HOST's BTF (see the Makefile's
# vmlinux.h rule), so the booted image should be the running kernel.
# Read the version out of the image itself rather than guessing from its
# filename, which carries a flavour name and not a version. Warn rather
# than refuse: an explicitly-passed image is the caller's decision, and
# CO-RE exists precisely to tolerate some drift.
IMG_VERSION="$(file -b "$KERNEL" 2>/dev/null | grep -oE 'version [^ ]+' | cut -d' ' -f2)"
if [ -n "$IMG_VERSION" ] && [ "$IMG_VERSION" != "$(uname -r)" ]; then
    echo "    note: image is $IMG_VERSION but the BPF object was built" \
         "against the running kernel's BTF ($(uname -r))"
fi

# --- build ------------------------------------------------------------

echo "==> building BPF object"
make av_lsm_spike.bpf.o >/dev/null || fail "BPF object build failed"

echo "==> building guest binaries"
# The loader must link libbpf, which ships shared-only on this system -
# hence the ldd walk below rather than a single static init.
gcc -Wall -Wextra -O2 -o "$WORK/init" enforce_test.c -lbpf \
    || fail "enforce_test build failed"
# Targets are static: they must run even with the loader's own libraries
# absent, and their only job is to exit 7.
gcc -Wall -Wextra -O2 -static -o "$WORK/target" target.c \
    || fail "target build failed"

# --- assemble the initramfs ------------------------------------------

echo "==> assembling initramfs"
ROOT="$WORK/root"
mkdir -p "$ROOT"/{proc,sys,dev} || fail "mkdir failed"

install -m 755 "$WORK/init" "$ROOT/init" || fail "install init failed"
install -m 755 "$WORK/target" "$ROOT/target_allowed" || fail "install failed"
# A separate copy, not a link: the two targets must have DIFFERENT
# inodes, since the whole test is that blocked_files matches one
# {dev, ino} and not the other.
install -m 755 "$WORK/target" "$ROOT/target_blocked" || fail "install failed"
install -m 644 av_lsm_spike.bpf.o "$ROOT/av_lsm_spike.bpf.o" || fail "install failed"

# Copy the loader's shared libraries to the SAME absolute paths they
# have on the host, so the ELF interpreter recorded in the binary
# resolves inside the guest without an ld.so.conf or LD_LIBRARY_PATH.
mapfile -t LIBS < <(ldd "$WORK/init" | grep -oE '/[^ ]+\.so[^ ]*' | sort -u)
[ "${#LIBS[@]}" -gt 0 ] || fail "ldd returned no libraries for init"
for lib in "${LIBS[@]}"; do
    [ -e "$lib" ] || fail "ldd named a missing library: $lib"
    mkdir -p "$ROOT$(dirname "$lib")" || fail "mkdir for $lib failed"
    # -L: resolve symlinks (libbpf.so.1 -> libbpf.so.1.7.0) and copy the
    # real object to the name the binary asks for.
    cp -L "$lib" "$ROOT$lib" || fail "cp $lib failed"
done
# /lib64 is a symlink to /usr/lib on merged-/usr systems, and the ELF
# interpreter path is recorded as /lib64/ld-linux-x86-64.so.2 - recreate
# whichever of the two directions the host uses.
if [ -L /lib64 ] && [ ! -e "$ROOT/lib64" ]; then
    ln -s "$(readlink /lib64)" "$ROOT/lib64" || fail "lib64 symlink failed"
fi
if [ -L /lib ] && [ ! -e "$ROOT/lib" ]; then
    ln -s "$(readlink /lib)" "$ROOT/lib" || fail "lib symlink failed"
fi

( cd "$ROOT" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) \
    > "$WORK/initramfs.cpio.gz" || fail "initramfs build failed"
echo "    $(stat -c%s "$WORK/initramfs.cpio.gz") bytes"

# --- boot -------------------------------------------------------------

# KVM when the current user can actually open /dev/kvm, TCG otherwise.
# Same fallback the repo's qemu-boot CI job uses, for the same reason.
if [ -w /dev/kvm ]; then
    ACCEL_ARGS=(-enable-kvm -cpu host)
    echo "==> booting (KVM)"
else
    ACCEL_ARGS=(-accel tcg -cpu max)
    echo "==> booting (TCG - no /dev/kvm access, slower)"
fi

# lsm=: named explicitly rather than relying on the host's default
# stack, so the result doesn't depend on this machine's boot cmdline.
# BPF LSM has to be in the list or the attach fails with EOPNOTSUPP.
timeout 180 qemu-system-x86_64 \
    -kernel "$KERNEL" \
    -initrd "$WORK/initramfs.cpio.gz" \
    -append "console=ttyS0 panic=-1 lsm=capability,bpf" \
    -display none \
    -serial "file:$WORK/serial.log" \
    -no-reboot \
    -m 1024M \
    "${ACCEL_ARGS[@]}"
QEMU_RC=$?

echo
echo "===== guest serial log ====="
grep -E '^ENFORCE_TEST:|libbpf:' "$WORK/serial.log" 2>/dev/null
echo "==========================="
echo

# --- verdict ----------------------------------------------------------

# QEMU's exit code is deliberately not the gate: init prints its verdict
# and syncs BEFORE reboot(RB_POWER_OFF), which on some kernels halts
# rather than terminating QEMU, so the `timeout` wrapper is an expected
# way for this to end. The marker text is what decides.
if [ ! -s "$WORK/serial.log" ]; then
    cp "$WORK/serial.log" ./serial-vm.log 2>/dev/null
    fail "guest produced no serial output (qemu rc=$QEMU_RC)"
fi

if grep -qF 'ENFORCE_TEST: PASS' "$WORK/serial.log"; then
    echo "RESULT: PASS - the BPF LSM program denied an exec with EPERM,"
    echo "        and left an unblocked exec working."
    exit 0
fi

# Keep the full log around for a failure; a pass doesn't need it.
cp "$WORK/serial.log" ./serial-vm.log 2>/dev/null
echo "Full log saved to ./serial-vm.log"

if grep -qF 'ENFORCE_TEST: FAIL' "$WORK/serial.log"; then
    fail "the guest ran the test and it did NOT enforce (see log above)"
fi
fail "inconclusive - the guest never reached a verdict (qemu rc=$QEMU_RC)"
