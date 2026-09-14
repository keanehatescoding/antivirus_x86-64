# Spike build - NOT part of the main build. Nothing in the repo's normal
# `make` path reaches here; this is built by hand when investigating the
# exec-interception redesign (#102).
#
# Needs: clang (bpf target), bpftool, libbpf headers.
#   Arch:   pacman -S clang bpf libbpf
#   Debian: apt install clang bpftool libbpf-dev
# The `enforce` target additionally needs: qemu-system-x86_64, cpio.

CLANG     ?= clang
BPFTOOL   ?= bpftool
ARCH      := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall \
              -Wno-missing-declarations

OBJS := av_lsm_spike.bpf.o control_nonsleepable.bpf.o

.PHONY: all clean check enforce
all: $(OBJS)

# Generated from the RUNNING kernel's BTF, so it is machine-specific and
# deliberately not committed.
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Load-only verifier test. Needs root; never attaches (see run_spike.sh).
check: $(OBJS)
	BPFTOOL="$(BPFTOOL)" ./run_spike.sh

# Enforcement test: attaches the program in a throwaway QEMU VM and
# proves it denies an exec. Needs qemu + cpio + a readable kernel image;
# does NOT need root, and never attaches anything on this machine.
enforce: av_lsm_spike.bpf.o
	./run_vm_test.sh

clean:
	rm -f $(OBJS) vmlinux.h serial-vm.log
