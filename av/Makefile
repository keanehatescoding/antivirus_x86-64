obj-m += av.o
av-y := main.o sigtable.o netlink_chan.o behavior.o logfmt.o

# No ccflags-y hardening here, deliberately: an out-of-tree module built
# via `make -C $(KDIR) M=$(PWD) modules` inherits the target kernel's own
# KBUILD_CFLAGS (including whatever CONFIG_STACKPROTECTOR_* /
# structleak options the distro enabled), so re-adding those flags would
# only duplicate what the kernel build already passes. Revisit only for
# a flag the kernel build provably does not supply.

# UNAME_R/KDIR are recursive (=/?=, not :=) so `uname -r` runs when KDIR
# is USED, not when this file is parsed - a `:=` would freeze the running
# kernel's version at parse time. Override for another tree with
# `make KDIR=/path/to/kernel/build` (cross-kernel builds).
UNAME_R ?= $(shell uname -r)
KDIR ?= /lib/modules/$(UNAME_R)/build
# $(CURDIR) builtin, not $(shell pwd): no fork, no parse-time subshell,
# immune to PWD-env skew.
PWD  := $(CURDIR)

# Toolchain override for Clang-built kernels (e.g. CachyOS's -clang
# variant). A kernel module generally must be built with the same
# compiler family the target kernel itself was built with, especially
# under LTO/CFI configs. Usage:
#   make                       # default: GCC
#   make LLVM=1                # build against a Clang-built kernel
#   make CC=clang LLVM=1       # same, compiler named explicitly
LLVM ?=

MAKE_ARGS := -C $(KDIR) M=$(PWD)
# Forward CC only when someone actually set it (command line or
# environment). GNU make predefines CC as "cc", so testing it for
# emptiness is always true - that used to pass CC="cc" down on every
# build, which overrode the clang that LLVM=1 selects (a bare
# `make LLVM=1` then ran cc with Clang-only flags) and tripped kbuild's
# "compiler differs" warning on GCC kernels (gcc vs. cc).
ifneq ($(origin CC),default)
  # Quoted: a multi-word CC (e.g. CC="ccache clang") would otherwise
  # word-split into CC=ccache plus a stray `clang` goal that the
  # recursive make treats as a build target instead of part of CC.
  MAKE_ARGS += CC="$(CC)"
endif
ifneq ($(LLVM),)
  MAKE_ARGS += LLVM=$(LLVM)
endif

all:
	$(MAKE) $(MAKE_ARGS) modules

clean:
	$(MAKE) $(MAKE_ARGS) clean
