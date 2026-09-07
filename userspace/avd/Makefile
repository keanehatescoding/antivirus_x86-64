CC ?= gcc
# _FORTIFY_SOURCE needs -O1+ to have any effect (already satisfied by
# -O2 above); avd runs privileged (root, via systemd) so the extra
# runtime checks it and -fstack-protector-strong buy are worth the
# small overhead. -Wformat-security is redundant with -Wall/-Wextra's
# -Wformat but is spelled out anyway since it's the one CodeQL/distro
# hardening scanners specifically check for.
CFLAGS ?= -Wall -Wextra -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
          -Wformat -Wformat-security
LDFLAGS ?=
# -fPIE and -pie/RELRO/BIND_NOW must stay coupled: a plain `+=` is
# ignored for command-line `make CFLAGS=...` overrides (which CI uses
# for -Werror in build-matrix.yml), so `override` forces the append
# even then. Keeps a non-PIE-default toolchain from hitting a
# relocation/link error on a mismatched pair.
override CFLAGS += -fPIE
override LDFLAGS += -pie -Wl,-z,relro,-z,now
PKG_CONFIG ?= pkg-config

# install target only - PREFIX/SYSCONFDIR/UNITDIR follow the usual
# GNU/systemd conventions so a packager can override them
# (DESTDIR=... for a staged build root, PREFIX=/usr for a distro
# package instead of the /usr/local default, etc.).
PREFIX      ?= /usr/local
SYSCONFDIR  ?= /etc/hyprav
UNITDIR     ?= /usr/lib/systemd/system
DESTDIR     ?=

LIBNL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libnl-genl-3.0 2>/dev/null)
LIBNL_LIBS   := $(shell $(PKG_CONFIG) --libs libnl-genl-3.0 2>/dev/null)
YARA_CFLAGS  := $(shell $(PKG_CONFIG) --cflags yara 2>/dev/null)
YARA_LIBS    := $(shell $(PKG_CONFIG) --libs yara 2>/dev/null)
# libfuzzy (ssdeep) ships no pkg-config file upstream, so probe for a
# downstream-provided one first and fall back to a plain -lfuzzy link.
# `?=` (not `:=`) so packagers can override without editing this file
# (e.g. `make FUZZY_LIBS="-l:libfuzzy.a"`). Recursive, so the probe
# runs when FUZZY_LIBS is used, not at Makefile-parse time.
FUZZY_LIBS   ?= $(shell $(PKG_CONFIG) --libs fuzzy 2>/dev/null || echo "-lfuzzy")
# TLSH fuzzy hashing (tlsh_core.c/tlsh_shim.c) is vendored pure C -
# no libtlsh/-ltlsh, no header search path, no C++ compiler. See
# tlsh_core.h and the top-level README's "Testing TLSH fuzzy hashing"
# section for why this used to be a system dependency (a C++-only
# library with real distro/version skew) and isn't anymore.

# `avd` must stay the default goal even though checkdeps (textually
# the first target below) is not a real build product - make defaults
# to whichever target is written first in the file, and CI invokes
# this Makefile as plain `make` with no explicit target.
.DEFAULT_GOAL := avd

# checkdeps runs before the objects are ever compiled (see the
# order-only "| checkdeps" prerequisite below) - it used to live in the
# `avd` recipe itself, but the objects are prerequisites of `avd`, so
# make built them (running straight into the plain compiler rules
# further down) before that recipe's friendly "not found" checks ever
# got a chance to run. A missing dependency then surfaced as a raw
# compiler fatal error instead of the guided message below. Putting the
# checks in their own target that the objects depend on guarantees they
# run first.
checkdeps:
	@if [ -z "$(LIBNL_LIBS)" ]; then \
		echo "ERROR: libnl-genl-3.0 not found via pkg-config."; \
		echo "  Arch/CachyOS: sudo pacman -S libnl"; \
		echo "  Debian/Ubuntu: sudo apt install libnl-genl-3-dev"; \
		exit 1; \
	fi
	@if [ -z "$(YARA_LIBS)" ]; then \
		echo "ERROR: yara not found via pkg-config."; \
		echo "  Arch/CachyOS: sudo pacman -S yara"; \
		echo "  Debian/Ubuntu: sudo apt install libyara-dev"; \
		exit 1; \
	fi
	@# mktemp + trap, not a fixed /tmp/.avd_fuzzy_check path: a
	@# predictable world-writable-directory path is a classic
	@# symlink-planting target - another local user (or a concurrent
	@# `make` run) could pre-create a symlink there pointing anywhere,
	@# and if this ever runs privileged (e.g. under `sudo make
	@# install`, which depends on this same rule), the compiler
	@# following that symlink would overwrite an arbitrary
	@# root-owned file with a two-line test program. mktemp's
	@# XXXXXX gives an unpredictable name; the trap cleans it up
	@# even on a failed/interrupted probe.
	@tmp=$$(mktemp "$${TMPDIR:-/tmp}/.avd_fuzzy_check.XXXXXX") || exit 1; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	if ! echo 'int main(){return 0;}' | $(CC) -x c - -o "$$tmp" $(FUZZY_LIBS) 2>/dev/null; then \
		echo "ERROR: libfuzzy (ssdeep) not found."; \
		echo "  Arch/CachyOS: sudo pacman -S ssdeep"; \
		echo "  Debian/Ubuntu: sudo apt install libfuzzy-dev"; \
		exit 1; \
	fi

# Makefile is a normal prerequisite throughout: GNU Make won't rebuild
# objects/binaries on a flags-only Makefile change otherwise, so an
# incremental build could install stale artifacts missing the hardening
# flags above. install depends on avd, so it inherits the rebuild.
avd: avd.o sha256.o tlsh_core.o tlsh_shim.o Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o avd avd.o sha256.o tlsh_core.o tlsh_shim.o $(LIBNL_LIBS) $(YARA_LIBS) $(FUZZY_LIBS) -lpthread

# Every translation unit here is plain C, built and linked with
# $(CC) - this project has no C++ code left (TLSH fuzzy hashing used
# to need a small C++ shim over libtlsh; it's now vendored pure C, see
# tlsh_core.h). "| checkdeps" is an order-only prerequisite: it forces
# checkdeps to run first without making a checkdeps timestamp change
# trigger a needless rebuild of these objects (checkdeps has no file
# output to have a timestamp in the first place).
avd.o: avd.c ../../av/netlink_proto.h sha256.h tlsh_shim.h Makefile | checkdeps
	$(CC) $(CFLAGS) $(LIBNL_CFLAGS) $(YARA_CFLAGS) -c avd.c -o avd.o

# sha256.o needs none of avd's third-party deps (libnl/yara/fuzzy)
# - no "| checkdeps" prerequisite, so `make` in a tree missing those
# still builds this object on its own (harmless; the final link still
# needs them regardless).
sha256.o: sha256.c sha256.h Makefile
	$(CC) $(CFLAGS) -c sha256.c -o sha256.o

# tlsh_core.o is the vendored TLSH algorithm itself - no third-party
# deps either (tlsh_diff_table.h is a header, not a link dependency),
# same no-checkdeps reasoning as sha256.o.
tlsh_core.o: tlsh_core.c tlsh_core.h tlsh_diff_table.h Makefile
	$(CC) $(CFLAGS) -c tlsh_core.c -o tlsh_core.o

tlsh_shim.o: tlsh_shim.c tlsh_shim.h tlsh_core.h Makefile
	$(CC) $(CFLAGS) -c tlsh_shim.c -o tlsh_shim.o

clean:
	rm -f avd avd.o sha256.o tlsh_core.o tlsh_shim.o

# Installs the binary, the systemd unit, and a default rules/corpus
# location under SYSCONFDIR - NOT enabled or started automatically
# (that's a deliberate, separate step: starting a daemon that scans
# and quarantines files system-wide shouldn't be a silent side effect
# of `make install`). packaging/avd.service is a template (@BINDIR@/
# @SYSCONFDIR@ placeholders) rendered here against PREFIX/SYSCONFDIR -
# DESTDIR is deliberately NOT part of the substitution: it's only a
# staging root for this install invocation (e.g. packaging into
# /tmp/pkgroot before building a distro package), not part of where
# avd actually runs once installed, so it must never end up baked
# into ExecStart.
install: avd
	install -D -m 0755 avd "$(DESTDIR)$(PREFIX)/bin/avd"
	mkdir -p "$(DESTDIR)$(UNITDIR)"
	sed -e 's|@BINDIR@|$(PREFIX)/bin|g' \
		-e 's|@SYSCONFDIR@|$(SYSCONFDIR)|g' \
		../../packaging/avd.service > "$(DESTDIR)$(UNITDIR)/avd.service"
	chmod 0644 "$(DESTDIR)$(UNITDIR)/avd.service"
	mkdir -p "$(DESTDIR)$(SYSCONFDIR)/rules"
	# Explicit production rule list, NOT a ../../rules/*.yar glob: test/demo
	# rules (see tests/fixtures/test.yar, whose weight=100 override=true
	# Suspicious_Shell rule false-positives on any script containing
	# "/bin/sh -i") must never ship to production even if one is ever
	# placed back under rules/ by mistake.
	install -m 0644 ../../rules/heuristics.yar ../../rules/elf_analysis.yar \
		../../rules/entropy.yar "$(DESTDIR)$(SYSCONFDIR)/rules/"
	install -m 0644 ../../corpus/fuzzy_hashes.txt \
		"$(DESTDIR)$(SYSCONFDIR)/fuzzy_hashes.txt"
	install -m 0644 ../../corpus/tlsh_hashes.txt \
		"$(DESTDIR)$(SYSCONFDIR)/tlsh_hashes.txt"
	@echo
	@echo "Installed:"
	@echo "  $(DESTDIR)$(PREFIX)/bin/avd"
	@echo "  $(DESTDIR)$(UNITDIR)/avd.service"
	@echo "  $(DESTDIR)$(SYSCONFDIR)/rules/*.yar"
	@echo "  $(DESTDIR)$(SYSCONFDIR)/fuzzy_hashes.txt"
	@echo "  $(DESTDIR)$(SYSCONFDIR)/tlsh_hashes.txt"
	@echo
	@echo "Not started - review the unit, then:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now avd.service"

.PHONY: clean install checkdeps
