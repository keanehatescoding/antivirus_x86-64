CC ?= gcc
# Same hardening rationale as userspace/avd/Makefile: avctl's
# add/del/scan/quarantine commands run privileged (pkexec), so the
# extra runtime checks _FORTIFY_SOURCE and stack-protector buy are
# worth the small overhead.
CFLAGS ?= -Wall -Wextra -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
          -Wformat -Wformat-security
LDFLAGS ?=
# Same coupling note as userspace/avd/Makefile: `override` keeps -fPIE
# and -pie/RELRO/BIND_NOW together even when CI passes its own
# `make CFLAGS=...` (build-matrix.yml) without them.
override CFLAGS += -fPIE
override LDFLAGS += -pie -Wl,-z,relro,-z,now

# install target only - avctl itself is still most commonly just built
# and run in place (./avctl, see the top-level README's examples),
# same as always. This install target exists specifically to give
# `pkexec avctl ...` (see docs/avd-socket-protocol.md's privilege
# section) a real, fixed path to authorize against: polkit action
# files can only reference one exact executable path via their
# org.freedesktop.policykit.exec.path annotation, and can't match an
# arbitrary build-directory location - so pkexec-based privileged
# avctl commands only work once avctl is installed here, even though
# every other avctl command works fine run in place. PREFIX/DESTDIR
# follow the same convention as userspace/avd/Makefile.
PREFIX          ?= /usr/local
DESTDIR         ?=
# POLKIT_ACTIONDIR is deliberately independent of PREFIX, unlike
# BINDIR above - polkit only scans a fixed system directory for action
# files (this default, or /etc/polkit-1/actions for a local override),
# it is not relocatable the way PREFIX-based installs are.
POLKIT_ACTIONDIR ?= /usr/share/polkit-1/actions

# Makefile prerequisite: a flags-only Makefile edit must invalidate the
# binary, or incremental builds keep installing the stale artifact.
avctl: avctl.c Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o avctl avctl.c

clean:
	rm -f avctl

install: avctl
	install -D -m 0755 avctl "$(DESTDIR)$(PREFIX)/bin/avctl"
	mkdir -p "$(DESTDIR)$(POLKIT_ACTIONDIR)"
	sed -e 's|@BINDIR@|$(PREFIX)/bin|g' \
		../../packaging/org.hyprav.avctl.policy \
		> "$(DESTDIR)$(POLKIT_ACTIONDIR)/org.hyprav.avctl.policy"
	chmod 0644 "$(DESTDIR)$(POLKIT_ACTIONDIR)/org.hyprav.avctl.policy"
	@echo
	@echo "Installed:"
	@echo "  $(DESTDIR)$(PREFIX)/bin/avctl"
	@echo "  $(DESTDIR)$(POLKIT_ACTIONDIR)/org.hyprav.avctl.policy"
	@echo
	@echo "pkexec-based privileged commands (scan, quarantine restore/delete,"
	@echo "and any future GUI action) only authorize correctly against THIS"
	@echo "installed path - 'pkexec ./avctl ...' from a build directory will"
	@echo "not match the installed policy action."

.PHONY: clean install
