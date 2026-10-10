# SPDX-License-Identifier: MIT
# No compiled build step - av-gui is a pure-Python GTK4 application.
# checkdeps verifies PyGObject + GTK4 bindings are importable (same
# friendly-failure style as userspace/avd/Makefile's checkdeps for its
# own third-party deps).
PREFIX   ?= /usr/local
DATADIR  ?= $(PREFIX)/share
DESTDIR  ?=
# Not PREFIX/lib/av-gui directly - namespaced under hyprav/ so a
# future second Python component doesn't collide, same reasoning as
# SYSCONFDIR being /etc/hyprav rather than /etc for avd's config.
LIBDIR   ?= $(PREFIX)/lib/hyprav/av-gui

checkdeps:
	@if ! python3 -c "import gi; gi.require_version('Gtk', '4.0'); from gi.repository import Gtk" 2>/dev/null; then \
		echo "ERROR: PyGObject + GTK4 not found."; \
		echo "  Arch/CachyOS: sudo pacman -S python-gobject gtk4"; \
		echo "  Debian/Ubuntu: sudo apt install python3-gi gir1.2-gtk-4.0"; \
		exit 1; \
	fi

# Nothing to actually build - `make` with no target just runs
# checkdeps, so `make && make install` (the pattern every other
# component in this repo uses) still gives useful feedback before
# install tries to copy anything.
all: checkdeps

# Installs the Python package, a launcher shim, and a desktop entry -
# NOT the polkit policy or avctl itself (see userspace/avctl/Makefile
# for that; pkexec-based actions need avctl installed regardless of
# whether av-gui is). Like avd's own install target, this does not
# start/enable anything - av-gui is a normal interactive desktop app,
# launched on demand (`av-gui`, or find "HyprAV" in your app
# launcher), not something to auto-start.
install: checkdeps
	mkdir -p "$(DESTDIR)$(LIBDIR)"
	cp -r av_gui "$(DESTDIR)$(LIBDIR)/"
	find "$(DESTDIR)$(LIBDIR)/av_gui" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	mkdir -p "$(DESTDIR)$(PREFIX)/bin"
	sed -e 's|@LIBDIR@|$(LIBDIR)|g' -e 's|@BINDIR@|$(PREFIX)/bin|g' bin/av-gui \
		> "$(DESTDIR)$(PREFIX)/bin/av-gui"
	chmod 0755 "$(DESTDIR)$(PREFIX)/bin/av-gui"
	mkdir -p "$(DESTDIR)$(DATADIR)/applications"
	sed -e 's|@BINDIR@|$(PREFIX)/bin|g' data/av-gui.desktop \
		> "$(DESTDIR)$(DATADIR)/applications/av-gui.desktop"
	chmod 0644 "$(DESTDIR)$(DATADIR)/applications/av-gui.desktop"
	@echo
	@echo "Installed:"
	@echo "  $(DESTDIR)$(LIBDIR)/av_gui/"
	@echo "  $(DESTDIR)$(PREFIX)/bin/av-gui"
	@echo "  $(DESTDIR)$(DATADIR)/applications/av-gui.desktop"
	@echo
	@echo "Launch with: av-gui   (or find \"HyprAV\" in your app launcher)"
	@echo "Privileged actions (scan, quarantine restore/delete, and every"
	@echo "add/remove button) need avctl AND its polkit policy installed too:"
	@echo "  cd ../avctl && sudo make install"

clean:
	find av_gui -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

.PHONY: all checkdeps install clean
