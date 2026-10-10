# SPDX-License-Identifier: MIT
"""av-gui - GTK4 management console for HyprAV.

Unprivileged reads via avd_client.py (avd's control socket) and
procfs_client.py (`avctl save -`); privileged writes via
pkexec_helper.py (`pkexec avctl ...`). See docs/avd-socket-protocol.md
for the protocol and packaging/org.hyprav.avctl.policy for the polkit
action backing every privileged button in this app.
"""
import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, Gio, GLib, Gtk

from .pages import dashboard, detections, policy, protected, quarantine, scan, signatures, trust
from .path_validation import for_display

REFRESH_INTERVAL_SECS = 4
APP_ID = "org.hyprav.avgui"

# Minimal custom CSS - everything else comes from the system GTK theme.
# @error_color is a named color GTK4's own default (Adwaita) stylesheet
# defines, not something libadwaita-specific, so this works without an
# Adw dependency.
_CSS = b"""
.av-malicious-row { background-color: alpha(@error_color, 0.12); }
"""


def _load_css():
    """Loads custom CSS styles for the application."""
    provider = Gtk.CssProvider()
    provider.load_from_data(_CSS)
    display = Gdk.Display.get_default()
    if display:
        Gtk.StyleContext.add_provider_for_display(
            display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )


class AvGuiWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="HyprAV")
        self.set_default_size(1000, 650)

        overlay = Gtk.Overlay()
        self.set_child(overlay)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        overlay.set_child(root)

        header = Gtk.HeaderBar()
        header.set_title_widget(Gtk.Label(label="HyprAV"))
        root.append(header)

        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        body.set_vexpand(True)
        root.append(body)

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        sidebar = Gtk.StackSidebar()
        sidebar.set_stack(self._stack)
        body.append(sidebar)
        body.append(Gtk.Separator())
        self._stack.set_hexpand(True)
        body.append(self._stack)

        self._toast_label = Gtk.Label()
        toast_box = Gtk.Box()
        toast_box.add_css_class("app-notification")
        toast_box.set_margin_start(8)
        toast_box.set_margin_end(8)
        toast_box.set_margin_top(4)
        toast_box.set_margin_bottom(4)
        toast_box.append(self._toast_label)
        self._toast_revealer = Gtk.Revealer()
        self._toast_revealer.set_child(toast_box)
        self._toast_revealer.set_valign(Gtk.Align.END)
        self._toast_revealer.set_halign(Gtk.Align.CENTER)
        self._toast_revealer.set_margin_bottom(24)
        overlay.add_overlay(self._toast_revealer)

        self._pages = {}
        self._add_page("dashboard", "Dashboard", dashboard.Page())
        self._add_page("detections", "Detections", detections.Page())
        self._add_page("quarantine", "Quarantine", quarantine.Page(self.show_toast))
        self._add_page("scan", "Scan a File", scan.Page(self.show_toast, lambda: self))
        self._add_page("signatures", "Signatures", signatures.Page(self.show_toast))
        self._add_page("trust", "Trust List", trust.Page(self.show_toast))
        self._add_page("protected", "Protected Paths", protected.Page(self.show_toast))
        self._add_page("policy", "Policy", policy.Page(self.show_toast))

        # Gtk.Stack doesn't reliably default to the first-added child -
        # verified empirically (it landed on "signatures" on startup
        # without this) - so pick the landing page explicitly rather
        # than relying on unspecified default-selection behavior.
        self._stack.set_visible_child_name("dashboard")

        self._stack.connect("notify::visible-child-name", self._on_page_changed)
        GLib.timeout_add_seconds(REFRESH_INTERVAL_SECS, self._on_timeout)

    def _add_page(self, name, title, page):
        self._pages[name] = page
        self._stack.add_titled(page.widget, name, title)

    def show_toast(self, message):
        """Shows a temporary notification message at the bottom of the window.

        Shared funnel for every page's toast, including privileged-action
        failure callbacks that interpolate raw avctl stderr/stdout and ids
        read back from avd - any of which may carry surrogate escapes for
        non-UTF-8 filenames. for_display() maps those to visible escapes
        first (identity for normal text), since Gtk.Label cannot encode
        lone surrogates and would raise UnicodeEncodeError."""
        self._toast_label.set_label(for_display(message))
        self._toast_revealer.set_reveal_child(True)
        GLib.timeout_add_seconds(4, self._hide_toast)

    def _hide_toast(self):
        self._toast_revealer.set_reveal_child(False)
        return GLib.SOURCE_REMOVE

    def _current_page(self):
        name = self._stack.get_visible_child_name()
        return self._pages.get(name)

    def _on_page_changed(self, *_args):
        page = self._current_page()
        if page:
            page.refresh()

    def _on_timeout(self):
        # Only the currently-visible page is polled - avd's control
        # socket is request/reply only (see docs/avd-socket-protocol.md),
        # so there's no push/subscribe mechanism to prefer over polling,
        # and polling every page in the background at once would be
        # pure waste for the seven pages the user isn't looking at.
        page = self._current_page()
        if page:
            page.refresh()
        return GLib.SOURCE_CONTINUE


class AvGuiApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self._window = None

    def do_activate(self):
        """Activates the application and presents the main window."""
        _load_css()
        if not self._window:
            self._window = AvGuiWindow(self)
        self._window.present()


def main():
    """Entry point for the av-gui application."""
    app = AvGuiApp()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
