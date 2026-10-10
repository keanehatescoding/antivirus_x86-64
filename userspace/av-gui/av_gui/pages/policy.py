# SPDX-License-Identifier: MIT
"""Policy page - fail-open/fail-closed toggle for what happens to an
exec when avd can't produce a verdict in time
(/proc/kernel_av_daemon_policy via avctl policy set)."""
import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from .. import path_validation, procfs_client, pkexec_helper


class Page:
    def __init__(self, toast_fn):
        self._toast = toast_fn
        self._updating = False
        # True from the moment a toggle fires a pkexec request until
        # its callback runs - guards two things: _on_toggled() won't
        # start a second overlapping request, and refresh() (including
        # the periodic poll - see app.py) won't re-sync the radios from
        # possibly-stale state and visually stomp the user's in-flight
        # change while they're still looking at (or authenticating) it.
        self._pending = False

        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=12,
            margin_top=16, margin_bottom=16, margin_start=16, margin_end=16,
        )

        outer.append(Gtk.Label(
            label="What should happen to an exec when avd can't produce a "
                  "verdict in time (not running, crashed, or slow)?",
            xalign=0, wrap=True,
        ))

        self._fail_open_radio = Gtk.CheckButton(label="Fail open (allow the exec) — default")
        self._fail_closed_radio = Gtk.CheckButton(label="Fail closed (kill the exec)")
        self._fail_closed_radio.set_group(self._fail_open_radio)
        self._fail_open_radio.connect("toggled", self._on_toggled)
        self._fail_closed_radio.connect("toggled", self._on_toggled)
        outer.append(self._fail_open_radio)
        outer.append(self._fail_closed_radio)

        self._error_label = Gtk.Label(xalign=0, wrap=True)
        self._error_label.add_css_class("error")
        outer.append(self._error_label)

        self.widget = outer
        self.refresh()

    def refresh(self):
        """Reads the current daemon-unavailable policy and updates the radio buttons."""
        if self._pending:
            return  # a change is already in flight - see _pending's comment
        self._error_label.set_label("")

        try:
            state = procfs_client.read_state()
        except procfs_client.ProcfsError as exc:
            self._error_label.set_label(
                path_validation.for_display(f"avctl: {exc}")
            )
            self._set_controls_sensitive(False)
            return

        policy = state["policy"]
        if policy not in ("fail-open", "fail-closed"):
            # Missing/unrecognized policy value - do NOT default to
            # selecting "fail open" here, that would show a specific,
            # confident answer for state we don't actually know.
            self._error_label.set_label(
                f"avctl reported no usable policy value ({policy!r}) - "
                "cannot show or change it right now"
            )
            self._set_controls_sensitive(False)
            return

        self._set_controls_sensitive(True)
        self._updating = True
        if policy == "fail-closed":
            self._fail_closed_radio.set_active(True)
        else:
            self._fail_open_radio.set_active(True)
        self._updating = False

    def _set_controls_sensitive(self, sensitive):
        self._fail_open_radio.set_sensitive(sensitive)
        self._fail_closed_radio.set_sensitive(sensitive)

    def _on_toggled(self, button):
        if self._updating or self._pending or not button.get_active():
            return
        value = "fail-closed" if button is self._fail_closed_radio else "fail-open"

        self._pending = True
        self._set_controls_sensitive(False)

        def done(ok, stdout, stderr):
            """Callback invoked after the policy change command completes."""
            self._pending = False
            if ok:
                self._toast(f"Policy set to {value}")
            else:
                self._toast(f"Policy change failed: {(stderr or stdout).strip() or 'unknown error'}")
            self.refresh()  # always re-sync from the real state, success or not
        pkexec_helper.run_privileged(["policy", "set", value], done)
