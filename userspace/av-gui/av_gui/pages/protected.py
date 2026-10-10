# SPDX-License-Identifier: MIT
"""Protected paths page - paths exempted from certain behavioral
heuristics (/proc/kernel_av_protected via avctl protect add/del)."""
import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from .. import path_validation, procfs_client, pkexec_helper
from ..widgets import build_table, clear_box


class Page:
    def __init__(self, toast_fn):
        self._toast = toast_fn

        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=8,
            margin_top=16, margin_bottom=16, margin_start=16, margin_end=16,
        )

        add_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._path_entry = Gtk.Entry(hexpand=True)
        self._path_entry.set_placeholder_text("/absolute/path")
        add_btn = Gtk.Button(label="Protect")
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", self._on_add)
        add_row.append(self._path_entry)
        add_row.append(add_btn)
        outer.append(add_row)

        self._error_label = Gtk.Label(xalign=0, wrap=True)
        self._error_label.add_css_class("error")
        outer.append(self._error_label)

        scroller, self._rows_box = build_table(["Path", ""])
        outer.append(scroller)
        self.widget = outer
        self.refresh()

    def refresh(self):
        """Reads and displays the list of protected paths from the kernel module."""
        self._error_label.set_label("")
        clear_box(self._rows_box)
        try:
            state = procfs_client.read_state()
        except procfs_client.ProcfsError as exc:
            self._error_label.set_label(
                path_validation.for_display(f"avctl: {exc}")
            )
            return

        paths = state["protected"]
        if not paths:
            self._rows_box.append(Gtk.Label(label="No protected paths.", xalign=0))
            return

        for p in paths:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            # Display value is escaped for Gtk; the removal button below
            # keeps the original byte-safe path for the avctl call.
            lbl = Gtk.Label(label=path_validation.for_display(p), xalign=0)
            lbl.set_hexpand(True)
            lbl.set_ellipsize(3)  # Pango.EllipsizeMode.END
            row.append(lbl)
            del_btn = Gtk.Button(label="Unprotect")
            del_btn.add_css_class("destructive-action")
            del_btn.connect("clicked", self._on_remove, p)
            row.append(del_btn)
            self._rows_box.append(row)

    def _on_add(self, _button):
        try:
            path = path_validation.validate_absolute_path(
                self._path_entry.get_text()
            )
        except ValueError as exc:
            self._toast(str(exc))
            return

        def done(ok, stdout, stderr):
            """Callback invoked after the protect add command completes."""
            if ok:
                self._toast("Protected")
                self._path_entry.set_text("")
                self.refresh()
            else:
                self._toast(f"Protect failed: {(stderr or stdout).strip() or 'unknown error'}")
        pkexec_helper.run_privileged(["protect", "add", path], done)

    def _on_remove(self, _button, path):
        def done(ok, stdout, stderr):
            """Callback invoked after the protect del command completes."""
            if ok:
                self._toast("Unprotected")
                self.refresh()
            else:
                self._toast(f"Unprotect failed: {(stderr or stdout).strip() or 'unknown error'}")
        pkexec_helper.run_privileged(["protect", "del", path], done)
