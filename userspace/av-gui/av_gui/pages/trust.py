# SPDX-License-Identifier: MIT
"""Trust list page - runtime-vouched-for binary hashes
(/proc/kernel_av_trusted via avctl trust add/del)."""
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
        self._hash_entry = Gtk.Entry(hexpand=True)
        self._hash_entry.set_placeholder_text("sha256 (hex)")
        self._name_entry = Gtk.Entry(hexpand=True)
        self._name_entry.set_placeholder_text("name")
        add_btn = Gtk.Button(label="Trust")
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", self._on_add)
        add_row.append(self._hash_entry)
        add_row.append(self._name_entry)
        add_row.append(add_btn)
        outer.append(add_row)

        self._error_label = Gtk.Label(xalign=0, wrap=True)
        self._error_label.add_css_class("error")
        outer.append(self._error_label)

        scroller, self._rows_box = build_table(["SHA256", "Name", ""])
        outer.append(scroller)
        self.widget = outer
        self.refresh()

    def refresh(self):
        """Reads and displays the list of trusted binary hashes from the kernel module."""
        self._error_label.set_label("")
        clear_box(self._rows_box)
        try:
            state = procfs_client.read_state()
        except procfs_client.ProcfsError as exc:
            self._error_label.set_label(
                path_validation.for_display(f"avctl: {exc}")
            )
            return

        entries = state["trust"]
        if not entries:
            self._rows_box.append(Gtk.Label(label="No trusted binaries.", xalign=0))
            return

        for t in entries:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            for text in (t["hash"], t["name"]):
                lbl = Gtk.Label(label=path_validation.for_display(text), xalign=0)
                lbl.set_hexpand(True)
                lbl.set_ellipsize(3)  # Pango.EllipsizeMode.END
                row.append(lbl)
            del_btn = Gtk.Button(label="Untrust")
            del_btn.add_css_class("destructive-action")
            del_btn.connect("clicked", self._on_remove, t["hash"])
            row.append(del_btn)
            self._rows_box.append(row)

    def _on_add(self, _button):
        h = self._hash_entry.get_text().strip()
        name = self._name_entry.get_text().strip()
        if not h or not name:
            self._toast("Hash and name are required")
            return

        def done(ok, stdout, stderr):
            """Callback invoked after the trust add command completes."""
            if ok:
                self._toast("Trusted")
                self._hash_entry.set_text("")
                self._name_entry.set_text("")
                self.refresh()
            else:
                self._toast(f"Trust failed: {(stderr or stdout).strip() or 'unknown error'}")
        pkexec_helper.run_privileged(["trust", "add", h, name], done)

    def _on_remove(self, _button, h):
        def done(ok, stdout, stderr):
            """Callback invoked after the trust del command completes."""
            if ok:
                self._toast("Untrusted")
                self.refresh()
            else:
                self._toast(f"Untrust failed: {(stderr or stdout).strip() or 'unknown error'}")
        pkexec_helper.run_privileged(["trust", "del", h], done)
