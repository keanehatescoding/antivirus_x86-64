# SPDX-License-Identifier: MIT
"""Signatures page - list/add/remove exact-hash signatures
(/proc/kernel_av_signatures via avctl add/del)."""
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
        self._algo_combo = Gtk.DropDown.new_from_strings(["sha256", "sha1", "md5"])
        self._hash_entry = Gtk.Entry(hexpand=True)
        self._hash_entry.set_placeholder_text("hash (hex)")
        self._name_entry = Gtk.Entry(hexpand=True)
        self._name_entry.set_placeholder_text("name")
        add_btn = Gtk.Button(label="Add")
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", self._on_add)
        add_row.append(self._algo_combo)
        add_row.append(self._hash_entry)
        add_row.append(self._name_entry)
        add_row.append(add_btn)
        outer.append(add_row)

        self._error_label = Gtk.Label(xalign=0, wrap=True)
        self._error_label.add_css_class("error")
        outer.append(self._error_label)

        scroller, self._rows_box = build_table(["Algo", "Hash", "Name", ""])
        outer.append(scroller)
        self.widget = outer
        self.refresh()

    def refresh(self):
        """Reads and displays the list of exact-hash signatures from the kernel module."""
        self._error_label.set_label("")
        clear_box(self._rows_box)
        try:
            state = procfs_client.read_state()
        except procfs_client.ProcfsError as exc:
            self._error_label.set_label(
                path_validation.for_display(f"avctl: {exc}")
            )
            return

        sigs = state["signatures"]
        if not sigs:
            self._rows_box.append(Gtk.Label(label="No signatures.", xalign=0))
            return

        for s in sigs:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            for text in (s["algo"], s["hash"], s["name"]):
                lbl = Gtk.Label(label=path_validation.for_display(text), xalign=0)
                lbl.set_hexpand(True)
                lbl.set_ellipsize(3)  # Pango.EllipsizeMode.END
                row.append(lbl)
            del_btn = Gtk.Button(label="Remove")
            del_btn.add_css_class("destructive-action")
            del_btn.connect("clicked", self._on_remove, s["algo"], s["hash"])
            row.append(del_btn)
            self._rows_box.append(row)

    def _on_add(self, _button):
        item = self._algo_combo.get_selected_item()
        algo = item.get_string() if item else "sha256"
        h = self._hash_entry.get_text().strip()
        name = self._name_entry.get_text().strip()
        if not h or not name:
            self._toast("Hash and name are required")
            return

        def done(ok, stdout, stderr):
            """Callback invoked after the signature add command completes."""
            if ok:
                self._toast(f"Added {algo} signature")
                self._hash_entry.set_text("")
                self._name_entry.set_text("")
                self.refresh()
            else:
                self._toast(f"Add failed: {(stderr or stdout).strip() or 'unknown error'}")
        pkexec_helper.run_privileged(["add", algo, h, name], done)

    def _on_remove(self, _button, algo, h):
        def done(ok, stdout, stderr):
            """Callback invoked after the signature del command completes."""
            if ok:
                self._toast("Removed signature")
                self.refresh()
            else:
                self._toast(f"Remove failed: {(stderr or stdout).strip() or 'unknown error'}")
        pkexec_helper.run_privileged(["del", algo, h], done)
