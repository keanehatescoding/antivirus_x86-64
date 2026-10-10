# SPDX-License-Identifier: MIT
"""Quarantine page - list quarantined files, restore/delete via
pkexec avctl quarantine restore|delete."""
import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from .. import avd_client, path_validation, pkexec_helper
from ..widgets import build_table, clear_box


class Page:
    def __init__(self, toast_fn):
        self._toast = toast_fn

        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=8,
            margin_top=16, margin_bottom=16, margin_start=16, margin_end=16,
        )
        self._error_label = Gtk.Label(xalign=0, wrap=True)
        self._error_label.add_css_class("error")
        outer.append(self._error_label)

        scroller, self._rows_box = build_table(["Original path", "Rule", "SHA256", "Actions"])
        outer.append(scroller)
        self.widget = outer
        self.refresh()

    def refresh(self):
        """Fetches and displays the list of quarantined files from avd."""
        self._error_label.set_label("")
        clear_box(self._rows_box)
        try:
            entries = avd_client.quarantine_list()
        except avd_client.AvdError as exc:
            self._error_label.set_label(
                path_validation.for_display(f"avd: {exc}")
            )
            return

        if not entries:
            self._rows_box.append(Gtk.Label(label="Quarantine is empty.", xalign=0))
            return

        for e in entries:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            for text in (e.get("original_path", "?"), e.get("rule_name") or "-", e.get("sha256") or "-"):
                lbl = Gtk.Label(label=path_validation.for_display(text), xalign=0)
                lbl.set_hexpand(True)
                lbl.set_ellipsize(3)  # Pango.EllipsizeMode.END
                row.append(lbl)

            actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
            restore_btn = Gtk.Button(label="Restore")
            delete_btn = Gtk.Button(label="Delete")
            delete_btn.add_css_class("destructive-action")
            qid = e.get("id", "")
            restore_btn.connect("clicked", self._on_restore, qid)
            delete_btn.connect("clicked", self._on_delete, qid)
            actions.append(restore_btn)
            actions.append(delete_btn)
            row.append(actions)

            self._rows_box.append(row)

    def _on_restore(self, _button, qid):
        def done(ok, stdout, stderr):
            """Callback invoked after the quarantine restore command completes."""
            if ok:
                self._toast(f"Restored {qid}")
                self.refresh()
            else:
                self._toast(f"Restore failed: {(stderr or stdout).strip() or 'unknown error'}")
        pkexec_helper.run_privileged(["quarantine", "restore", qid], done)

    def _on_delete(self, _button, qid):
        def done(ok, stdout, stderr):
            """Callback invoked after the quarantine delete command completes."""
            if ok:
                self._toast(f"Deleted {qid}")
                self.refresh()
            else:
                self._toast(f"Delete failed: {(stderr or stdout).strip() or 'unknown error'}")
        pkexec_helper.run_privileged(["quarantine", "delete", qid], done)
