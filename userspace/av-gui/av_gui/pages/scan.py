# SPDX-License-Identifier: MIT
"""On-demand scan page - pick a file, scan it via pkexec avctl scan."""
import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

from .. import path_validation, pkexec_helper


class Page:
    def __init__(self, toast_fn, window_provider):
        self._toast = toast_fn
        self._window_provider = window_provider

        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=12,
            margin_top=16, margin_bottom=16, margin_start=16, margin_end=16,
        )

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._path_entry = Gtk.Entry(hexpand=True)
        self._path_entry.set_placeholder_text("/absolute/path/to/file")
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_browse)
        scan_btn = Gtk.Button(label="Scan")
        scan_btn.add_css_class("suggested-action")
        scan_btn.connect("clicked", self._on_scan)
        row.append(self._path_entry)
        row.append(browse_btn)
        row.append(scan_btn)
        outer.append(row)

        self._result_label = Gtk.Label(xalign=0, wrap=True)
        outer.append(self._result_label)

        self.widget = outer

    def refresh(self):
        """No-op refresh - scan page is purely action-driven."""
        pass  # purely action-driven - nothing to poll

    def _on_browse(self, _button):
        dialog = Gtk.FileDialog()
        dialog.open(self._window_provider(), None, self._on_file_chosen)

    def _on_file_chosen(self, dialog, result):
        try:
            gfile = dialog.open_finish(result)
        except GLib.Error:
            return  # cancelled - nothing to do
        if gfile:
            path = gfile.get_path()
            if path:
                self._path_entry.set_text(path)

    def _on_scan(self, _button):
        try:
            path = path_validation.validate_absolute_path(
                self._path_entry.get_text()
            )
        except ValueError as exc:
            self._result_label.set_label(str(exc))
            return
        self._result_label.set_label("Scanning…")

        def done(ok, stdout, stderr):
            """Callback invoked after the scan command completes."""
            if ok:
                # Scan output echoes the scanned path, which may carry
                # surrogate escapes for a non-UTF-8 filename - sanitize
                # before handing it to Gtk.Label (see show_toast()).
                self._result_label.set_label(
                    path_validation.for_display(stdout.strip() or "(no output)")
                )
                self._toast("Scan complete")
            else:
                self._result_label.set_label(
                    path_validation.for_display(
                        f"Scan failed: {(stderr or stdout).strip() or 'unknown error'}"
                    )
                )
        pkexec_helper.run_privileged(["scan", path], done)
