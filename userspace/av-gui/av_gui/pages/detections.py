# SPDX-License-Identifier: MIT
"""Detections page - recent scan verdicts (avd's VERDICTS RECENT).
Read-only, no privileged actions here."""
import time

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from .. import avd_client, path_validation
from ..widgets import build_table, make_row, clear_box


class Page:
    def __init__(self):
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=8,
            margin_top=16, margin_bottom=16, margin_start=16, margin_end=16,
        )
        self._error_label = Gtk.Label(xalign=0, wrap=True)
        self._error_label.add_css_class("error")
        outer.append(self._error_label)

        scroller, self._rows_box = build_table(
            ["Time", "Verdict", "Rule", "Score", "Path", "PID", "On-demand"]
        )
        outer.append(scroller)
        self.widget = outer
        self.refresh()

    def refresh(self):
        """Fetches and displays recent scan verdicts from avd."""
        self._error_label.set_label("")
        clear_box(self._rows_box)
        try:
            verdicts = avd_client.verdicts_recent(200)
        except avd_client.AvdError as exc:
            self._error_label.set_label(
                path_validation.for_display(f"avd: {exc}")
            )
            return

        if not verdicts:
            self._rows_box.append(Gtk.Label(label="No scans recorded yet.", xalign=0))
            return

        for v in verdicts:
            try:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(v["timestamp"])))
            except (KeyError, ValueError):
                ts = path_validation.for_display(v.get("timestamp", "?"))
            row = make_row([
                ts,
                v.get("verdict", "?"),
                v.get("rule_name") or "-",
                v.get("score", "0"),
                v.get("path", "?"),
                v.get("pid", "?"),
                "yes" if v.get("on_demand") == "1" else "no",
            ])
            if v.get("verdict") == "MALICIOUS":
                row.add_css_class("av-malicious-row")
            self._rows_box.append(row)
