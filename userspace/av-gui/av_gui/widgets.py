# SPDX-License-Identifier: MIT
"""Small reusable GTK4 widgets shared across pages."""
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Pango", "1.0")
from gi.repository import Gtk, Pango

from .path_validation import for_display


def build_table(headers):
    """Returns (scrolled_window, rows_box). Callers append row widgets
    (e.g. from make_row()) to rows_box.

    A plain Box-of-Boxes table, not Gtk.ColumnView: simpler to
    populate from plain Python dicts/lists for a first-cut management
    UI, at the cost of no click-to-sort - acceptable for the row
    counts this GUI deals with (signatures/trust/detections/
    quarantine are typically tens to low hundreds of entries, not
    something that needs virtualized scrolling).
    """
    outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

    header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    for h in headers:
        lbl = Gtk.Label(label=h, xalign=0)
        lbl.add_css_class("heading")
        lbl.set_hexpand(True)
        header_row.append(lbl)
    outer.append(header_row)
    outer.append(Gtk.Separator())

    rows_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    rows_box.set_margin_top(4)
    outer.append(rows_box)

    scroller = Gtk.ScrolledWindow()
    scroller.set_child(outer)
    scroller.set_vexpand(True)
    return scroller, rows_box


def make_row(values):
    """A single table row: one Gtk.Label per value, evenly expanded
    and ellipsized so long paths/hashes don't blow out the layout.

    Values come from avd/avctl and may carry surrogate escapes for
    non-UTF-8 filenames, which Gtk.Label cannot encode - for_display()
    maps those to visible escapes first, leaving normal values unchanged."""
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    for v in values:
        lbl = Gtk.Label(label=for_display(v), xalign=0)
        lbl.set_hexpand(True)
        lbl.set_ellipsize(Pango.EllipsizeMode.END)
        row.append(lbl)
    return row


def clear_box(box):
    """Removes every child of `box` - used before repopulating a
    rows_box from build_table() on refresh()."""
    child = box.get_first_child()
    while child:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt
