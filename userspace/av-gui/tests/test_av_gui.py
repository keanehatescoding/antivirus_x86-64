# SPDX-License-Identifier: MIT
"""Regression tests for the #97 av-gui hardening (issue #97).

Runs without root, GTK, or avd: pure unit tests over path_validation and
avctl_path. The Gtk.Label(surrogate) crash is covered at the codec level
(test_for_display_is_gtk_safe asserts the sanitized form is strict-UTF-8
encodable, which is exactly what Gtk's marshaller requires); an optional
live-GTK test runs only when PyGObject is importable.

Run with: python3 -m unittest discover -s userspace/av-gui/tests -v
"""
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from av_gui import avctl_path, path_validation


class ValidateAbsolutePathTest(unittest.TestCase):
    """Canonicalization and rejection cases for validate_absolute_path."""

    def test_rejects_relative(self):
        """Relative paths are rejected."""
        with self.assertRaises(ValueError):
            path_validation.validate_absolute_path("relative/path")

    def test_rejects_newline(self):
        """Embedded newlines are rejected (avctl is line-oriented)."""
        with self.assertRaises(ValueError):
            path_validation.validate_absolute_path("/tmp/foo\nbar")

    def test_rejects_nul(self):
        """Embedded NUL bytes are rejected."""
        with self.assertRaises(ValueError):
            path_validation.validate_absolute_path("/tmp/foo\0bar")

    def test_canonicalizes_dotdot(self):
        """Lexical .. segments resolve to the canonical path."""
        self.assertEqual(
            path_validation.validate_absolute_path("/tmp/../etc/passwd"),
            "/etc/passwd",
        )

    def test_measures_bytes_not_codepoints(self):
        """PATH_MAX applies to encoded bytes, not code points."""
        over = "/" + "é" * 2049  # 2 bytes each in UTF-8 -> >4096 bytes
        with self.assertRaises(ValueError):
            path_validation.validate_absolute_path(over)
        under = "/" + "é" * 100  # 201 bytes -> fine
        self.assertTrue(path_validation.validate_absolute_path(under))

    def test_resolves_symlink(self):
        """Existing symlinks resolve to their target."""
        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.join(tmp, "realfile")
            with open(real, "w"):
                pass
            link = os.path.join(tmp, "link")
            os.symlink(real, link)
            self.assertEqual(
                path_validation.validate_absolute_path(link),
                os.path.realpath(link),
            )


class ForDisplayTest(unittest.TestCase):
    """Surrogate-safe display conversion (the Gtk.Label crash in #97)."""

    def test_normal_unchanged(self):
        """Plain ASCII paths pass through byte-identical."""
        self.assertEqual(
            path_validation.for_display("/tmp/normal-file.txt"),
            "/tmp/normal-file.txt",
        )

    def test_invalid_byte_0x80(self):
        """A lone 0x80 byte survives as a visible, GTK-safe escape."""
        raw = b"/tmp/\x80 evil"
        decoded = raw.decode("utf-8", errors="surrogateescape")
        shown = path_validation.for_display(decoded)
        # Must be strict-UTF-8 encodable - this is what Gtk requires.
        shown.encode("utf-8")
        # Must not collapse distinct bytes into one U+FFFD.
        other = path_validation.for_display(
            b"/tmp/\x81 evil".decode("utf-8", errors="surrogateescape")
        )
        self.assertNotEqual(shown, other)
        self.assertIn("\\x80", shown)

    def test_gtk_accepts_sanitized(self):
        """Live GTK check when PyGObject is available, else skipped."""
        try:
            import gi

            gi.require_version("Gtk", "4.0")
            from gi.repository import Gtk
        except (ImportError, ValueError) as exc:
            self.skipTest(f"PyGObject unavailable: {exc}")
        bad = b"/tmp/\x80".decode("utf-8", errors="surrogateescape")
        Gtk.Label(label=path_validation.for_display(bad))  # must not raise

    def test_toast_and_scan_boundaries(self):
        """Payloads reaching show_toast()/scan _result_label stay GTK-safe."""
        payloads = [
            # Quarantine id read back from avd with a non-UTF-8 byte.
            "Restored " + b"a\x80id".decode("utf-8", "surrogateescape"),
            # avctl stderr echoing a non-UTF-8 path.
            "Scan failed: "
            + b"/tmp/\x80: permission denied".decode(
                "utf-8", "surrogateescape"
            ),
            # Scan stdout echoing a non-UTF-8 path.
            b"/tmp/\x80: MALICIOUS".decode("utf-8", "surrogateescape"),
        ]
        for payload in payloads:
            # Exactly what show_toast() and scan's done() now pass to
            # Gtk.Label.set_label() - must be strict-UTF-8 encodable.
            path_validation.for_display(payload).encode("utf-8")
        # Normal output is byte-identical through the same path.
        self.assertEqual(path_validation.for_display("CLEAN\n"), "CLEAN\n")


class PrivilegedPathTest(unittest.TestCase):
    """Allowlist + trust checks for the pkexec resolver."""

    def _set_env(self, value):
        if value is None:
            os.environ.pop("AVCTL_PATH", None)
        else:
            os.environ["AVCTL_PATH"] = value

    def test_rejects_tmp_evil(self):
        """An attacker path outside the allowlist is never returned."""
        self._set_env("/tmp/evil/avctl")
        try:
            got = avctl_path.resolve_privileged_avctl_path()
        finally:
            self._set_env(None)
        self.assertNotEqual(got, "/tmp/evil/avctl")

    def test_rejects_user_owned_dev_binary(self):
        """A user-owned executable is fine unprivileged, never privileged."""
        with tempfile.NamedTemporaryFile(
            delete=False, suffix="-avctl"
        ) as tmp:
            tmp.write(b"#!/bin/sh\necho hi\n")
            tmppath = tmp.name
        os.chmod(tmppath, 0o755)
        try:
            self._set_env(tmppath)
            self.assertNotEqual(
                avctl_path.resolve_privileged_avctl_path(),
                os.path.realpath(tmppath),
            )
            self.assertEqual(
                avctl_path.resolve_unprivileged_avctl_path(),
                os.path.realpath(tmppath),
            )
        finally:
            self._set_env(None)
            os.unlink(tmppath)

    def test_returns_allowlisted_or_none(self):
        """The privileged resolver only ever returns allowlist or None."""
        self._set_env(None)
        got = avctl_path.resolve_privileged_avctl_path()
        self.assertTrue(
            got is None or got in avctl_path._PRIVILEGED_ALLOWLIST,
            f"unexpected privileged path: {got!r}",
        )

    def test_parent_dirs_trusted(self):
        """World-writable or user-owned parents fail the trust check."""
        self.assertFalse(avctl_path._parent_dirs_trusted("/tmp/evil/avctl"))
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "avctl")
            with open(target, "w"):
                pass
            self.assertFalse(avctl_path._parent_dirs_trusted(target))
        # System parents of a real install are trusted (skip if missing).
        if os.path.exists("/usr/bin/avctl"):
            st = os.stat("/usr/bin")
            if st.st_uid == 0 and not (
                st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                self.assertTrue(
                    avctl_path._parent_dirs_trusted("/usr/bin/avctl")
                )


if __name__ == "__main__":
    unittest.main()
