# SPDX-License-Identifier: MIT
"""Validate absolute filesystem paths entered in av-gui.

scan.py and protected.py previously accepted anything starting with "/"
(issue #97). That misses `..` traversal that escapes the intended location
only after normalization, symlink tricks where the typed path and the path
actually handed to avctl differ, and embedded newline/NUL bytes that break
avctl's own line-oriented parsing (avctl already rejects newlines per PR
#76; this is defense in depth at the GUI boundary so the user sees the
rejection before a polkit prompt).

`validate_absolute_path()` canonicalizes with normpath + realpath and
returns the canonical path the caller should pass on, so what the user is
shown is what actually gets scanned/protected. It deliberately does NOT
check existence: scan targets must exist but protect targets may not yet,
and an exists-check would just add a TOCTOU between the check and the
pkexec'd avctl call. avctl and the daemon remain the enforcement point;
this is input hygiene, not an authorization gate.
"""
import os

# Linux PATH_MAX; avd's own control-socket line bound is PATH_MAX + 256
# (see docs/avd-socket-protocol.md), so anything longer is rejected here
# rather than truncated or misparsed downstream.
_PATH_MAX = 4096


def validate_absolute_path(path):
    """Canonicalizes `path` and returns it.

    Raises ValueError with a user-displayable message if the path is not
    usable: empty, non-absolute, over PATH_MAX, or containing NUL/newline.
    """
    if not isinstance(path, str):
        raise ValueError("Path must be absolute.")
    text = path.strip()
    if not text:
        raise ValueError("Path must be absolute.")
    if "\0" in text:
        raise ValueError("Path contains an invalid character.")
    if "\n" in text or "\r" in text:
        raise ValueError("Path must not contain newlines.")
    if not text.startswith("/"):
        raise ValueError("Path must be absolute.")
    # normpath collapses //, /./, trailing slashes and lexically resolves
    # /../; realpath additionally resolves symlinks in the existing prefix
    # so the returned path matches what the filesystem will actually open.
    canonical = os.path.realpath(os.path.normpath(text))
    if not canonical.startswith("/"):
        raise ValueError("Path must be absolute.")
    if "\0" in canonical or "\n" in canonical or "\r" in canonical:
        raise ValueError("Path contains an invalid character.")
    # PATH_MAX counts pathname *bytes*, not Unicode code points - a path
    # of multibyte characters could pass a len() check while exceeding
    # the kernel/avd byte limit downstream, so measure the encoded form.
    if not canonical or len(os.fsencode(canonical)) > _PATH_MAX:
        raise ValueError("Path is too long.")
    return canonical


def for_display(text):
    """Renders `text` safe for Gtk.Label and other UTF-8-only consumers.

    avd/avctl output is decoded with errors="surrogateescape" (see
    avd_client._request), so a non-UTF-8 filename arrives with lone
    surrogates that Gtk.Label cannot encode (UnicodeEncodeError) and would
    crash the refresh. This maps such bytes to visible \\xNN escapes via
    backslashreplace - lossless and distinguishable, unlike "replace"'s
    single U+FFFD - while leaving normal strings byte-identical.
    """
    if not isinstance(text, str):
        text = str(text)
    try:
        return text.encode("utf-8", "surrogateescape").decode(
            "utf-8", "backslashreplace"
        )
    except (UnicodeEncodeError, UnicodeDecodeError, ValueError):
        return text.encode("utf-8", "replace").decode("utf-8")
