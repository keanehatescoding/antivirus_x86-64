# SPDX-License-Identifier: MIT
"""Wraps a host command so it still works from inside a Flatpak sandbox.

av-gui's privileged/unprivileged calls (pkexec_helper.py,
procfs_client.py) always need to reach avctl and pkexec on the HOST -
that's where avd, the installed policy file, and the polkit agent
actually live. Native installs (Arch/Debian/Fedora) and the AppImage
build both run unsandboxed already, so this is a no-op there; only the
Flatpak build (packaging/flatpak/org.hyprav.avgui.yml) is sandboxed by
design, so it needs `flatpak-spawn --host` (granted via that
manifest's --talk-name=org.freedesktop.Flatpak finish-arg) to escape
the sandbox for these two calls specifically - the same mechanism
tools like GNOME Builder use for host toolchain access.
"""
import os

_FLATPAK_INFO = "/.flatpak-info"


def in_flatpak_sandbox():
    """Returns True if running inside a Flatpak sandbox."""
    return os.path.exists(_FLATPAK_INFO)


def host_argv(argv):
    """Prefixes argv with `flatpak-spawn --host` when running inside a
    Flatpak sandbox; returns argv unchanged everywhere else (native
    installs, AppImage - neither sandboxes subprocess calls)."""
    if in_flatpak_sandbox():
        return ["flatpak-spawn", "--host"] + list(argv)
    return list(argv)
