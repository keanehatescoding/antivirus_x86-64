# SPDX-License-Identifier: MIT
"""Runs privileged avctl commands via pkexec, asynchronously (so the
GTK main loop never blocks on the polkit authentication prompt). See
docs/avd-socket-protocol.md's Authorization section and
packaging/org.hyprav.avctl.policy for the polkit action this relies
on.

One-shot subprocess per action, not a persistent privileged helper
process kept alive by the GUI - a long-lived root-owned helper would
itself be a second always-on privileged surface to secure, worse than
a stateless call whose entire trust boundary is pkexec plus the one
policy file.
"""
import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

from . import avctl_path, host_exec

# pkexec only authorizes against avctl's INSTALLED path (see
# org.freedesktop.policykit.exec.path in packaging/org.hyprav.avctl.policy,
# and userspace/avctl/Makefile install target's own comment on why) -
# this must match that install location, not wherever av-gui itself
# happens to be run from. bin/av-gui's launcher shim sets AVCTL_PATH
# for real installs, derived from the same PREFIX avctl itself was
# installed to (see that script's @BINDIR@ comment) - the
# /usr/local/bin/avctl literal in avctl_path.py is only a fallback for a
# from-source/dev run where that substitution never happened.
#
# $AVCTL_PATH is never trusted blindly here (issue #97): it is resolved
# through avctl_path.resolve_privileged_avctl_path(), which requires a
# root-owned, non-group/other-writable executable named avctl and falls
# back to the system default otherwise, so an attacker-controlled
# environment cannot redirect the pkexec'd binary.


def run_privileged(args, on_done):
    """Runs `pkexec <AVCTL_PATH> *args` asynchronously.

    `on_done(ok, stdout, stderr)` is called back on the GTK main loop
    once the subprocess exits. `ok` is True only on exit code 0 - a
    denied polkit prompt just exits non-zero like any other avctl
    failure, so callers don't need to special-case "denied" vs. "some
    other error", both show up the same way (an error message from
    stderr/stdout).
    """
    avctl = avctl_path.resolve_privileged_avctl_path()
    if avctl is None:
        on_done(
            False, "",
            "avctl not found at a trusted system path "
            "(/usr/local/bin/avctl, /usr/bin/avctl) - "
            "reinstall avctl before retrying privileged actions",
        )
        return
    argv = host_exec.host_argv(["pkexec", avctl] + list(args))
    try:
        proc = Gio.Subprocess.new(
            argv,
            Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE,
        )
    except GLib.Error as exc:
        on_done(False, "", str(exc))
        return

    def _finished(source, result, _user_data=None):
        try:
            _, stdout, stderr = source.communicate_utf8_finish(result)
        except GLib.Error as exc:
            on_done(False, "", str(exc))
            return
        on_done(source.get_exit_status() == 0, stdout or "", stderr or "")

    proc.communicate_utf8_async(None, None, _finished)
