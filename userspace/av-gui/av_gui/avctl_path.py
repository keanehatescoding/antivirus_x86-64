# SPDX-License-Identifier: MIT
"""Resolve the avctl binary path for av-gui's two call sites.

procfs_client.py calls avctl directly, unprivileged (`avctl save -`);
pkexec_helper.py calls it via pkexec, privileged (`pkexec avctl ...`).
Both historically did `os.environ.get("AVCTL_PATH", "/usr/local/bin/avctl")`
with no validation. For the unprivileged read path that only risks showing
fake data; for the pkexec path an attacker-controlled AVCTL_PATH could get
pkexec'd with elevated trust for the wrong binary while the polkit policy
(`packaging/org.hyprav.avctl.policy`) only authorizes the installed
`@BINDIR@/avctl` (issue #97).

The privileged resolver below therefore accepts only the exact install
locations the policy can authorize (`/usr/local/bin/avctl` for the default
`PREFIX=/usr/local`, `/usr/bin/avctl` for distro `PREFIX=/usr` packaging) and
additionally requires the chosen file to be a root-owned, non-group/other-
writable executable whose parent directories are all root-owned directories
without group/other write permission. Anything else - including a tampered
or missing install - yields None, and pkexec_helper surfaces that as a plain
error instead of elevating anything. The final cross-check against the
policy's exact exec.path still happens in polkit itself; this check just
guarantees we never ask pkexec to elevate anything but the installed avctl.

Validation runs at call time (inside run_privileged(), not at import), and
every parent directory is checked along with the file itself, so the window
for a swap between "we validated this pathname" and "pkexec executes this
pathname" requires write access to a root-owned, non-writable directory -
i.e. privileges the attacker would already need to own the machine. A
pathname-based check cannot fully pin the inode across the pkexec exec
(pkexec takes a path, not a file descriptor); the parent-directory trust
requirement is what makes that residual window unexploitable to an
unprivileged attacker.

Inside a Flatpak sandbox (see host_exec.py) the host's filesystem is not
visible, so ownership checks would always fail even for the legitimate host
avctl. There only the allowlist shape is enforced locally and executability
is probed on the host via `flatpak-spawn --host test -x`; host-side
pkexec/polkit remains the enforcing gate.
"""
import os
import stat
import subprocess

from . import host_exec

DEFAULT_AVCTL_PATH = "/usr/local/bin/avctl"
# The only install locations the polkit policy can authorize: @BINDIR@ is
# $(PREFIX)/bin, and PREFIX is /usr/local by default, /usr in distro
# packaging (see userspace/avctl/Makefile). $AVCTL_PATH pointing anywhere
# else is never used for pkexec, even if it names a root-owned avctl.
_PRIVILEGED_ALLOWLIST = ("/usr/local/bin/avctl", "/usr/bin/avctl")


def _looks_like_avctl(real):
    """Return True if a resolved path has avctl's expected basename."""
    return os.path.basename(real) == "avctl"


def _is_trusted_system_binary(real):
    """Return True if `real` is a root-owned, non-group/other-writable
    executable regular file.

    Guards the pkexec path against an attacker planting or redirecting
    AVCTL_PATH to something they can modify. Callers must also check
    _parent_dirs_trusted() - this covers the file itself only.
    """
    try:
        st = os.stat(real)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    if not os.access(real, os.X_OK):
        return False
    if st.st_uid != 0:
        return False
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False
    return True


def _parent_dirs_trusted(real):
    """Return True if every directory from dirname(`real`) up to `/` is a
    root-owned directory without group/other write permission.

    Without this, validating the file alone leaves a swap window: an
    attacker with write access to a parent directory could replace the
    validated pathname between the stat and pkexec's exec. All system
    parents of the allowlisted paths (`/`, `/usr`, `/usr/bin`,
    `/usr/local`, `/usr/local/bin`) satisfy this on a normal install.
    """
    directory = os.path.dirname(real)
    while True:
        try:
            st = os.stat(directory)
        except OSError:
            return False
        if not stat.S_ISDIR(st.st_mode):
            return False
        if st.st_uid != 0:
            return False
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False
        if directory == "/":
            return True
        parent = os.path.dirname(directory)
        if parent == directory:
            return True
        directory = parent


def _host_executable(path):
    """Return True if `path` is executable on the host.

    Inside a Flatpak sandbox os.access() would test the sandbox's own
    filesystem, not the host's where avctl and pkexec actually live, so
    probe via `flatpak-spawn --host test -x` instead. Outside a sandbox
    this is a plain os.access() check.
    """
    if host_exec.in_flatpak_sandbox():
        try:
            completed = subprocess.run(
                ["flatpak-spawn", "--host", "test", "-x", path],
                timeout=5, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0
    return os.access(path, os.X_OK)


def _privileged_candidate_ok(real):
    """Return True if `real` (already realpath'd) may be pkexec'd.

    Requires allowlist membership plus, on native installs, a trusted
    file in trusted parent directories; in a Flatpak sandbox, requires
    host-side executability instead (ownership is unenforceable from
    inside the sandbox, leaving host-side pkexec/polkit as the gate).
    """
    if real not in _PRIVILEGED_ALLOWLIST:
        return False
    if host_exec.in_flatpak_sandbox():
        return _host_executable(real)
    return _is_trusted_system_binary(real) and _parent_dirs_trusted(real)


def resolve_privileged_avctl_path():
    """Return a validated avctl path for `pkexec avctl ...`, or None.

    Uses $AVCTL_PATH only when it resolves onto the allowlist and passes
    the trust checks; otherwise falls back to the first allowlisted
    candidate that does (preferring /usr/local, then /usr, so a
    /usr/local install shadows a stale distro copy the way $PATH would).
    Returns None when no trusted install exists - callers must surface an
    error rather than pkexec'ing an unvalidated fallback. Never returns a
    relative path.
    """
    raw = os.environ.get("AVCTL_PATH")
    if raw and os.path.isabs(raw):
        try:
            real = os.path.realpath(raw)
        except OSError:
            real = None
        if real is not None and _privileged_candidate_ok(real):
            return real
    for candidate in _PRIVILEGED_ALLOWLIST:
        try:
            real = os.path.realpath(candidate)
        except OSError:
            continue
        if _privileged_candidate_ok(real):
            return real
    return None


def resolve_unprivileged_avctl_path():
    """Return a validated avctl path for direct unprivileged reads.

    No privilege elevation is involved here (procfs_client.py runs
    `avctl save -` as the GUI's own user), so a from-source dev run
    pointing AVCTL_PATH at a user-owned build tree is legitimate and must
    keep working. Only enforces "absolute + executable regular file";
    falls back to the default otherwise. Never returns a relative path.
    """
    raw = os.environ.get("AVCTL_PATH")
    if raw and os.path.isabs(raw):
        real = os.path.realpath(raw)
        if host_exec.in_flatpak_sandbox():
            return real
        try:
            st = os.stat(real)
        except OSError:
            pass
        else:
            if stat.S_ISREG(st.st_mode) and os.access(real, os.X_OK):
                return real
    return DEFAULT_AVCTL_PATH
