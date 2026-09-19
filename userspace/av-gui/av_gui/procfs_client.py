"""Reads signatures/trust/protected-paths/policy via `avctl save -`
(stdout mode - see do_save() in userspace/avctl/avctl.c) rather than
reading /proc/kernel_av_* directly: this reuses avctl's existing,
already-tested line format instead of a second parser in Python, and
works fully unprivileged (avctl save only reads those /proc files, it
never writes). See docs/avd-socket-protocol.md's note on why the GUI
reuses this format instead of adding a second read protocol.
"""
import subprocess

from . import avctl_path, host_exec


class ProcfsError(Exception):
    """Raised when `avctl save -` can't be run or exits non-zero -
    typically means the kernel module isn't loaded (see avctl's own
    "is the av module loaded?" hint in its error output, passed
    through here via stderr), or that this user isn't in the hyprav
    trusted-reader group (the IOC entries are 0640 root:hyprav, see
    #143 - avctl prints a group hint for EACCES, also passed through
    via stderr)."""


def read_state():
    """Returns a dict: signatures (list of {algo, hash, name}), trust
    (list of {hash, name}), protected (list of path strings), policy
    (str, "fail-open"/"fail-closed", or None if unavailable)."""
    try:
        result = subprocess.run(
            host_exec.host_argv(
                [avctl_path.resolve_unprivileged_avctl_path(), "save", "-"]
            ),
            capture_output=True, text=True, timeout=10, check=False,
            # os.fsdecode parity: never fail the whole read on a
            # non-UTF-8 name, and never mangle distinct byte sequences
            # into the same U+FFFD (see avd_client._request below).
            errors="surrogateescape",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProcfsError(f"could not run avctl: {exc}") from exc

    if result.returncode != 0:
        raise ProcfsError(result.stderr.strip() or "avctl save - failed")

    signatures = []
    trust = []
    protected = []
    policy = None

    for line in result.stdout.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("sig add "):
            parts = line[len("sig add "):].split(" ", 2)
            if len(parts) == 3:
                signatures.append({"algo": parts[0], "hash": parts[1], "name": parts[2]})
        elif line.startswith("trust add "):
            parts = line[len("trust add "):].split(" ", 1)
            if len(parts) == 2:
                trust.append({"hash": parts[0], "name": parts[1]})
        elif line.startswith("protect add "):
            protected.append(line[len("protect add "):])
        elif line.startswith("policy "):
            policy = line[len("policy "):]

    return {
        "signatures": signatures,
        "trust": trust,
        "protected": protected,
        "policy": policy,
    }
