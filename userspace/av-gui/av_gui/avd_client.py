"""Raw client for avd's control socket (unprivileged verbs only).

See docs/avd-socket-protocol.md for the full wire protocol. This
module only speaks the three read-only verbs (STATUS, VERDICTS RECENT,
QUARANTINE LIST) - the three privileged verbs (SCAN, QUARANTINE
RESTORE/DELETE) go through pkexec_helper.py + avctl instead, since
avd's own SO_PEERCRED check would reject them from this unprivileged
GUI process even if we sent them directly.
"""
import os
import socket

DEFAULT_SOCK_PATH = "/run/avd/control.sock"
# avd bounds a control connection's idle wait for its request line to
# AVD_CONTROL_RECV_TIMEOUT_SECS (5s, see avd.c) - this is the client
# side of the same idea: without a timeout here, a stuck or misbehaving
# avd would hang recv() (and therefore the GTK main loop, since callers
# run this synchronously) forever instead of surfacing as an AvdError
# the caller can show and move on from.
SOCKET_TIMEOUT_SECS = 5


def _sock_path():
    return os.environ.get("AVD_SOCK_PATH", DEFAULT_SOCK_PATH)


class AvdError(Exception):
    """Raised for a connection failure or an ERR response from avd."""


def _request(cmd):
    """Sends one command line and returns the full response text. avd
    closes the connection after exactly one response (one command per
    connection - see the protocol doc), so reading until EOF is how a
    client knows the response is complete; there is no length prefix.
    """
    path = _sock_path()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            # Applies to connect()/recv() both - a timeout on either
            # raises socket.timeout, a subclass of OSError, so the
            # except clause below already covers it.
            sock.settimeout(SOCKET_TIMEOUT_SECS)
            sock.connect(path)
            sock.sendall((cmd + "\n").encode("utf-8"))
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError as exc:
        raise AvdError(
            f"could not connect to avd control socket {path}: {exc} "
            "(is avd running?)"
        ) from exc
    # surrogateescape (the same codec os.fsdecode uses for filenames), not
    # "replace": a non-UTF-8 filename - including one deliberately crafted
    # to be unrepresentable - must surface accurately instead of having
    # every distinct invalid byte sequence collapse into the same U+FFFD,
    # which would hide the true name of a quarantined/flagged file (issue
    # #97). surrogates round-trip losslessly and never raise, so one bad
    # name still can't fail the whole list the way strict decoding would.
    return b"".join(chunks).decode("utf-8", errors="surrogateescape")


def _parse_rows(resp):
    """Parses an "OK\\nCOUNT n\\n<rows>\\nEND\\n" response into a list
    of tab-split field lists. Raises AvdError on an "ERR ..." response,
    a missing/mismatched COUNT, a missing END terminator, or anything
    else malformed - never returns a silently truncated/partial row
    list, since callers (e.g. status()) trust this shape completely."""
    lines = resp.split("\n")
    if not lines or lines[0] != "OK":
        if lines and lines[0].startswith("ERR "):
            raise AvdError(lines[0][4:])
        raise AvdError("malformed response from avd control socket")

    if len(lines) < 2 or not lines[1].startswith("COUNT "):
        raise AvdError("malformed response from avd control socket (missing COUNT)")
    try:
        expected = int(lines[1][len("COUNT "):])
    except ValueError as exc:
        raise AvdError(
            "malformed response from avd control socket (bad COUNT)"
        ) from exc

    rows = []
    end_seen = False
    for line in lines[2:]:
        if line == "END":
            end_seen = True
            break
        if line == "":
            continue
        rows.append(line.split("\t"))

    if not end_seen:
        raise AvdError("malformed response from avd control socket (missing END)")
    if len(rows) != expected:
        raise AvdError(
            f"malformed response from avd control socket "
            f"(COUNT said {expected}, got {len(rows)} rows)"
        )
    return rows


def status():
    """Returns a dict: uptime_secs, rules_loaded, fuzzy_corpus_count,
    tlsh_corpus_count, scan_queue_len, scan_threads (all int), plus -
    on daemons new enough to report them - scans_total,
    scans_malicious, scan_avg_ms, scan_max_ms, last_scan_ms (all int).
    Accepts both the 6-field row (older avd) and the 11-field row:
    the metrics fields were appended, never inserted, so positional
    parsing of the first six is stable either way."""
    rows = _parse_rows(_request("STATUS"))
    if len(rows) != 1:
        raise AvdError(f"STATUS returned {len(rows)} row(s), expected 1")
    base_keys = [
        "uptime_secs", "rules_loaded", "fuzzy_corpus_count",
        "tlsh_corpus_count", "scan_queue_len", "scan_threads",
    ]
    metric_keys = [
        "scans_total", "scans_malicious", "scan_avg_ms",
        "scan_max_ms", "last_scan_ms",
    ]
    fields = rows[0]
    if len(fields) == len(base_keys):
        keys = base_keys
    elif len(fields) == len(base_keys) + len(metric_keys):
        keys = base_keys + metric_keys
    else:
        raise AvdError(
            f"malformed STATUS row: expected {len(base_keys)} or "
            f"{len(base_keys) + len(metric_keys)} fields, got {len(fields)}"
        )
    try:
        values = [int(v) for v in fields]
    except ValueError as exc:
        raise AvdError(f"malformed STATUS row: non-integer field ({exc})") from exc
    return dict(zip(keys, values))


def verdicts_recent(n=100):
    """Returns a list of dicts (newest first): id, timestamp, pid,
    path, sha256, verdict, rule_name, score, on_demand."""
    rows = _parse_rows(_request(f"VERDICTS RECENT {int(n)}"))
    keys = [
        "id", "timestamp", "pid", "path", "sha256", "verdict",
        "rule_name", "score", "on_demand",
    ]
    for r in rows:
        if len(r) != len(keys):
            raise AvdError(
                f"malformed VERDICTS RECENT row: expected {len(keys)} "
                f"fields, got {len(r)}"
            )
    return [dict(zip(keys, r)) for r in rows]


def quarantine_list():
    """Returns a list of dicts: id, original_path, timestamp,
    rule_name, sha256."""
    rows = _parse_rows(_request("QUARANTINE LIST"))
    keys = ["id", "original_path", "timestamp", "rule_name", "sha256"]
    for r in rows:
        if len(r) != len(keys):
            raise AvdError(
                f"malformed QUARANTINE LIST row: expected {len(keys)} "
                f"fields, got {len(r)}"
            )
    return [dict(zip(keys, r)) for r in rows]
