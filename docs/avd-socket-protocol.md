# avd Control Socket Protocol (Unix Domain Socket)

Management channel between `avd` and its clients (`avctl`, and the
planned GTK4 GUI) - status, recent verdict history, quarantine
list/restore/delete, and on-demand scanning. Separate from the
kernel↔daemon Generic Netlink channel described in
[`netlink-protocol.md`](netlink-protocol.md): that channel is
kernel-initiated only, requires `CAP_NET_ADMIN`, and supports exactly
one registered daemon - none of which fits an interactive management
client. See `userspace/avd/avd.c`'s control-socket section for the
implementation and `userspace/avctl/avctl.c`'s `control_request()` for
the reference client.

## Why a second channel instead of extending netlink

Netlink's `AV_C_*` commands exist to let the *kernel* ask *avd* to
analyze a file it just intercepted, correlated by a kernel-generated
`REQID` - fundamentally kernel-initiated request/response. A
management client asking "what got quarantined recently?" or "scan
this file right now" is the opposite direction and has no kernel
involvement at all; forcing it through the netlink family would mean
either a second daemon "registering" (the kernel only tracks one
`daemon_portid` - see `netlink-protocol.md`'s known limitations) or
loosening `GENL_ADMIN_PERM`, both worse than a purpose-built socket.

## Transport

- `AF_UNIX`, `SOCK_STREAM`, path `/run/avd/control.sock` by default
  (systemd's `RuntimeDirectory=avd` in `packaging/avd.service` owns
  `/run/avd`'s lifecycle; `avd` also creates the directory itself as a
  fallback for manual/test runs - see `ensure_parent_dir()` in
  `avd.c`). Override with the `AVD_SOCK_PATH` environment variable
  (both `avd` and `avctl` read it) or, for `avd`, the 5th positional
  argument.
- `avd` `chmod`s the socket file `0666` after `bind()` - every client
  can connect. What a connection is allowed to *do* is gated per
  command, not per connection (see Authorization below).
- **One command per connection.** A client connects, sends exactly one
  request line, reads the response until the server closes the
  connection (EOF - there is no length prefix), then disconnects.
  There is no session/keepalive concept.
- At most `AVD_CONTROL_MAX_CONNS` (32) connections open at once - a
  connection beyond that gets `ERR too many concurrent control
  connections - try again shortly` and is closed immediately. Each
  connection also has an `AVD_CONTROL_RECV_TIMEOUT_SECS` (5s) idle
  timeout on receiving its request line, so a client that connects and
  never sends anything can't hold a slot open indefinitely.
- Of those 32, at most `AVD_CONTROL_MAX_CONNS_PER_UID` (8) may belong to
  any single uid at once - resolved via `SO_PEERCRED` at accept time. On
  a `0666` socket the global cap alone doesn't stop one unprivileged
  local user from opening all 32 connections and sitting on each for the
  5s idle timeout, repeating indefinitely - the per-uid cap leaves room
  for every other user regardless. A connection beyond a uid's own cap
  gets the same `ERR too many concurrent control connections` response.

## Wire format

Request: one line, `\n`-terminated:

```
VERB [ARG ...]\n
```

Bounded by `AVD_SOCK_LINE_MAX` (`PATH_MAX + 256`) in `avd.c` - a
request that doesn't fit, or never sends a newline, is rejected as
malformed rather than silently truncated.

Response, always starting with one of:

```
OK\n
```
```
ERR <message>\n
```

`OK` responses that carry data continue with a row count and the rows
themselves, terminated by `END` - deliberately explicit on both ends
(`COUNT`, then `END`) rather than trusting the count alone, so a
client that mis-parses one row can still resynchronize by scanning
for `END`:

```
OK\n
COUNT <n>\n
<row 1>\n
...
<row n>\n
END\n
```

Row fields are **tab-separated**. Known limitation, same class as
`avctl save`/`load`'s documented one (see `do_save()` in `avctl.c`):
a field value containing a literal tab or newline (a path or rule name
could, in principle, on Linux) will misparse. Not addressed here for
the same reason it wasn't addressed there - narrow, real-world-rare,
and would need a heavier framing format to fully close.

## Commands

| Command | Auth | Response |
|---|---|---|
| `STATUS` | any | 1 row: `uptime_secs\trules_loaded(0/1)\tfuzzy_corpus_count\ttlsh_corpus_count\tscan_queue_len\tscan_threads` |
| `VERDICTS RECENT <n>` | any, filtered | up to `n` most-recent rows *the caller owns* (newest first): `id\ttimestamp\tpid\tpath\tsha256\tverdict(CLEAN/MALICIOUS)\trule_name\tscore\ton_demand(0/1)` |
| `QUARANTINE LIST` | any, filtered | one row per quarantined file *the caller owns*: `id\toriginal_path\ttimestamp\trule_name\tsha256` |
| `SCAN <absolute-path>` | **root** | 1 row: `verdict(CLEAN/MALICIOUS)\trule_name\tscore\tsha256` |
| `QUARANTINE RESTORE <id>` | **root** | `OK` only, no rows |
| `QUARANTINE DELETE <id>` | **root** | `OK` only, no rows |

`<id>` is a quarantined file's basename with the `.quarantined` suffix
stripped (exactly what `QUARANTINE LIST` returns in its first field) -
not a path, must not contain `/`.

## Authorization

Gated **per command, not per connection** - matches this codebase's
existing precedent of world-readable `/proc` state (e.g.
`/proc/kernel_av_signatures` is `0644`) with writes checked
separately, rather than two sockets with two different modes. Right
after `accept()`, `avd` reads the connecting process's credentials via
`SO_PEERCRED` (kernel-populated at `connect()` time from the actual
peer process - not attacker-writable, same trust boundary as
`nlmsg_get_src()` in `msg_handler()` on the netlink side). `SCAN`,
`QUARANTINE RESTORE`, and `QUARANTINE DELETE` require `uid == 0`,
returning `ERR permission denied ...` otherwise.

`STATUS` answers any peer with aggregate counts only - nothing
per-file. `VERDICTS RECENT` and `QUARANTINE LIST` also answer any
peer, but unlike `/proc/kernel_av_signatures` (which holds no
per-user data), each row is a specific file's path and SHA-256 hash -
worth protecting the same way file contents themselves are. Both
filter their rows to ones the connecting peer's uid owns (the
scanned/quarantined file's original owner, not the triggering
process's pid) before sending `COUNT`; `uid == 0` sees every row
unfiltered. A row whose owner can't be determined (missing/unreadable
quarantine metadata, or a failed `fstat()` at scan time) is treated as
root-only rather than shown to everyone.

Callers that need one of the three privileged verbs use `pkexec avctl
scan|quarantine restore|quarantine delete ...` (see
`packaging/org.hyprav.avctl.policy`) rather than talking to the socket
directly as root themselves - this gives two independent checks in
practice: polkit's authorization prompt gates whether `pkexec` runs
`avctl` as root at all, and `avd`'s own `SO_PEERCRED` check
independently verifies the connecting process actually is root once
it gets there.

## Known limitations

- **Verdict history is in-memory only**, a bounded ring buffer
  (`AVD_VERDICT_HISTORY_MAX`, 500 entries) - lost on every `avd`
  restart. Deliberate, matching this codebase's existing convention
  that kernel/avd runtime state is memory-only unless a save/load
  mechanism was added as its own explicit feature (see `avctl
  save`/`load` for the kernel-state equivalent). Not addressed here;
  a future on-disk log is a reasonable follow-up if this turns out to
  matter in practice.
- **Tab/newline in a field value misparses** - see Wire format above.
- **No path-traversal protection needed on `SCAN`'s argument** beyond
  requiring it to be absolute - unlike quarantine `<id>`, an arbitrary
  absolute path is exactly what `SCAN` is *for* (scan any file the
  daemon's own privileges can read), so there's nothing to restrict
  there beyond the existing root-only gate.
- **`SCAN` does not share the kernel-triggered scan queue.** Unlike
  `AV_C_SCAN_REQUEST` (which goes through the bounded worker pool
  (size/queue depth runtime-tunable via the `AVD_SCAN_THREADS`/
  `AVD_SCAN_QUEUE_MAX` environment variables - see
  `docs/netlink-protocol.md`), a control-socket `SCAN` command calls
  `perform_scan()` directly on that connection's own thread, uncoordinated
  with kernel-triggered scans. It has its own concurrency cap,
  `AVD_CONTROL_MAX_SCAN_CONNS` (4, well under `AVD_CONTROL_MAX_CONNS`) -
  a root-authenticated client issuing more concurrent `SCAN`s than that
  gets `ERR too many concurrent SCAN requests - try again shortly`
  rather than tying up every control connection slot (each held for up
  to `SCAN_TIMEOUT_SECS`, not the much shorter
  `AVD_CONTROL_RECV_TIMEOUT_SECS`) and starving ordinary
  STATUS/VERDICTS/QUARANTINE LIST use by every other local user.
- **`avd` must already be registered with the kernel module for the
  control socket to exist at all** - `main()` in `avd.c` still exits
  before starting the control socket if `genl_connect()`/
  `genl_ctrl_resolve()` fail (see that function). This means
  `av.ko` must be `insmod`'d before `avd` (and therefore before
  `avctl scan`/`quarantine`/any GUI use) will work at all, even though
  none of this protocol itself touches netlink. Making `avd` tolerate
  a missing module (retry registration in the background) would be a
  real behavior change to existing, tested startup logic - explicitly
  out of scope here.
