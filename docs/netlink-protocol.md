# Kernel ↔ Daemon Protocol (Generic Netlink)

This document + `av/netlink_chan.{c,h}` +
`userspace/avd/` establish the request/response channel; the actual YARA
matching logic still needs to be added inside `avd` as its own feature
commit.

## Why Generic Netlink

Plain `/proc` works for occasional writes (adding signatures — see
`sigtable.c`) but has no natural way for the **kernel to initiate** a
message and get a **correlated reply** back per-event. Generic Netlink
(genl) is the standard mechanism for this in Linux (systemd, udev,
nl80211 all use it) and doesn't require reserving a new protocol number
in the kernel headers the way a raw `NETLINK_*` family would.

## Message flow

```
 kernel module                          avd (userspace daemon)
 --------------                          ----------------------
 module load
   |
   |<--------- AV_C_REGISTER ------------|   daemon starts, registers
   |           (captures daemon's                its netlink port ID
   |            portid for unicast)
   |
 [execve on an unknown file - no
  signature match in sigtable]
   |
   |---------- AV_C_SCAN_REQUEST ------->|   unicast to daemon's portid
   |           REQID, PID, PATH,             (kernel generates a unique
   |           SHA256, DEV_MAJOR,            REQID per request)
   |           DEV_MINOR, INO
   |
   |                                     [ daemon opens PATH, checks its
   |                                       dev/ino against the request
   |                                       (falls back to /proc/PID/exe,
   |                                       else answers UNAVAILABLE),
   |                                       then runs YARA / fuzzy /
   |                                       TLSH on that fd ]
   |
   |<--------- AV_C_VERDICT -------------|   REQID (echoed back),
   |           VERDICT (0=clean/                VERDICT, RULE_NAME
   |           1=malicious/2=unavailable),
   |           RULE_NAME
   |
 [workqueue thread was blocked in
  av_netlink_scan_request(), wakes
  up via completion, matched by
  REQID; kills the process if
  VERDICT=malicious]
```

The workqueue thread (`av_work_fn` in `main.c`) blocks waiting for the
verdict with a timeout (default 12000ms — see `DAEMON_TIMEOUT_MS` in
`main.c`; raised from an earlier 2000ms default that was shorter than
avd's own `SCAN_TIMEOUT_SECS` of 10s, which meant any scan taking
longer than 2s had its verdict dropped here regardless of what avd
decided) — this is safe because it's
process context, not the atomic kprobe path. If the daemon isn't
running, isn't registered, or takes too long, the request fails, and
what happens next is now an **operator-configurable policy**, not a
fixed choice: fail-open (the default — treat the file as clean and let
the exec proceed) or fail-closed (kill it, same as a confirmed
malicious verdict). Fail-open vs fail-closed is a real design decision
— a security tool that fails open on timeout has a different threat
model than one that fails closed (blocks execution until it gets an
answer). Fail-open remains the default to avoid the daemon
crashing/restarting becoming a denial-of-service against every
unsigned exec on the system, but an operator running a
hardened/high-assurance deployment who'd rather block on "no verdict"
can flip it at runtime:

```bash
avctl policy get                    # fail-open | fail-closed
avctl policy set fail-closed        # requires root, same as the other /proc writes
avctl policy set fail-open          # back to the default
```

This is backed by `/proc/kernel_av_daemon_policy` (0644, single
`atomic_t` in `main.c`) — see `daemon_policy_proc_write()`'s comment
there for the exact accepted values (`fail-open`/`fail-closed`, plus a
mandatory trailing newline, same convention as the other `/proc`
write handlers). The 0644 reads are deliberate: unlike the three IOC
entries (signatures/trust/protected, `0640 root:hyprav` since #143),
this is a single flag rather than fingerprintable IOC content, and
the GUI policy display plus `avctl policy get` read it unprivileged.
Resets to fail-open on every module load/unload, same
as every other in-memory kernel-side state here; `avctl save`/`avctl
load` round-trip it alongside signatures/trust/protected-paths if you
want it to persist across reloads.

**Timing caveat, found while building this — since fixed:** the policy
used to be read inside `av_work_fn()` — i.e. at *verdict* time,
asynchronously, whenever that specific exec's workqueue item happened
to run — rather than captured back at the kprobe/exec moment itself. A
process that started (and was allowed past the kprobe) while this was
still fail-open could still get killed if an operator flipped it to
fail-closed before that exec's work item was processed, since the
check read the *current* value, not the value at launch time, and it
wasn't scoped to some other process either — flipping this from an
interactive shell with no daemon running could get that shell's own
recent exec caught by it too. **Fixed:** the exec kprobe handler
(now `handler_pre_bprm_check()`) snapshots the policy into `struct
av_work`'s `fail_closed` field at kprobe time, and `av_work_fn()`
enforces that snapshot instead of re-reading the live value — an
operator toggling the policy now only affects execs observed *after*
the flip, never ones already in flight.

## Commands

| Command | Direction | Purpose |
|---|---|---|
| `AV_C_REGISTER` | daemon → kernel | Daemon announces itself; kernel stores its netlink port ID for future unicasts. **Only one daemon connection is supported right now** — a second `REGISTER` from a different portid while one is live is rejected with `-EBUSY` (re-`REGISTER` from the already-pinned portid stays idempotent). |
| `AV_C_SCAN_REQUEST` | kernel → daemon | Kernel asks the daemon to analyze a file. |
| `AV_C_VERDICT` | daemon → kernel | Daemon's answer, correlated by `REQID`. |

## Attributes

| Attribute | Type | Used in | Notes |
|---|---|---|---|
| `AV_A_REQID` | u64 | SCAN_REQUEST, VERDICT | Kernel-generated, monotonically increasing. Daemon must echo it back unchanged — this is how concurrent requests (multiple execve calls in flight at once) get matched to the right waiter. |
| `AV_A_PID` | u32 | SCAN_REQUEST | PID of the process that's executing the file (informational for the daemon; the kernel does its own `pid_task()` lookup for the actual kill). |
| `AV_A_PATH` | nul-string | SCAN_REQUEST | Absolute path to the file. |
| `AV_A_SHA256` | nul-string | SCAN_REQUEST | Precomputed SHA-256 (kernel already computed it for the signature check, may as well forward it — saves the daemon a redundant hash for logging/caching). |
| `AV_A_VERDICT` | u8 | VERDICT | `0` = clean, `1` = malicious, `2` = unavailable (the daemon could not reach the file the kernel hashed - see *Scanning the hashed file* below). Any other value is rejected with `-EINVAL` (`av_verdict_valid()`). |
| `AV_A_RULE_NAME` | nul-string | VERDICT | Which rule/heuristic matched, for logging. Optional/empty on a clean verdict. |
| `AV_A_DEV_MAJOR` | u32 | SCAN_REQUEST | `major()` of the hashed file's `st_dev`, as userspace `fstat()` reports it (kernel side uses `vfs_getattr()`, not the raw inode fields, so btrfs subvolumes and overlayfs agree). |
| `AV_A_DEV_MINOR` | u32 | SCAN_REQUEST | `minor()` of the same. |
| `AV_A_INO` | u64 | SCAN_REQUEST | `st_ino` of the hashed file. The three identity attributes are sent together or not at all (omitted only if `vfs_getattr()` fails). |

## Scanning the hashed file (issue #227)

The kernel hashes the exec'd file through the `struct file` it pinned at
the probe, so a rename or unlink after the exec can't change what it
hashed. The daemon only gets `PATH`, and opens it by name some time
later. Without a check, a rename-swap in that window made YARA/ssdeep/
TLSH scan a decoy, and an unlink made the open fail - which avd used to
answer `CLEAN`.

So the request carries the file's identity, and avd scans only an fd
whose `fstat()` matches it:

1. Open `PATH` (`O_NONBLOCK`, regular files only). If its dev/ino match,
   scan it.
2. Otherwise open `/proc/<PID>/exe`. `mm->exe_file` follows the exec'd
   file through renames and unlinks, so this reaches the real file in
   the "exec, then swap the path" case. It is accepted on the same
   identity match only: for a script it names the interpreter, and
   before the exec commits it names the old image.
3. If neither matches, reply `AV_VERDICT_UNAVAILABLE`. The kernel applies
   the fail-open/fail-closed policy above to it, exactly like a timeout:
   fail-closed kills (`type=fail-closed reason=daemon-unavailable`),
   fail-open logs `event=unverified type=daemon` at warn - never
   `event=clean type=daemon`.

The fanotify verdict cache (`AVD_FANOTIFY=1`) is consulted only with the
`fstat()` of an fd that passed this check, so a decoy's cached `CLEAN`
can't answer for the hashed file.

**Step 2 and capabilities.** Opening another process's `/proc/<PID>/exe`
goes through `ptrace_may_access()`: without `CAP_SYS_PTRACE`, it needs
the same uid *and* a target whose permitted capabilities are a subset of
avd's. `packaging/avd.service`'s `CapabilityBoundingSet=` and the privsep
parent's `PS_PARENT_CAPS` both leave `CAP_SYS_PTRACE` out on purpose (see
`privsep_parent.h`), so under the shipped unit step 2 rarely succeeds and
a path swap usually ends in step 3. That is still safe - the swap is
never reported clean, and fail-closed blocks it - but under fail-open the
exec runs, logged as unverified. With `AVD_FANOTIFY=1` the race does not
arise: the exec is held and scanned through the event's own fd before it
runs.

Quarantine after a step-2 scan moves the real inode (linked through the
fd) and leaves whatever now sits at `PATH` alone: `quarantine_file()`
only unlinks `PATH` after an `lstat()` re-check that it still names the
fd's inode.

**Version skew.** A request with no identity attributes comes from a
module that predates them, and that module also rejects verdict `2`.
avd keeps the old by-path behaviour for those requests (including
`CLEAN` on a failed open) instead of making every such exec wait out
`DAEMON_TIMEOUT_MS`. An older avd ignores the new attributes and never
sends `2`.

**Testing the race.** `av.ko` has a test-only parameter,
`av_toctou_test_delay_ms` (0 by default, clamped to 2000), that makes
the exec work item sleep before hashing and so before the request
reaches avd. `tests/test_netlink.sh` sets it through
`/sys/module/av/parameters/` so its swaps land deterministically:
exec-then-unlink must come back as `event=unverified`, never
`event=clean`, and exec-then-rename-a-decoy must still SIGKILL the real
image (via step 2 - the test avd runs as full root) and leave the decoy
in place. Leave the parameter at 0 outside tests: while it is set every
exec waits that long and parks a worker.

## Known limitations (document these in your report)

- **Single daemon only.** No multi-client support - only one daemon can
  be registered at a time, and a second `REGISTER` from a different
  portid while one is live is rejected with `-EBUSY` (logged at
  `pr_alert`; a re-`REGISTER` from the already-pinned portid is
  idempotent). A replacement daemon after a crash is unaffected:
  `NETLINK_URELEASE` clears the slot when the old socket closes.
  **Fixed:** `REGISTER` and `VERDICT` now require
  `GENL_ADMIN_PERM` (CAP_NET_ADMIN), `VERDICT` is additionally
  checked against the currently-registered daemon's portid, and a live
  `REGISTER` can no longer be silently overwritten, so an
  unprivileged local process can no longer impersonate the daemon or
  answer someone else's scan request, and neither can a second
  privileged one while a daemon is live. `avd` already runs under `sudo`
  in every documented workflow, so this doesn't change how you run it -
  it just closes a gap where anything unprivileged previously could
  have disabled detection entirely by registering first.
- **`avd` did not authenticate the sender of `AV_C_SCAN_REQUEST`.** The
  kernel side checks `AV_C_VERDICT` against the registered daemon's
  portid (see above), but `avd` itself never registers a `genl_family`
  of its own - it's a plain client socket, so `GENL_ADMIN_PERM` (which
  only gates access to a *kernel*-registered `.doit` handler) never
  applied to messages arriving at `avd`. Any local process that knew
  `avd`'s portid (which defaults to its pid via netlink autobind, so
  as discoverable as `pgrep avd`) could unicast a forged
  `SCAN_REQUEST` straight to it, bypassing the kernel and any
  `CAP_NET_ADMIN` requirement - flooding the scan queue, or directing
  the (typically root) daemon to scan/quarantine an attacker-chosen
  path. **Fixed:** `msg_handler()` in `avd.c` now rejects any
  `AV_C_SCAN_REQUEST` whose `nlmsg_pid` isn't `0` (kernel-origin).
- **Module could be unloaded while a callback was still running.**
  `genl_family` was missing `.module = THIS_MODULE`, so generic
  netlink had no way to pin the module while `av_nl_register_doit()`
  or `av_nl_verdict_doit()` was actively executing on another CPU —
  an `rmmod` racing an in-flight callback from `avd` was a genuine
  use-after-free of module `.text`, not just a theoretical one.
  **Fixed** by adding `.module = THIS_MODULE` to the family struct.
- **Fail-open on timeout/no-daemon**, as above. **Addressed:** no
  longer a fixed choice — `avctl policy set fail-closed` makes it fail
  closed instead, at runtime, no module reload needed. Fail-open
  remains the default for the reason given above (avoid a crashed
  daemon becoming a system-wide DoS); fail-closed is opt-in for
  deployments that want it. The retroactive-kill hazard from flipping
  this mid-flight (see the timing caveat above the Commands table) is
  now fixed too — the policy is captured per-exec at kprobe time.
- **Kernel netlink API surface is version-sensitive**, same caveat as
  the syscall-wrapper kprobe hooking — `genl_family` struct layout has
  changed across kernel versions (notably where `.policy` lives). This
  code targets the layout used in kernels 5.10+, which covers all
  three CI targets (6.12/6.18/7.1.4), but is worth re-checking if you
  ever build against something older.
- `avd` now runs real detection logic (weighted YARA scoring with an
  override tier, fuzzy hashing, quarantine)
