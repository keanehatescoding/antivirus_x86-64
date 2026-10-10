# Pre-exec Enforcement (fanotify)

Phase 2 of #102, implemented in #176. When this mode is on, `avd` holds
every exec on a marked local filesystem until it has a verdict. It
answers `FAN_DENY` for a malicious image, so the exec fails with `EPERM`
before the program runs. The kernel module's `bprm_check` kprobe can
only kill a process after it has started. The kprobe stays loaded and is
still the detector whenever `avd` is down or a filesystem is not marked.

## Turning it on

Enforcement is **opt-in**. Holding every exec on the machine behind a
userspace daemon is a different risk from scanning after the fact.

| Variable | Default | Meaning |
|---|---|---|
| `AVD_FANOTIFY` | unset (off) | `1` enables pre-exec enforcement. |
| `AVD_FANOTIFY_TIMEOUT_MS` | `11000` (the scan timeout + 1 s) | Watchdog deadline per held exec, 100–60000. A malformed or out-of-range value is ignored (logged) and the default is used. |

Under systemd:

```
systemctl edit avd.service
  [Service]
  Environment=AVD_FANOTIFY=1
```

At startup `avd` logs `fanotify pre-exec enforcement active on N
filesystem(s)`. If `fanotify_init()` fails, or no filesystem can be
marked, `avd` logs `pre-exec enforcement disabled` and carries on in
post-exec mode. A missing `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` is one
cause.

## How it works

- **Marks.** A listener thread puts a `FAN_MARK_FILESYSTEM`
  `FAN_OPEN_EXEC_PERM` mark on every filesystem in
  `/proc/self/mountinfo`, skipping these:
  - mounts with `noexec`;
  - pseudo filesystems: proc, sysfs, cgroup and similar;
  - network filesystems: nfs, cifs/smb, 9p, ceph and similar;
  - FUSE (`fuse`, `fuseblk`, `fuse.*`).

  Network and FUSE filesystems are skipped on purpose. Marking them
  would put a network round-trip, or another userspace daemon, in front
  of every exec. A FUSE server that execs would also deadlock against
  `avd`. tmpfs **is** marked, because `/tmp` and `/dev/shm` are where
  droppers usually land. The listener polls mountinfo for `POLLPRI`, so
  filesystems mounted later are marked too. See `fan_parse.h` for the
  parser and the skip list.
- **Verdicts.** A held exec is judged from its open event fd. There is no
  path to re-open, so the file can't be swapped between the check and the
  open. The checks run in this order:
  1. the verdict cache;
  2. a SHA-256 lookup in `avd`'s snapshot of `/proc/kernel_av_signatures`;
  3. the normal scan pipeline (YARA, fuzzy hashes, TLSH) on the shared
     worker pool.

  Cache hits are answered on the listener thread. Misses go to the
  worker pool.
- **Signatures.** `avd` hashes exec images with SHA-256 only, so the
  snapshot holds only the `sha256` entries. It is refreshed every 2 s.
  When its content changes, the whole verdict cache is invalidated, so
  `avctl add sha256 …` also takes effect on files already cached as
  clean. MD5 and SHA-1 signatures are still enforced by the kernel's
  post-exec path only.
- **Verdict cache.** The cache is direct-mapped on `(dev, ino)`. An entry
  only answers for the exact `(size, mtime, ctime)` it was scanned at.
  ctime is the change cookie: userspace cannot set it, and every write,
  truncate, chmod or rename-over bumps it.
- **Netlink dedup.** `FAN_OPEN_EXEC_PERM` fires in `open_exec()`, before
  `security_bprm_check()`. So when the kernel module then sends its own
  scan request for the same exec, `avd` answers it from the cache
  instead of scanning the image a second time.
- **Watchdog.** The kernel has no timeout for permission events, and an
  unanswered one would hold that exec forever. So every cache miss gets
  a deadline of `AVD_FANOTIFY_TIMEOUT_MS`. When it passes, or right away
  if the scan queue is full, the listener answers by the daemon policy
  in `/proc/kernel_av_daemon_policy` (`avctl policy set`), re-read each
  time:
  - **fail-open** (the default): `FAN_ALLOW`.
  - **fail-closed**: `FAN_DENY`.

  The kernel applies the same policy to netlink requests that `avd`
  never answers.
- **Re-entrancy.** `avd` never execs anything, and
  `tests/test_avd_no_exec.sh` checks this against the built binary and
  its linked libraries. `FAN_OPEN_EXEC_PERM` does not fire for read
  opens or for ld.so's library mmaps. So nothing `avd` does while
  answering an event can raise another event. As an extra guard, events
  from `avd`'s own pid are always allowed.
- **Shutdown.** On SIGTERM, the workers finish and answer the scans
  they already hold, the listener stops, and the fanotify fd is closed.
  Closing it releases every mark, and the kernel allows any permission
  event that was never read. Exec then falls back to the kprobe path.

## Limitations

- **Freshly written files are not cached.** The cache key includes
  ctime, but a same-size rewrite in the same timestamp tick keeps it
  (before 6.13's multigrain timestamps, and on filesystems without
  them). So a verdict is only cached for a file whose ctime was more
  than 3 seconds old when the exec arrived. Any later change then gets
  a new ctime on every kernel. Until a new file settles, each exec of
  it is scanned in full.
- **Interpreted content.** The scan covers the image being exec'd. For
  `#!` scripts that means the script file is scanned, and YARA rules
  match on it. A file read by an interpreter such as `python3 evil.py`
  is not an exec and is not held.
- **Unmarked filesystems.** Network filesystems, FUSE and `noexec`
  mounts are only covered by the post-exec kprobe.
- **Fail-open default.** If a scan is slower than the timeout, or the
  queue is full, the exec is allowed. Choose fail-closed with
  `avctl policy set fail-closed` if availability matters less than
  coverage.

## Observability

`STATUS` on the control socket (see `avd-socket-protocol.md`) has five
extra fields: `fanotify_active`, `fan_events`, `fan_cache_hits`,
`fan_denied` and `fan_fallbacks`. `fan_fallbacks` counts the execs
answered by policy rather than by a verdict. The GUI dashboard shows
them in its "pre-exec enforcement" row. Denials are logged as
`avd: BLOCKED exec of "<path>" (pid N): <rule>`.

## Cost

Measured by `tests/test_fanotify_exec.sh` in a 2-vCPU virtme-ng guest
by timing a loop of `/bin/true` execs:

| | per exec |
|---|---|
| enforcement off, repeated binary | ~3.6 ms |
| enforcement on, cache hit | ~2.9 ms |
| enforcement off, first-seen binary | ~3.6 ms |
| enforcement on, first-seen binary (full scan) | ~7.1 ms |

Cache hits run *faster* than with enforcement off, because the kernel's
`bprm_check` request is answered from the cache instead of rescanned. A
first-seen binary pays about 3.5 ms for the scan.

## Testing

`tests/test_fanotify_exec.sh` marks filesystems system-wide, so it
refuses to run outside a VM. Run it in a throwaway guest booted from the
host kernel:

```
tests/run_fanotify_vng.sh     # needs virtme-ng and /dev/kvm, no root on the host
```

It covers the following:
- marking a newly mounted filesystem;
- cache hits;
- EICAR and YARA-matched script denials;
- live signature updates invalidating cached verdicts;
- the watchdog under both fail-open and fail-closed;
- exec behaviour after `avd` stops;
- the cost figures above.

`tests/test_fan_parse.sh` (parsers) and `tests/test_avd_no_exec.sh`
(re-entrancy) run anywhere and are part of `tests/run_all.sh`.
