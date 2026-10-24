# avd privilege separation (design sketch for #103)

Status: proposal, no code yet. Written against master at `08ff847`.

## Problem

avd runs as root for its whole lifetime, and everything runs in one
process. The code that parses attacker-influenced bytes (the file being
scanned) sits in the same address space as the code that can quarantine
files, kill processes, answer fanotify permission events and send
netlink verdicts. A memory-safety bug in any of these is root:

- libyara scanning the file, including its `elf` module, which parses the
  scanned ELF in-process (the shipped rules import `elf` and `math`)
- libfuzzy (ssdeep) over the file contents
- the vendored TLSH implementation (`tlsh_core.c`) over the file contents
- `sha256_fd()`

Rule and corpus files are root-owned admin input and are not part of this
threat model; the scanned file is.

## What the code looks like today

- `userspace/avd/avd.c` is a single process. Scan workers, the fanotify
  listener and the control-socket threads are all pthreads.
- There is no `seccomp`, `setuid`, `capset`, `prctl` or `NO_NEW_PRIVS`
  anywhere in avd.
- `packaging/avd.service` is deliberately `User=root` and unsandboxed. Its
  comment argues avd needs to read any file and rename into quarantine,
  which is true of the parent but not of the parsing code.
- `perform_scan(fd, path, sha256, pid, on_demand, out)` is already almost
  the right seam. The analysis steps (`sha256_fd`, `yr_rules_scan_fd`,
  `check_fuzzy_corpus`, `check_tlsh_corpus`) need only an open fd and fill
  a `struct scan_result`. The privileged step, `quarantine_file(fd, path,
  rule, hash)`, is called inline from four places inside it (signature
  match, YARA, fuzzy, TLSH).

## Why not just seccomp and a capability drop in-process

Two constraints rule out the cheap version of the issue's first two bullets:

1. **Threads share one address space.** A per-thread seccomp filter on the
   scan threads does not help once an attacker has code execution: they
   can write to memory that the privileged threads use. glibc's `setuid()`
   also changes the uid of every thread, so scan threads cannot be
   de-privileged on their own either. Real separation needs a separate
   process.
2. **`CAP_NET_ADMIN` cannot be dropped after `bind()`.** Both genl ops in
   `av/netlink_chan.c` (`AV_C_REGISTER` and `AV_C_VERDICT`) are
   `GENL_ADMIN_PERM`, so every verdict reply is checked against
   `CAP_NET_ADMIN`. The issue's "drop CAP_NET_ADMIN after genl_connect +
   bind" would stop avd from answering the kernel. The parent keeps it.

## Proposal

### Stage 0: split analysis from action (no behaviour change)

Refactor `perform_scan()` into:

- `analyze_fd(fd, sha256_hint) -> struct analysis` (hash, verdict,
  rule name, score, inconclusive). No filesystem writes, no logging of
  attacker strings beyond what the parent decides to print.
- the remainder (quarantine, `verdict_history`, fanotify cache, latency
  counters) staying in the parent and acting on the returned struct.

This hoists the four inline `quarantine_file()` calls into one place
after analysis. It is worth landing on its own and keeps the later diffs
small.

### Stage 1: unprivileged scan worker processes

The parent loads rules and corpora (trusted, root-owned input) and then
forks N workers, so each worker inherits the compiled YARA rules and
corpora copy-on-write and nothing is re-parsed. Each worker, before
serving any request:

1. closes every inherited fd except its IPC socket (and stderr or a log
   fd)
2. `setgroups(0)`, `setgid`/`setuid` to a dedicated user (for example
   `hyprav-scan`, declared next to the existing group in
   `packaging/hyprav.sysusers` and the Debian twin)
3. `prctl(PR_SET_NO_NEW_PRIVS, 1)` and clears all capabilities
4. sets `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE=0`, `RLIMIT_NOFILE`
5. installs a seccomp allowlist (below)

IPC is one `AF_UNIX`/`SOCK_SEQPACKET` socketpair per worker:

- request: the already-open scan fd via `SCM_RIGHTS` plus a small
  fixed-size header (request id, optional precomputed sha256)
- reply: a fixed-size struct (verdict, score, inconclusive flag, rule
  name, sha256)

The fd is opened by the parent, so the worker needs no filesystem access
at all: read permission was decided at open time.

**The parent treats every reply as untrusted.** It checks the length,
range-checks the verdict, forces NUL termination, and sanitises the rule
name before it is logged, written to the quarantine `.meta` sidecar or
stored in history. A compromised worker controls those bytes.

**Failure handling.** A worker that crashes, exceeds the existing scan
deadline (`SCAN_TIMEOUT_SECS`), or sends a malformed reply is killed and
respawned, and the scan is reported as inconclusive. That matches the
daemon's current fail-open policy (the fanotify docs keep fail-open as the
default), but a crash is also a signal worth logging loudly: it is either
a bug or an exploit attempt.

**Seccomp allowlist.** Default action kill. Expected contents: `read`,
`pread64`, `lseek`, `fstat`/`newfstatat` with `AT_EMPTY_PATH`, `mmap`,
`munmap`, `mprotect`, `mremap`, `brk`, `madvise`, `futex`, `dup`, `close`,
`recvmsg`/`sendmsg` on the IPC socket, `clock_gettime`,
`clock_nanosleep`, `rt_sig*`, `getrandom`, `exit_group`. Explicitly
absent: `open*`, `socket`, `connect`, `execve*`, `clone`/`fork`, `ptrace`,
`kill`, anything that writes the filesystem. The real list must come from
tracing the test suite and a YARA scan with the shipped rules, not from
this guess. libseccomp is not currently a dependency; either add it or
emit the BPF program by hand (a short, auditable filter for this list).

Optional extra layers once the above works: `chroot` to an empty
directory and `unshare(CLONE_NEWNET)` before dropping privileges. Seccomp
already forbids both filesystem and network access, so these are
defence in depth.

### Stage 2: shrink the parent

After init the parent still needs real power, so this stage is smaller
than the issue suggests. Candidates to confirm empirically, not assume:

- keeps: `CAP_NET_ADMIN` (verdicts), `CAP_SYS_ADMIN` (fanotify permission
  events), `CAP_KILL`, and whichever of `CAP_DAC_READ_SEARCH`,
  `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_CHOWN` the open/quarantine paths
  actually hit
- gains: `NO_NEW_PRIVS`, a bounding set limited to the list above, and a
  seccomp filter that excludes `execve`, `ptrace`, module loading and so
  on

This can also be done in `packaging/avd.service` with
`CapabilityBoundingSet=`, `NoNewPrivileges=yes` and
`SystemCallFilter=` without adding filesystem sandboxing, which the unit
comment rightly avoids. That makes the unit comment worth rewording: avd
cannot be confined to a restricted filesystem view, but it can still be
confined in capabilities and syscalls.

## Rollout

- Opt-in first: `AVD_PRIVSEP=1`, like `AVD_FANOTIFY` today, then default
  on after one release of soak.
- Latency matters on the fanotify path, which holds every exec. One
  socketpair round trip is expected to be small compared with a YARA
  scan, but it should be measured, not assumed.
- Worker count follows the existing worker pool size.

## Tests

- worker killed mid-scan returns inconclusive and a new worker appears
- worker sends truncated, oversized or non-NUL-terminated replies; parent
  stays correct
- worker reply with a hostile rule name (control characters, path
  separators) never reaches the quarantine sidecar or log unsanitised
- seccomp kill is observed if a worker attempts `open()` (test hook)
- the existing QEMU boot and fanotify tests pass with `AVD_PRIVSEP=1`

## Open questions

1. User and group name for the worker, and whether it should be shared
   with anything existing.
2. Memory cost of N workers each holding the compiled rules. Fork
   copy-on-write should share most pages, but YARA's refcounting may
   dirty some; measure.
3. Whether `sha256_fd()` stays in the parent (cheap, simple, but it is
   untrusted-content code) or moves into the worker. Leaning worker, with
   the parent trusting nothing it returns.
4. Interaction with the control-socket `SCAN` path, which also calls
   `perform_scan()`: it should use the same worker pool.

## Out of scope

Fuzzing the netlink and control-socket parsers and the metrics work from
#105; the BPF LSM fast path from #177.
