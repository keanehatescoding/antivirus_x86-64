# avd privilege separation (design sketch for #103)

Status: proposal. Stage 0 is implemented in #200; stages 1 and 2 are
design only. Written against master at `08ff847` and revised after review
of #199.

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

## Contracts the split must not change

These already hold in `avd.c` today. Each stage has to keep them, and the
tests below check them.

1. **Action before answer.** `fan_run_task()` runs `perform_scan()`, which
   includes the quarantine, then `fan_cache_store()`, and only then
   `fan_respond()`. Whoever observes the answer (another process, the
   kernel's own `bprm_check` request that follows `FAN_ALLOW`) must find the
   quarantine already done. Nothing may be moved to after the response.
2. **Detector precedence and fall-through.** In order: (a) an exact
   signature match (only when the signature snapshot is non-empty) convicts
   immediately with `Sig:<name>` and score 0; (b) no rules loaded is an
   inconclusive CLEAN; (c) a YARA match convicts if an `override` rule fired
   or the summed weight reaches `MALICIOUS_SCORE_THRESHOLD`, and supplies
   `rule_name` and `score`; (d) a below-threshold YARA match records its
   score and falls through; (e) ssdeep, then (f) TLSH, each convict with
   `Fuzzy:<name>(<n>)` or `TLSH:<name>(<n>)`, keeping whatever score YARA
   recorded. The first conviction wins and later detectors do not run.
   `tests/test_perform_scan.sh` (from #200) pins every one of these
   outcomes.
3. **Bounded queue, non-blocking listener.** Scans run on `avd_scan_threads`
   pool threads fed by a queue bounded at `AVD_SCAN_QUEUE_MAX`. The fanotify
   listener enqueues with `queue_push(task, false)`, so a full queue is an
   immediate answer by the daemon policy, never a wait. The kernel-request
   and control-socket producers may block.
4. **Fanotify deadline.** The `AVD_FANOTIFY_TIMEOUT_MS` deadline is stamped
   when the event arrives, before `queue_push()`, so queue wait and scan time
   both count against it. When it expires the listener answers by the
   daemon policy and the scan result, if it ever arrives, is only logged.
5. **Fail open is `CLEAN` plus `inconclusive`.** `fan_run_task()` answers
   from `res.verdict` alone and never reads `res.inconclusive`;
   `fan_cache_store()` is what refuses to cache an inconclusive result. So
   every failure path must return a CLEAN verdict with `inconclusive = true`.
6. **Signatures can change at runtime, rules cannot.** Rules and both
   corpora are loaded once at startup (`main()`, before any thread starts)
   and never reloaded. The exact-signature snapshot is different:
   `fan_sigs_refresh()` replaces it while avd runs and bumps `fan_cache_gen`.

## Proposal

### Stage 0: split analysis from action (no behaviour change)

Implemented in #200. `perform_scan()` becomes `analyze_fd()` (SHA-256,
signature lookup, YARA, ssdeep, TLSH; fills a `struct scan_result`) plus an
acting half that quarantines once, then records metrics and history. The four
inline `quarantine_file()` calls become one, after the analysis, and contract
1 is untouched because `perform_scan()` still returns only after the
quarantine.

Stage 0 deliberately leaves the SHA-256 and signature lookup inside
`analyze_fd()`. Stage 1 moves them out (see below); doing that later keeps
#200 a pure refactor.

### Stage 1: unprivileged scan worker processes

Only the detectors that parse the file go into a worker: YARA, ssdeep and
TLSH. The parent keeps SHA-256 and the exact-signature lookup, both of which
then run first:

- Signatures change at runtime (contract 6). A worker that forked earlier
  would hold a stale copy and the parent would apply its answer as current.
  In the parent, the lookup sees the live snapshot and the existing
  `fan_cache_gen` handling stays exactly as it is.
- The parent computes the SHA-256 itself from the fd, or uses the digest the
  kernel already supplied for a netlink scan. That digest ends up in
  quarantine metadata and verdict history, so it must not be something a
  compromised worker can set. It is a fixed-size streaming loop with no
  attacker-controlled allocation or structure parsing, so it is the least
  risky code that reads the file, which is why it can stay.

#### The spawner

Workers are not forked from the main process. By the time a worker is
needed again (after a crash or timeout) the main process is multithreaded,
and that rules out the obvious options:

- `fork()` from a multithreaded process leaves the child with only the
  calling thread, and any mutex another thread held stays locked. Until it
  calls `exec`, POSIX lets the child use only async-signal-safe functions,
  while a scan worker needs `malloc` and all of libyara.
- `fork()` plus `exec` would be safe, but it throws away the compiled YARA
  rules and corpora that a forked child shares copy-on-write, forcing every
  worker to recompile them.

Instead, avd forks one **spawner** process, once, in the window that exists
today after `load_tlsh_corpus()` and before the first `pthread_create()` and
before any socket is opened (so the spawner inherits none of them). That
window has exactly one thread. The spawner:

- stays single-threaded for its whole life, so it can always `fork()` safely
- holds the compiled rules and corpora, which every worker it forks inherits
- is the only process that holds `CAP_SETUID`, `CAP_SETGID` and `CAP_SETPCAP`
  (the last to empty a worker's bounding set); everything else is dropped,
  with `NO_NEW_PRIVS` and its own small seccomp filter (fork, the credential
  calls, socket I/O)
- never reads a scanned file or handles file content, so it is not part of
  the attack surface
- on a request over its control socket, forks a worker, hardens it, and
  returns the worker's socket and pid to the parent

This also answers "who keeps the bootstrap capabilities for respawns": the
spawner does, and the main process does not need them (Stage 2).

Pool shape: each existing scan thread owns one worker process. The queue, the
pool size, `queue_push(task, false)` for the listener and the deadline
stamping are therefore unchanged; the worker round trip happens inside the
scan thread where the in-process scan happens today (contracts 3 and 4). The
control-socket `SCAN` path already enqueues to the same pool, so it uses
workers with no extra work.

If the spawner dies, no worker can be replaced. Proposal: avd exits non-zero
so systemd restarts it, which the kernel already treats like any avd crash
(its own fail-open/fail-closed policy applies in the meantime). Silently
falling back to scanning in the root process would defeat the point.

#### Worker hardening fails closed

The spawner applies these in order inside the child and checks every return
value. Any failure ends the child with `_exit(1)` before it reports ready;
no request is ever sent to a worker that has not reported ready.

1. rlimits: `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE=0` and a small
   `RLIMIT_NOFILE` (not `RLIMIT_NPROC`: seccomp already forbids `fork`, and a
   low NPROC set before `setuid` is a known way to make `setuid` misbehave)
2. close every inherited fd except the IPC socket (and one log fd if used)
3. `setgroups(0)`, then `setresgid` and `setresuid` to the dedicated user
   (for example `hyprav-scan`, declared next to the existing group in
   `packaging/hyprav.sysusers` and its Debian twin), then confirm that
   `setuid(0)` now fails
4. empty the bounding set, then clear the permitted, effective and
   inheritable sets
5. `prctl(PR_SET_NO_NEW_PRIVS, 1)`
6. install the seccomp allowlist last

Only then does the worker report ready. The parent does not take that on
trust: before dispatching, it reads `/proc/<pid>/status` and requires the
worker's uids and gids to be the dedicated ones, `CapEff`, `CapPrm` and
`CapBnd` to be zero, `NoNewPrivs: 1` and `Seccomp: 2`.

#### IPC

One `AF_UNIX`/`SOCK_SEQPACKET` socketpair per worker, strictly one request in
flight per worker.

- request: the already-open scan fd via `SCM_RIGHTS`, plus a fixed-size
  header holding the request id
- reply: a fixed-size struct: the echoed request id, verdict, inconclusive
  flag, score, rule name, and a few small advisory fields (YARA match count,
  override flag, fuzzy score, TLSH diff) so the parent can keep emitting the
  same log lines. The scan's log lines move to the parent; the worker writes
  no logs.

The fd is opened by the parent, so the worker needs no filesystem access:
read permission was decided at open time. The open file description is
shared with the parent, so the file offset is shared too. The worker uses
`pread` and `lseek`, and the parent already must not rely on the offset after
analysis (quarantine goes through `linkat` on the fd).

Descriptor lifetime. The worker receives with `MSG_CMSG_CLOEXEC`, accepts a
message carrying exactly one descriptor (zero or several is a protocol error:
it closes everything it was sent and reports failure), and closes the
descriptor on every path before replying: success, error, or short read. A
worker that is killed has its descriptors closed by the kernel. The small
`RLIMIT_NOFILE` is the backstop: a leak makes the worker fail
deterministically and get replaced, not drift towards the system limit. The
parent keeps its own copy of the fd until the acting half (quarantine) has
finished, then closes it.

Request association. Because there is one request in flight, the next reply
on a worker's socket can only belong to it, and the parent still requires the
echoed request id to match. After a timeout, a mismatch or any other anomaly
the parent kills the worker (`SIGKILL`) and closes its socket. A socket is
never reused after an anomaly, so a late reply can never be matched to a
later scan. The replacement gets a fresh socketpair from the spawner.

#### The parent treats every reply as untrusted

- length must be exactly the struct size; the request id must match
- `verdict` must be CLEAN or MALICIOUS, otherwise the reply is a failure
- `inconclusive` must be 0 or 1
- `rule_name` is forced NUL-terminated within its fixed size and restricted
  to a printable allowlist before it is logged, written to the quarantine
  `.meta` sidecar or stored in history
- `score` and the advisory fields are display-only; nothing is decided from
  them. They are clamped to a documented range (score: 0 to 10000, far above
  any sum of rule weights today) so they cannot corrupt a log line or an
  integer
- there is no digest in the reply (see above)

#### Failure handling

A worker that crashes, exceeds `SCAN_TIMEOUT_SECS`, or sends a malformed
reply is killed and replaced, and the scan returns the **canonical failure
result**: the whole `struct scan_result` zeroed, then `verdict = CLEAN`,
`inconclusive = true`, empty `rule_name`, score 0, with only the parent's own
digest filled in. Contract 5 needs exactly this, and starting from zero
rather than from a partly filled struct means no field of an earlier reply
can leak into it. This matches today's fail-open handling, but a worker
failure is also worth logging loudly: it is either a bug or an exploit
attempt.

The worker's own scan timeout is separate from the fanotify deadline. As
today, a held exec is answered by policy at `AVD_FANOTIFY_TIMEOUT_MS` while
the scan may still be running, and a result that arrives afterwards is only
logged (contract 4).

#### Rules never change, but the design assumes it

Rules and corpora are loaded once, so a worker's inherited copy cannot go
stale. If a reload feature is ever added, it must not leave old workers
serving: either the spawner and all workers are retired and recreated from
the new rules, or every reply carries a rules generation that the parent
validates before applying or caching it. Reload also cannot create a new
spawner from the multithreaded main process, so it needs its own design.

#### Seccomp allowlist

Default action kill. Expected contents: `read`, `pread64`, `lseek`,
`fstat`/`newfstatat` with `AT_EMPTY_PATH`, `mmap`, `munmap`, `mprotect`,
`mremap`, `brk`, `madvise`, `futex`, `dup`, `close`, `recvmsg`/`sendmsg` on
the IPC socket, `clock_gettime`, `clock_nanosleep`, `rt_sig*`, `getrandom`,
`exit_group`. Explicitly absent: `open*`, `socket`, `connect`, `execve*`,
`clone`/`fork`, `ptrace`, `kill`, anything that writes the filesystem. The
real list must come from tracing the test suite and a YARA scan with the
shipped rules, not from this guess. libseccomp is not currently a dependency;
either add it or emit the BPF program by hand (a short, auditable filter for
this list).

Optional extra layers once the above works: `chroot` to an empty directory
and `unshare(CLONE_NEWNET)` before dropping privileges. Seccomp already
forbids both filesystem and network access, so these are defence in depth.

#### Residual risk: a compromised worker that is reused

Process separation stops a compromised worker from becoming root, but a
worker that is exploited by one file keeps running and answers later
requests. It can then report MALICIOUS for a legitimate file the parent hands
it (which the parent will quarantine) or CLEAN for malware. It can only speak
about the file it was given, and it cannot reach anything else, but this is a
real integrity loss and the parent cannot detect it. Options, in increasing
cost: recycle each worker after a fixed number of scans (bounds the window);
use a fresh worker per scan from the spawner (removes it, at the price of one
`fork()` per scan, which must be measured against the fanotify deadline). This
is an open question below.

### Stage 2: shrink the parent

After init the parent still needs real power, so this stage is smaller than
the issue suggests. Candidates to confirm empirically, not assume:

- keeps: `CAP_NET_ADMIN` (verdicts), `CAP_SYS_ADMIN` (fanotify permission
  events), `CAP_KILL`, and whichever of `CAP_DAC_READ_SEARCH`,
  `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_CHOWN` the open/quarantine paths
  actually hit
- drops, once the spawner exists: `CAP_SETUID`, `CAP_SETGID` and
  `CAP_SETPCAP`. They live only in the spawner
- gains: `NO_NEW_PRIVS`, a bounding set limited to the list above, and a
  seccomp filter that excludes `execve`, `ptrace`, module loading and so on

This can also be done in `packaging/avd.service` with
`CapabilityBoundingSet=`, `NoNewPrivileges=yes` and `SystemCallFilter=`
without adding filesystem sandboxing, which the unit comment rightly avoids.
One catch: those settings apply to the whole unit including the spawner, so
the unit's bounding set has to include `CAP_SETUID`, `CAP_SETGID` and
`CAP_SETPCAP`, and its syscall filter has to allow the credential calls. The
main process then drops those capabilities itself after it has forked the
spawner. The unit comment is also worth rewording: avd cannot be confined to
a restricted filesystem view, but it can still be confined in capabilities
and syscalls.

## Rollout

- Opt-in first: `AVD_PRIVSEP=1`, like `AVD_FANOTIFY` today, then default on
  after one release of soak.
- Latency matters on the fanotify path, which holds every exec. One
  socketpair round trip is expected to be small compared with a YARA scan,
  but it should be measured, not assumed. The same measurement decides the
  worker-recycling question.
- Worker count follows the existing scan pool size.

## Tests

- hardening failure injection: make each step (setuid, capset, seccomp, ...)
  fail in a test build; the worker must exit without reporting ready and the
  parent must never send it a request
- the parent's `/proc/<pid>/status` check rejects a worker that skipped a
  step
- worker killed mid-scan: the scan is the canonical failure result and a new
  worker appears; repeat under concurrent scans with workers being killed, to
  exercise respawn from the multithreaded parent
- worker sends truncated, oversized, non-NUL-terminated or wrong-request-id
  replies; the parent stays correct and does not reuse that socket
- a late reply after a timeout is never matched to a later scan
- an unexpected extra or missing `SCM_RIGHTS` descriptor is rejected and
  closed
- many scans in a row (more than the worker's `RLIMIT_NOFILE`) never
  exhaust a worker's descriptors
- worker reply with a hostile rule name (control characters, path
  separators) never reaches the quarantine sidecar or log unsanitised
- every failure path yields exactly the canonical result, with no field left
  over from a previous reply
- the quarantine has completed before `FAN_ALLOW`/`FAN_DENY` is written
  (contract 1), and a full queue is still answered immediately by policy
  with the listener never blocking (contracts 3 and 4)
- seccomp kill is observed if a worker attempts `open()` (test hook)
- `tests/test_perform_scan.sh` and the existing QEMU boot and fanotify tests
  pass with `AVD_PRIVSEP=1`

## Open questions

1. User and group name for the worker, and whether it should be shared with
   anything existing.
2. Memory cost of N workers each holding the compiled rules. Fork
   copy-on-write should share most pages, but YARA's refcounting may dirty
   some; measure.
3. Worker lifetime: long-lived, recycled after K scans, or one per scan (see
   the residual-risk section). Needs the latency measurement.
4. Spawner death: exit and let systemd restart avd (proposed), or degrade to
   all-inconclusive and keep running.
5. Whether to kill a worker whose scan has already missed the fanotify
   deadline, instead of letting it finish and only logging the late result as
   today.

## Out of scope

Fuzzing the netlink and control-socket parsers and the metrics work from
#105; the BPF LSM fast path from #177.
