# avd privilege separation (design sketch for #103)

Status: Stage 0 is merged (#200). Stage 1 is built in slices, all tested: the
wire format and reply validation (`userspace/avd/privsep_proto.h`), the
parent/content split inside `analyze_fd()`, the worker side
(`privsep_worker.h`: the hardening sequence, the seccomp filter and the
request/reply loop), the spawner with its control channel
(`privsep_spawner.h`) and the parent-side dispatch client
(`privsep_client.h`: reader thread, request table, the `/proc/<pid>/status`
check, canonical failure on any anomaly). Stage 1e wires them into avd behind
`AVD_PRIVSEP=1` (see "As wired into avd" under Rollout). Stage 1f locks the
spawner itself down (`privsep_lockdown.h`: capabilities cut to four,
`NO_NEW_PRIVS`, a seccomp superset filter; see "As implemented" under "The
spawner"), and avd now logs why the spawner died (see "Open items").
`tests/test_fanotify_exec.sh --privsep` runs the end-to-end fanotify suite with
privilege separation on (see "End-to-end test with privilege separation on");
it is a manual run, not a CI job, and it passes, as does
`tests/test_avd_socket.sh --privsep` (scan, quarantine, restore and delete over
the control socket). Stage 2 step 2 (the main process drops
capabilities once the spawner exists, `privsep_parent.h`) is built and tested;
the parent's seccomp filter (step 3) and the unit's `CapabilityBoundingSet=`
are not (see "Stage 2").
Written against
master at `08ff847` and revised after review of #199.

## Problem

avd runs as root for its whole lifetime, and everything runs in one
process. The code that parses attacker-influenced bytes (the file being
scanned) sits in the same address space as the code that can quarantine
files, answer fanotify permission events and send the netlink verdicts the
kernel module acts on. A memory-safety bug in any of these is root:

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

Merged in #200: `perform_scan()` is `analyze_fd()` (SHA-256,
signature lookup, YARA, ssdeep, TLSH; fills a `struct scan_result`) plus an
acting half that quarantines once, then records metrics and history. The four
inline `quarantine_file()` calls became one, after the analysis, and contract
1 is untouched because `perform_scan()` still returns only after the
quarantine.

Stage 0 deliberately left the SHA-256 and signature lookup inside
`analyze_fd()` so #200 stayed a pure refactor. Stage 1 separates them (see
below): `analyze_fd()` now does the hash and signature lookup itself and hands
the rest to `analyze_content()`, which is the part a worker will run.

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
today after `load_tlsh_corpus()` and before `nl_socket_alloc()`, which is also
before the first `pthread_create()`. That window has exactly one thread and
no sockets, so the spawner inherits none of avd's netlink, control or
fanotify descriptors.

**Bootstrap channel.** Just before that fork the main process creates one
`socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC)`. The spawner inherits one
end and the main process keeps the other. Right after the fork the main
process closes the spawner's end, and the spawner closes every descriptor it
inherited except its end and stderr. There is no named rendezvous point, so
nothing to race or spoof, and the spawner needs neither filesystem access nor
`bind()`. EOF on this channel is how each side learns the other has died.

Messages are fixed-size and treated as untrusted input in both directions.
Workers are named by a `worker_id` the spawner assigns, never by pid:

- `SPAWN(request_id)`: the spawner makes a `socketpair`, forks a worker, and
  waits (bounded by a short startup timeout) for the worker's own readiness
  report, which the worker sends on its socket only after every hardening
  step has succeeded. Only then does it reply
  `READY(request_id, worker_id, pid)` with the main process's end of the
  worker socket attached via `SCM_RIGHTS`. If the worker exits or closes its
  socket first, sends anything else, or the timeout expires, the spawner kills
  and reaps it and replies `FAILED(request_id, reason)`, where `reason`
  distinguishes fork, hardening and timeout failures
- `KILL(worker_id)`: the spawner sends `SIGKILL` to that worker
- `EXITED(worker_id, wait status)`: sent unprompted whenever the spawner reaps
  a worker, so the cause (exit code or signal) can be logged

`worker_id` is a 64-bit counter that only increases for the spawner's
lifetime and is never reused, so a delayed `EXITED` for a worker that has
already been replaced can only name the old one. The main process ignores
(and logs) any message naming an id it is not tracking, and a `KILL` for an
id that has already exited is a no-op.

**Correlating replies.** Scan threads replace their workers independently, so
several `SPAWN`s can be outstanding at once, and `EXITED` events arrive
unprompted on the same channel. The `request_id` is a 64-bit counter chosen by
the main process, echoed in `READY` and `FAILED`. One small reader thread in
the main process (created after the spawner is forked) owns reads from the
channel: it hands each `READY`/`FAILED` to the scan thread waiting on that
`request_id`, applies each `EXITED` to the worker table, and drops anything
naming a request or worker it does not know. Writers (`SPAWN`, `KILL`) share
the channel under a lock. A scan thread waits for its reply with a bound a
little above the spawner's startup timeout; a reply that never comes counts
as the spawner being unresponsive (see below). The spawner itself handles
concurrent spawns as a small state machine in its single `poll()` loop, one
entry per pending `request_id`, so a slow-starting worker never blocks the
loop.

The spawner:

- stays single-threaded for its whole life, so it can always `fork()` safely
- holds the compiled rules and corpora, which every worker it forks inherits
- is the only process that holds `CAP_SETUID`, `CAP_SETGID` and `CAP_SETPCAP`
  (the last to empty a worker's bounding set), plus `CAP_KILL`, which it needs
  to signal a worker running as a different uid; everything else is dropped,
  with `NO_NEW_PRIVS` and a seccomp filter that is a **superset** of the
  worker allowlist (see "Seccomp filters stack" below)
- never reads a scanned file or handles file content, so it is not part of
  the attack surface

This also answers "who keeps the bootstrap capabilities for respawns": the
spawner does, and the main process does not need them (Stage 2).

**As implemented (`privsep_spawner.h`).** The behaviour above is in, and the
spawner's own lockdown is described in the next subsection. These details are
worth knowing that the sketch did not say:

- One fixed 40-byte struct carries every message in both directions, and each
  receiver validates it per sender class: a type that sender may not send,
  a field that type does not use being non-zero, a `READY` without exactly one
  descriptor, or a descriptor on anything else is malformed, and every
  descriptor that arrived is closed. Malformed input from main is dropped (the
  channel is `SEQPACKET`, so there is no stream to resynchronise, and nobody
  to answer).
- The worker's readiness report is the same struct with type `WORKER_READY`,
  sent with `sendmsg()` on the IPC descriptor, which is the one send call the
  worker filter allows.
- A hardening failure is reported through the worker's exit code,
  `64 + step`, and decoded when the spawner reaps it, so `FAILED` carries the
  step number. Any other exit before ready, including code 64 itself and
  codes past the last step, is `FAILED(EXITED)` with the raw wait status.
  Besides `FORK`, `HARDEN` and `TIMEOUT` there are `EXITED`, `PROTOCOL` (a
  malformed ready report) and `RESOURCE` (`socketpair()` failed or a table is
  full).
- The spawner resets `SIGCHLD` to its default disposition at startup. A
  caller that had it ignored (or set `SA_NOCLDWAIT`) would make the kernel
  reap workers itself, `waitpid()` would fail with `ECHILD`, and no `EXITED`
  would ever be sent.
- A zero-length record is not EOF. `recvmsg()` returns 0 for both a closed
  peer and an empty `SEQPACKET` record, so EOF requires a hangup as well; an
  empty record is malformed and dropped, and cannot shut the spawner down.
- A pending worker whose socket reaches EOF is not failed on the spot: the
  exit status, which names the hardening step, arrives with `SIGCHLD`, and
  the startup deadline covers a worker that closed its socket and kept
  running. The closed socket is also dropped from the `poll()` set, because a
  closed `SEQPACKET` peer reports `POLLHUP` forever and would spin the loop.
- Pending and live workers share one budget (512) with a smaller bound on
  simultaneous spawns (64), so a pending worker can always be promoted. A
  `SPAWN` over either bound is answered `FAILED(RESOURCE)` immediately.
- A worker is named by `worker_id` only after `READY`, so a `KILL` can only
  name a live worker. A pending one is bounded by the startup timeout.
- The spawner's replies are blocking sends. If main stops draining the
  channel the spawner stalls, which is why the reader thread in main must
  always drain it, and why a send failure ends the spawner (main is gone).
- The pid the worker compares `getppid()` against is recorded by the spawner
  before `fork()`. Reading it in the child would also accept a spawner that
  had already died and orphaned it.

**As implemented: the spawner's lockdown (`privsep_lockdown.h`).** The spawner
locks itself down inside `ps_spawner_run()`, once its own setup is done and
before it serves anything. It cannot be switched off in a production build.
The steps run in this order. Steps 1 to 4 are read back; step 5 (seccomp) is
checked only by the return value of `prctl(PR_SET_SECCOMP)`. A failure at any
step ends the spawner with exit status `16 + step`, avd sees the channel close
and refuses to run:

1. bounding set cut to `CAP_SETUID`, `CAP_SETGID`, `CAP_SETPCAP`, `CAP_KILL`
   (a missing one is an error: the next step could not raise it)
2. effective and permitted set to the same four, inheritable empty (which also
   empties the ambient set)
3. `NO_NEW_PRIVS`
4. `PR_SET_PDEATHSIG` again, read back, and `getppid()` must still be avd. A
   capability drop should not clear it, but the contract is "if avd dies, so
   do I", so a kernel or a reordering that disagrees fails closed
5. the seccomp filter, last

The filter is built by a small label assembler (about 75 instructions) rather
than by hand-computed offsets. It is a superset of the worker allowlist plus
what only the spawner needs, and the extra list came from tracing a real
spawner and the hardening of a real worker with `strace -f`, not from reading
the code. Things the trace turned up that the sketch missed:

- `set_robust_list`: glibc calls it in every fork child, so it runs after the
  spawner's filter is installed
- `setuid` and `setgid`: worker hardening probes that `setuid(0)` now fails,
  and a killed probe would be a worker that can never start
- `signalfd4` is not on the list at all: the spawner calls it before the
  filter exists, which is why the lockdown comes last. (`rt_sigaction` is on
  the list, through the worker allowlist.)

Argument checks: `prctl` only for the seven options in use (and
`PR_SET_PDEATHSIG` only with `SIGKILL`, which stops it being cleared with
`prctl` but not by a credential change; see "Residual risk: a compromised
spawner can outlive avd" below), `kill` only with `SIGKILL` (the signal only, not the
target; see "Residual risk: the spawner can signal any process" below), `clone` only with exactly `fork()`'s flags (`CHILD_SETTID`,
`CHILD_CLEARTID`, exit signal `SIGCHLD`, upper half zero, so no threads and no
`CLONE_NEW*`), `socketpair` only `AF_UNIX`, `prlimit64` only on pid 0,
`newfstatat` only with `AT_EMPTY_PATH`. Everything else, including `open*`,
`socket`, `execve*`, `ptrace`, `write`, `mount`, `bpf` and `clone3`, kills the
spawner.

The filter depends on glibc's behaviour: `fork()` is `clone`, not `clone3`,
and `poll` is `poll`, not `ppoll` (glibc 2.39 on x86-64, checked here). On a
libc that differs the spawner dies on its first spawn, avd exits and the
failure is loud, but nothing in avd's log yet says the cause was a seccomp
kill (see "Open items"). `tests/test_privsep_lockdown.sh` runs a real `fork()`
under the filter, so a build host that differs fails there first.

**Reaping and lifecycle.** The spawner is the parent of every worker, so it is
the only process that can reap them, and it must. It blocks `SIGCHLD` and
reads it from a `signalfd` in the same `poll()` as the control channel and
the sockets of pending spawns. (A self-pipe is the alternative only if
`SIGCHLD` is *not* blocked and a handler writes to the pipe: a blocked
signal never runs its handler, so the two must not be combined.) `SIGCHLD`s
coalesce, which is why the reap below loops. On each wakeup it calls
`waitpid(-1, &status, WNOHANG)` in a loop until that returns 0, and sends an
`EXITED` message per worker. `KILL` only sends the signal and leaves the
reaping to that loop: a blocking `waitpid()` could hang the spawner on a
process stuck in uninterruptible sleep. Without this loop every failed
worker would stay a zombie and repeated failures would exhaust the process
table.

The main process never signals a worker pid itself. Because only the spawner
reaps, a pid cannot be reused between the spawner deciding to signal it and
the signal being sent, which a signal from the main process could not
guarantee. The main process also needs no `CAP_KILL` for this.

Orphans. Each worker sets `PR_SET_PDEATHSIG` to `SIGKILL`, and so does the
spawner with respect to the main process, so killing avd leaves nothing
running, unless the spawner is compromised (see "Residual risk: a compromised
spawner can outlive avd"). The signal follows the thread that forked; the spawner is forked by
the main thread, which lives as long as the process.

Pool shape: each existing scan thread owns one worker process. The queue, the
pool size, `queue_push(task, false)` for the listener and the deadline
stamping are therefore unchanged; the worker round trip happens inside the
scan thread where the in-process scan happens today (contracts 3 and 4). The
control-socket `SCAN` path already enqueues to the same pool, so it uses
workers with no extra work.

If the spawner dies, no worker can be replaced (the main process sees EOF on
the channel). It can also hang rather than die: a `SPAWN` that gets no reply
within its bound fails that one scan with the canonical failure result, and a
run of consecutive missed replies is treated like death, since a hung spawner
cannot recover on its own. Proposal: avd exits non-zero so systemd restarts it, which the
kernel already treats like any avd crash (its own fail-open/fail-closed
policy applies in the meantime). Silently falling back to scanning in the
root process would defeat the point.

#### Worker hardening fails closed

The spawner applies these in order inside the child and checks every return
value. Any failure ends the child with `_exit(1)` before it reports ready on
its socket; the spawner then replies `FAILED`, so no request is ever sent to
a worker that has not reported ready.

1. close every inherited fd except the IPC socket (and one log fd if used)
2. rlimits: `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE=0` and a small
   `RLIMIT_NOFILE` (not `RLIMIT_NPROC`: seccomp already forbids `fork`, and a
   low NPROC set before `setuid` is a known way to make `setuid` misbehave)
3. empty the bounding set
4. `setgroups(0)`, then `setresgid` and `setresuid` to the dedicated user
   (for example `hyprav-scan`, declared next to the existing group in
   `packaging/hyprav.sysusers` and its Debian twin), then confirm that
   `setuid(0)` now fails
5. clear the permitted, effective and inheritable sets, and read them back
6. `prctl(PR_SET_NO_NEW_PRIVS, 1)`
7. `prctl(PR_SET_PDEATHSIG, SIGKILL)`, then read it back with
   `PR_GET_PDEATHSIG` and require `SIGKILL`, then require `getppid()` to equal
   the pid the spawner recorded before the `fork()`
8. install the seccomp allowlist last

Two of these differ from the first draft of this document, both found while
implementing `privsep_worker.h`:

- The bounding set (3) is emptied *before* the credential change (4), not
  after. `PR_CAPBSET_DROP` needs `CAP_SETPCAP` in the effective set, and
  changing the real, effective and saved uid away from 0 clears it, so the
  drop fails with `EPERM` if it comes second. The tests check this: swapping
  the two makes hardening fail at the bounding-set step.
- Descriptors are closed (1) *before* the rlimits (2). On a kernel without
  `close_range()` the fallback walks descriptor numbers up to the current
  `RLIMIT_NOFILE`, which would miss open descriptors above a limit that had
  already been lowered.

`ps_worker_harden()` returns the number of the step that failed (and leaves
`errno`), so the spawner can say which one in `FAILED`.

The parent-death signal needs both the order and the handshake above:

- The kernel clears it whenever a process changes its effective or
  filesystem uid or gid (tried here: set, then `setresuid()`, and
  `PR_GET_PDEATHSIG` reads back 0). So it is set *after* step 4, never
  before, and read back so that a later reordering fails closed instead of
  silently leaving orphans.
- Setting it is not enough by itself. If the spawner died before the child
  called `prctl()`, no signal will ever arrive. So the spawner records its own
  pid before the `fork()` and the child, after the `prctl()`, exits unless
  `getppid()` still equals it.
- The spawner does the same against the main process, right after it is
  forked and again after its own capability drop.
- The packaged unit's default `KillMode=control-group` also cleans up
  descendants on a service stop or restart, but not a manual launch, so it
  complements this and does not replace it.

Only then does the worker report ready, and only on that report does the
spawner send `READY`. The main process does not take that on
trust: before dispatching, it reads `/proc/<pid>/status` (the pid from
`READY`; the spawner has no filesystem access, so the main process does
this) and requires the worker's uids and gids to be the dedicated ones,
`CapEff`, `CapPrm` and `CapBnd` to be zero, `NoNewPrivs: 1` and
`Seccomp: 2`. The pid is used for this read-only check and never to signal
or address the worker: dispatch goes through the socket, and signals go
through the spawner. A stale pid can therefore only make the check fail,
which gets the worker replaced.

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
the parent has the spawner `KILL` the worker and closes its own end of the
socket. A socket is never reused after an anomaly, so a late reply can never be matched to a
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

#### Seccomp allowlist (worker)

Default action kill. Expected contents: `read`, `pread64`, `lseek`,
`fstat`, `fstatfs`, `newfstatat` with `AT_EMPTY_PATH`, `mmap`, `munmap`, `mprotect`,
`mremap`, `brk`, `madvise`, `futex`, `dup`, `close`, `recvmsg`/`sendmsg` on
the IPC socket, `clock_gettime`, `clock_nanosleep`, `rt_sig*`, `getrandom`,
`exit_group`. Explicitly absent: `open*`, `socket`, `connect`, `execve*`,
`clone`/`fork`, `ptrace`, `kill`, anything that writes the filesystem. The
real list has now been checked against a trace of the real detection path
(`analyze_content()`: libyara 4.5.0 with the shipped rules, ssdeep and TLSH,
over small and large ELF files, random data, text and an empty file, on
glibc 2.39, linked with `-z now` like the shipped binary). The scan makes
12 distinct syscalls in a single thread with no `clone`, and the list above
covered all of them except one: **`fstatfs`**, which libyara calls on the
scan descriptor. It takes a descriptor and an output buffer and no path, so
it is allowed without argument checks. Without it every scan was killed with
`SIGSYS`; with it all of the traced cases complete under the real filter.

Two caveats. The trace is of one libyara and libc; another distribution may
call something else (`statx`, `fcntl`), and a worker killed for that would
turn every scan into a fail-open result, so the parent must report a
`SIGSYS` death loudly and a startup self-test scan must catch it before avd
serves anything (see the dispatch notes). And the worker may never log:
`analyze_content()` printed to stdout and stderr, and any such call, however
rare (a buffer filling, an "over the size cap" notice), is killed by the
filter. The content scan therefore has to return its findings in the reply
and leave all logging to the parent.

The filter is emitted by hand rather than through libseccomp, which keeps it
a dependency-free, auditable program of about 40 instructions
(`ps_seccomp_build()`), and which is what lets it be tested exhaustively in
userspace: the tests run it through a small classic-BPF interpreter for every
syscall number on several architecture values. It is tighter than a plain
name list in three ways:

- the architecture must be x86-64 and the x32 bit clear; anything else is
  killed (x86-64 only for now, see #105)
- `sendmsg` and `recvmsg` are allowed only on exactly the IPC descriptor,
  comparing all 64 bits of the argument, so a compromised worker cannot use
  them on any other descriptor
- `newfstatat` is allowed only with `AT_EMPTY_PATH`. That makes the intended
  use (describing an open descriptor) possible, but it does **not** stop path
  probing: a seccomp filter cannot inspect the path argument, and Linux still
  resolves a non-empty path under that flag (relative to the directory
  descriptor, or to the working directory for `AT_FDCWD`). A compromised
  worker can therefore read file metadata (existence, type, size, owner, mode)
  of any path its uid can reach. Closing that needs a mount-level restriction,
  which is what the optional `chroot` to an empty directory below is for; it
  is not implemented, so this is a known residual exposure of metadata, not of
  file contents

The default action is `SECCOMP_RET_KILL_PROCESS`.

#### Seccomp filters stack

A seccomp filter is inherited across `fork()`. A child may add filters but can
never loosen one it inherited; every attached filter is evaluated and the
strictest result wins. Three consequences:

1. The spawner's own filter (implemented, `privsep_lockdown.h`; the test suite
   checks the superset property over every syscall number) must allow everything
   a worker needs, so it is a superset of the worker allowlist plus what only
   the spawner needs
   (`clone`/`fork`, `wait4`, `kill`, `socketpair`, `sendmsg`/`recvmsg`,
   `poll`, the credential, capability and rlimit calls, `prctl`). A narrow
   spawner filter would kill the workers it creates. The tight worker-only filter above is installed last, inside the
   worker, after hardening.
2. A `SystemCallFilter=` in `packaging/avd.service` applies to the whole unit,
   spawner and workers included, so it must be a superset of both as well.
   The spawner also calls `signalfd4` before it locks itself down, so that
   filter has to allow it too, though the spawner's own filter does not.
3. The main process installs its own Stage 2 filter only after it has forked
   the spawner. Installed earlier, the spawner would inherit it.

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

#### Residual risk: the spawner can signal any process

The spawner keeps `CAP_KILL` so that it can `SIGKILL` a worker that runs as
another uid. The seccomp filter pins the signal to `SIGKILL` but not the
target, so a compromised spawner could `kill(-1, SIGKILL)` or signal avd
itself. The filter cannot close this: it cannot know which pids are workers,
and pinning avd's pid would not help either, because `kill()` on any of avd's
thread ids signals the whole process (checked here, and the thread ids are not
fixed). The result is a loss of protection, not code execution as root: avd
dies, the kernel module's own fail-open or fail-closed policy applies until
systemd restarts it, and an attacker who can do this can also kill other
services.

How likely it is: the spawner never reads a scanned file. Its only inputs are
fixed 40-byte control messages from avd and, until a worker reports ready, that
worker's readiness message, all validated; once a worker is ready its socket
belongs to avd and the worker can no longer reach the spawner. Compromising it
takes a bug in that validation, which sees no file content.

Real fixes are boundary changes, so this is an open question below and not
part of Stage 1f: run the spawner and its workers in their own PID namespace
(`CLONE_NEWPID` when avd forks the spawner, which needs `CAP_SYS_ADMIN` at that
moment; the pid avd's `/proc` check reads from `READY` would then need
translating), or remove the spawner's need for `CAP_KILL`. The next subsection
has a way of doing the second that also closes its own problem.

#### Residual risk: a compromised spawner can outlive avd

The parent-death signal is what ends the spawner when avd dies. The kernel
clears it whenever the process's effective or filesystem uid or gid changes,
and the spawner keeps `CAP_SETUID` and `CAP_SETGID` and has to allow
`setresuid`, `setresgid`, `setuid`, `setgid` and `setgroups` in its filter,
because every worker it forks runs its own credential change and its
`setuid(0)` probe under that inherited filter before its tight filter exists.
So the `PR_SET_PDEATHSIG` rule in the filter only closes the direct route
(`prctl(PR_SET_PDEATHSIG, 0)`); a compromised spawner can still call
`setresgid()` and the signal is gone.

Measured, as root, with the real lockdown (`ps_spawner_lockdown()`) and the
real filter, the spawner reading `PR_GET_PDEATHSIG` before and after: with no
credential change it reads 9 (`SIGKILL`) throughout and is killed when its
parent is killed; after `setresgid(65534, 65534, 65534)` or
`setresuid(65534, 65534, 65534)` it reads 0 and keeps running after its parent
is killed. The filter cannot prevent it: the values the workers need (the
dedicated uid and gid) are the ones that change the effective id, so pinning
the arguments does not help, and a filter cannot tell the spawner from the
workers it forks. `tests/test_privsep_lockdown.sh` records this as a known gap.

What bounds it today. A surviving spawner is not a root process with free
rein: it is cut to four capabilities and cannot open files, execute programs
or create sockets. When avd runs under the packaged unit, which sets no
`KillMode=` and so gets systemd's default `control-group`, systemd kills every
process left in the unit's cgroup when it stops the unit, before
`Restart=on-failure` starts it again. That is systemd's documented behaviour
and has not been exercised here. A manual launch has no such backstop.

A way to close this and the `CAP_KILL` risk together, not built or tested:
run the spawner as the workers' uid. avd (root) forks the spawner, and the
spawner's first act is what a worker's hardening does today (empty the
bounding set, drop to the dedicated uid and gid, clear the capabilities,
`NO_NEW_PRIVS`, parent-death signal, filter), so its workers inherit all of it
and need only their rlimits and their tight filter. With no capabilities the
spawner needs no `CAP_KILL` (a process may signal another whose real or saved
uid is its own effective uid, which the workers share), no `CAP_SETUID` or
`CAP_SETGID` (so the filter can drop the whole credential family and the
effective ids can no longer change) and no `CAP_SETPCAP` (the bounding set is
already empty and inherited). The spawner would stop being a root process at
all. The cost: the uid separation between the spawner and its workers goes (a
worker that escaped its filter through a kernel bug would be the spawner's
uid, though the spawner would hold nothing worth taking), and worker hardening
and its tests (Stages 1b and 1c) are reworked, so it is a design change to
review and not a fix to this slice.
### Stage 2: shrink the parent

After init the parent still needs real power, so this stage is smaller than
the issue suggests. Three steps, one PR each:

1. A way to run avd end to end with privilege separation on (built, see "End-to-end
   test with privilege separation on").
2. The capability drop, below (built, with `AVD_PRIVSEP=1` only).
3. The parent's seccomp filter, log-only first to collect the real syscall
   list, then enforcing (not built).

#### Step 2 as built: `privsep_parent.h`

With `AVD_PRIVSEP=1`, inside `privsep_start()`, after the spawner is forked (it
has inherited its capabilities by then) and before the client's reader thread
is created, the main process calls `ps_parent_lockdown()`. The order matters
because capabilities, the bounding set and `NO_NEW_PRIVS` are per thread, not
per process: a thread that exists before the call keeps full root for its whole
life, and every thread created afterwards (the reader, the scan threads, the
fanotify listener, the control threads) inherits the reduced set. The tests
check every thread, not just the main one. The steps:

1. bounding set cut to `PS_PARENT_CAPS` and read back (this is the step that
   needs `CAP_SETPCAP`, so nothing may drop that earlier)
2. effective and permitted set to `PS_PARENT_CAPS`, inheritable and ambient
   empty, read back
3. `NO_NEW_PRIVS` set and read back

The first failing step is fatal: avd prints `parent lockdown step N failed`
and exits instead of running as an unreduced root. The process stays uid 0.

`PS_PARENT_CAPS` is `0x20100f`:

| capability | why the main process still needs it |
|---|---|
| `CAP_NET_ADMIN` | both genl ops are `GENL_ADMIN_PERM` (verdicts, daemon policy) |
| `CAP_SYS_ADMIN` | `fanotify_init(FAN_CLASS_CONTENT)` and the filesystem marks; the module's trust-list writes |
| `CAP_DAC_READ_SEARCH` | `linkat(fd, "", ..., AT_EMPTY_PATH)` into quarantine |
| `CAP_DAC_OVERRIDE` | reading a quarantined (mode 0000) file back on restore |
| `CAP_FOWNER` | `chmod`/`fchmod`/`unlink` on a file the daemon does not own |
| `CAP_CHOWN` | `fchown` back to the original owner on restore |

Everything else goes, notably `CAP_SETUID`, `CAP_SETGID`, `CAP_SETPCAP`,
`CAP_KILL`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO` and
`CAP_MKNOD`. Two things that look like they need a capability do not:
`ps_client_stop()` still `SIGKILL`s the spawner, which works because both run
as uid 0 (a signal needs a matching uid or `CAP_KILL`), and the client reads
`/proc/<worker>/status`, which is world-readable.

The audit behind the table is a reading of every `chown`, `chmod`, `unlink`,
`rename`, `linkat`, `bind`, `setsockopt`, `fanotify_*`, `/proc` and `exec`
call in `avd.c`, not a traced run. It is deliberately conservative, and the
design doc's own rule applies: it is a candidate list until a real run
confirms it. Two runs now have, in a virtme-ng guest on 7.3.1: the fanotify
suite with `--privsep` (33 checks) and `tests/test_avd_socket.sh --privsep`,
which quarantines and restores a file owned by `nobody` with mode 0640 and
checks that it comes back with that owner and mode, without the logged
`fchown` failure that a missing `CAP_CHOWN` produces (verified by removing
`CAP_CHOWN` from the set: that run fails). That covers the quarantine and
restore uses of `CAP_FOWNER`, `CAP_DAC_OVERRIDE` and `CAP_CHOWN`, and the
genl, fanotify and `/proc/kernel_av_signatures` uses of the other three.
`avd.c` itself calls none of `execve`, `fork`, `setuid`, `kill`,
`mount`, `ptrace` or `setrlimit` (the spawner's `fork()` and the
`SIGKILL` in `ps_client_stop()` live in the headers; the fork happens before
the drop).

Not done in this step, on purpose:

- **No `packaging/avd.service` change.** `CapabilityBoundingSet=` in the unit
  applies to every avd start, privilege separation on or not, so it is a
  change to the default install and gets its own PR now that the list has
  been confirmed by a run (see above). When it is added it must be the union of the
  two sets, `0x2011ef` (`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_DAC_READ_SEARCH`,
  `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_CHOWN` for the parent, plus
  `CAP_SETUID`, `CAP_SETGID`, `CAP_SETPCAP`, `CAP_KILL` for the spawner): the
  spawner's own lockdown fails if its bounding set lacks any of its four, and
  the parent drops those four itself afterwards.
- **No seccomp filter on the parent** (step 3), so `Seccomp` in the parent's
  `/proc/<pid>/status` is still 0.
- **Without `AVD_PRIVSEP=1` nothing changes**: avd is root with every
  capability, as before.

`tests/test_privsep_parent.sh` (root; SKIP without it) compiles the production
header with ASan+UBSan and checks, in forked children, the state read back from
`/proc`, that capabilities really are per thread (a thread created before the
call keeps them, one created after is reduced), that a root process of the same uid can still be `SIGKILL`ed (what
`ps_client_stop()` does to the spawner), that the kept capabilities still work (`chown`, `chmod` and `open` on
another uid's mode-0000 file, `linkat(AT_EMPTY_PATH)`), that `setuid`, `setgid`
and `PR_CAPBSET_DROP` now fail and a dropped capability cannot be regained,
that a bounding set missing `CAP_CHOWN` fails step 1, and a failure injected at
each step. `tests/test_fanotify_exec.sh --privsep` also reads `CapEff`, `CapPrm`, `CapBnd`,
`CapInh` and `NoNewPrivs` of every thread of the live avd process from
`/proc/<pid>/task/<tid>/status`.

#### Step 3 and the unit: still to do

- The parent's seccomp filter, excluding `execve`, `ptrace`, module loading and
  so on. The allowlist has to come from a traced run (log-only first), not from
  reading the code.
- `NoNewPrivileges=yes`, `CapabilityBoundingSet=` and `SystemCallFilter=` in
  `packaging/avd.service`, without filesystem sandboxing, which the unit
  comment rightly avoids. Those settings apply to the whole unit including
  the spawner, so the unit's bounding set has to be the union above and its
  syscall filter a superset of the spawner's and the worker's (see "Seccomp
  filters stack"). The unit comment is also worth rewording: avd cannot be
  confined to a restricted filesystem view, but it can still be confined in
  capabilities and syscalls.

## Rollout

- Opt-in first: `AVD_PRIVSEP=1`, like `AVD_FANOTIFY` today, then default on
  after one release of soak.
- Latency matters on the fanotify path, which holds every exec. One
  socketpair round trip is expected to be small compared with a YARA scan,
  but it should be measured, not assumed. The same measurement decides the
  worker-recycling question.
- Worker count follows the existing scan pool size.

### As wired into avd (Stage 1e)

- `AVD_PRIVSEP=1` is read once at startup. avd then looks up the user
  `hyprav-scan` (declared in `packaging/hyprav.sysusers` and its Debian twin)
  and **refuses to start** if the user is missing or is root, or if the
  spawner cannot be started. It never falls back to scanning as root.
- The spawner is forked in the window the design names: after
  `load_tlsh_corpus()`, while single-threaded, before `nl_socket_alloc()`.
  stdio is flushed first so no buffered output is duplicated into the spawner
  and every worker.
- avd does not report privilege separation as on until the spawner has
  produced a hardened worker: `privsep_start()` spawns one probe worker, which
  the client verifies from `/proc` like any other, and releases it. The
  spawner is forked before it locks itself down and `ps_spawner_start()`
  returns at once, so without this a spawner that failed its lockdown still
  got a "privilege separation on" line and let startup carry on until the
  channel closed. `tests/test_perform_scan.sh` makes the lockdown fail for real
  (`CAP_SETPCAP` removed from the bounding set) and checks that avd stops and
  never prints that line.
- Each scan thread owns one worker (thread-local handle), spawned on its first
  scan and released when the thread exits. `analyze_fd()` does SHA-256 and the
  signature lookup in the parent as before, then calls `analyze_in_worker()`
  instead of `analyze_content()`.
- The worker writes no logs: it has no `write()` under its filter, so its
  `stdout` and `stderr` are pointed at fixed in-memory buffers (`fmemopen`, no
  syscalls) and discarded. The parent prints the `scan` line itself and, for a
  conviction, a `MATCH`, `FUZZY MATCH` or `TLSH MATCH` line built from the
  validated rule name. The reply carries no YARA match count, so the
  YARA line reads `avd: MATCH "<path>" -> score=<n>: "<rules>"`, and the
  "matched but below threshold" line is not reproduced. Relying on assigning
  `stdout`/`stderr` is a glibc property, which is all avd targets.
- Any worker failure (no worker, crash, timeout, malformed reply) returns the
  canonical failure result, logged to stderr with the reason. Losing the
  spawner makes avd exit 1 so systemd restarts it.
- Limits. The reply wait is YARA's 10 s plus 20 s each for the ssdeep and TLSH
  passes (50 s), which have no timeout of their own and read at most 256 MiB.
  Measured on a 2.1 GHz Xeon with the shipped rules and corpora, a 255 MiB
  file takes about 5 s end to end (YARA 0.4 s, ssdeep 1.5-2 s, TLSH 2.5-2.7 s),
  so the budget is roughly 8x the worst case. `RLIMIT_CPU` is cumulative, so it
  is derived rather than guessed: 256 scans (the recycle point) times the wait
  plus a second, 13056 s, which a worker cannot reach before it is recycled.
  The recycle count itself is still unmeasured and to be revisited with the
  latency numbers (open question 3). `RLIMIT_NOFILE` is 32; and
  `RLIMIT_AS` is the spawner's virtual size at fork plus 2 GiB, because the
  compiled rules and corpora count against it and libyara maps the scanned
  file whole. A file too large to map comes back inconclusive (fail open)
  instead of being scanned. That is a behaviour difference from the
  in-process path, and a real one: shown with a 256 MiB headroom and a 1 GiB
  file that an override rule convicts, the in-process scan returns MALICIOUS
  and the worker returns CLEAN plus inconclusive. With the shipped 2 GiB
  headroom the window is narrow, since YARA's own 10 s timeout also fails open
  (a 3 GiB file took 19 s to scan here and timed out in both paths), so it
  covers files above the headroom that still scan inside the timeout. It is
  still an evasion of the fail-open kind (pad a sample past the headroom), and
  it is not closed. The obvious fix, `RLIMIT_DATA` instead of `RLIMIT_AS`,
  does let the worker scan that file, but `RLIMIT_DATA` does not count shared
  mappings (checked: a 1 GiB `MAP_SHARED|MAP_ANONYMOUS` succeeds under a
  256 MiB `RLIMIT_DATA` and fails under `RLIMIT_AS`), so a compromised worker
  could then exhaust memory. Open question 6 below.
- `tests/test_perform_scan.sh` runs the whole case table twice, in process and
  in workers, and requires identical verdicts, rule names, scores, quarantine
  contents and metrics. As root it also reads a live worker back from `/proc`
  (dedicated uid and gid, empty `CapEff`, `NoNewPrivs`, `Seccomp: 2`) and
  checks that losing the spawner makes avd exit without scanning. It also
  starts the real avd with `AVD_PRIVSEP=1` in a private mount namespace with a
  bind-mounted copy of `/etc/passwd` (the host's accounts are never touched)
  and asserts exit 1 and the refusal message when `hyprav-scan` is missing,
  has uid 0 or has gid 0, a control where a valid user is accepted, and a
  default-off pair (`AVD_PRIVSEP` unset, and set to `0`, must skip the account
  check and start no workers; only the exact value `1` enables it). These avd runs use an empty rules directory, so even with the
  kernel module loaded nothing they see can be convicted or quarantined. A
  case whose namespace does not show the intended entry is skipped, not
  passed, and the whole group is skipped where mount namespaces are not
  available. Without root the worker half prints SKIP.

## Tests

`tests/test_privsep_spawner.sh` covers the spawner and its channel: the
message validation matrix and descriptor handling; spawn, round trip over the
passed socket, `KILL`, `EXITED`; every failure reason; concurrent spawns
answered out of order; reaping with no zombies and a stable descriptor set
after churn; the spawner holding only its channel, the signalfd and stderr;
orderly shutdown and parent death; the table limits; and, as root, real
workers with real hardening read back from `/proc/<pid>/status`, a failure
injected at each step, and the worker dying with the spawner. In the list
below that covers the failure-injection, concurrent-`SPAWN`, zombie, spawner
descriptor, `EXITED` status, spawner/avd death and rejected-`SCM_RIGHTS`
items for the spawner side. The parent-side items (late replies, respawn
under concurrent scans, the `/proc` check, `AVD_PRIVSEP=1`) arrive with the
dispatch slice.

`tests/test_privsep_lockdown.sh` covers the spawner's lockdown. Under
ASan+UBSan it runs the seccomp program through a classic-BPF interpreter
against an independent statement of what the spawner may do: every syscall
number, every argument-checked call, the architecture and x32 checks, the
superset property against the worker filter, and the assembler's failure modes.
Against the real kernel it installs the same filter in forked children (no root
needed) to show that what the spawner uses works, including a real glibc
`fork()`, and that what it must never do kills it with `SIGSYS`. As root it
reads a real spawner back from `/proc` (four capabilities in every set,
`NoNewPrivs`, `Seccomp: 2`) and the worker it made (still fully hardened under
both filters), injects a failure at each lockdown step, shows that a missing
`CAP_SETPCAP` or a wrong parent pid is refused before anything serves, and
kills avd to show the locked-down spawner dies with it. The suite also runs
cleanly inside a bounding set already cut to the four capabilities (the
packaged unit's future `CapabilityBoundingSet=`), where the first refusal
moves from the bounding-set step to the capabilities step. `tests/test_perform_scan.sh`
reads the spawner back from inside the real avd and checks that a spawner that
cannot lock itself down stops avd at startup.

- hardening failure injection: make each step (setuid, capset, seccomp, ...)
  fail in a test build; the worker must exit without reporting ready and the
  parent must never send it a request
- the parent's `/proc/<pid>/status` check rejects a worker that skipped a
  step, and never sees a worker that is still mid-hardening (`READY` is only
  sent after the worker's report)
- concurrent `SPAWN`s from several scan threads, with slow and failing
  workers mixed in, each get exactly their own `READY` or `FAILED`; a worker
  that never reports is killed and reaped at the startup timeout
- a burst of simultaneous worker exits (coalesced `SIGCHLD`) leaves no
  zombie and produces one `EXITED` per worker
- worker killed mid-scan: the scan is the canonical failure result and a new
  worker appears; repeat under concurrent scans with workers being killed, to
  exercise respawn from the multithreaded parent
- worker sends truncated, oversized, non-NUL-terminated or wrong-request-id
  replies; the parent stays correct and does not reuse that socket
- a late reply after a timeout is never matched to a later scan
- the spawner inherits no descriptor other than its channel end and stderr
  (check `/proc/<spawner>/fd`)
- kill workers repeatedly (a thousand times, under concurrent scans): no
  zombie children remain under the spawner and the process count is stable
- each `EXITED` message carries the real wait status, and the exit code or
  killing signal is logged
- killing the spawner takes its workers down, and killing avd takes the
  spawner down (`PR_SET_PDEATHSIG`)
- parent death before and during the startup window of both the worker and
  the spawner: a test hook pauses the child between hardening steps, the
  parent is killed at each point, and the child must exit (the `getppid()`
  handshake, and `PR_GET_PDEATHSIG` failing closed if the call is moved
  before the credential change)
- a delayed `EXITED` for a replaced worker is ignored: it must not be
  applied to the replacement
- the main process never calls `kill()` on a worker pid
- a real scan succeeds in a worker under the spawner's filter and the unit's
  `SystemCallFilter=`, not only under the worker filter on its own
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
- `tests/test_perform_scan.sh` passes with `AVD_PRIVSEP=1`, and so do
  `tests/run_fanotify_vng.sh --privsep` and `tests/test_avd_socket.sh
  --privsep` (both run by hand in a virtme-ng guest). The QEMU boot job is
  not part of this:
  it loads only `av.ko` from a static init and never starts avd

## Open questions

1. User and group name for the worker, and whether it should be shared with
   anything existing.
2. Memory cost of N workers each holding the compiled rules. Fork
   copy-on-write should share most pages, but YARA's refcounting may dirty
   some; measure.
3. Worker lifetime: long-lived, recycled after K scans, or one per scan (see
   the residual-risk section). Needs the latency measurement.
4. Spawner death or hang: exit and let systemd restart avd (proposed), or
   degrade to all-inconclusive and keep running; and how many consecutive
   missed replies count as a hang.
5. Whether to kill a worker whose scan has already missed the fanotify
   deadline, instead of letting it finish and only logging the late result as
   today.
6. Files too large for the worker's address-space limit fail open, where the
   in-process scan would convict them (see "As wired into avd"). Options:
   keep `RLIMIT_AS` and accept the gap; move to `RLIMIT_DATA` and bound the
   worker's memory another way (shared mappings are not counted by it), for
   example a cgroup memory limit on the unit or a seccomp rule that rejects
   `MAP_SHARED` on anonymous mappings; or have the parent refuse to send
   files above the limit and treat them by policy (for example a size-only
   verdict, or quarantine-on-doubt).
7. The spawner holds `CAP_KILL`, which the filter cannot limit to its
   workers, and `CAP_SETUID`/`CAP_SETGID`, which let it clear its own
   parent-death signal (see "Residual risk: the spawner can signal any
   process" and "Residual risk: a compromised spawner can outlive avd").
   Options: run the spawner as the workers' uid with no capabilities, which
   closes both (described under the second risk); a separate PID namespace for
   the spawner and its workers, with the `/proc` check reworked for
   namespace-local pids, which closes only the first; or workers that never
   need a signal from a more privileged process (exit on socket EOF,
   `RLIMIT_CPU` as the backstop for a hang), which removes `CAP_KILL` but not
   the case of a worker stuck in a call that does neither.

## Open items

- No CI job runs avd at all, with or without privilege separation: the QEMU
  boot job has no avd, libyara or libnl in its static initramfs, and the
  end-to-end scripts need root, a module build and (for fanotify) a VM. A job
  that does would be the safety net Stage 2 wants; it is a separate piece of
  work.
- Stage 2 step 3 (the parent's seccomp filter, log-only first) and the unit's
  `CapabilityBoundingSet=`; see "Stage 2". Step 2's capability list is
  confirmed by the two `--privsep` runs (see "Step 2 as built").

### End-to-end test with privilege separation on

`tests/test_fanotify_exec.sh --privsep` (or `AV_TEST_PRIVSEP=1`; through the
wrapper, `tests/run_fanotify_vng.sh --privsep`) adds `AVD_PRIVSEP=1` to every
avd start in the suite, so the existing checks (enforcement comes up, EICAR
and YARA matches refused before they run, runtime signatures, the watchdog)
all run with scans done in workers. The watchdog's hold gate sits in the
parent's scan threads, so it still pins them. It also creates the
`hyprav-scan` user in the guest if missing (the guest is throwaway) and, once
scans have run, checks `/proc` independently of avd's own check: the spawner
is uid 0 with a capability bounding set of exactly `CAP_KILL`, `CAP_SETGID`,
`CAP_SETUID` and `CAP_SETPCAP` (`0x1e0`), `NO_NEW_PRIVS` and a seccomp filter,
and every thread of the main process is uid 0 with exactly the six parent
capabilities (`0x20100f`) and `NO_NEW_PRIVS`, and every worker is the `hyprav-scan` uid and
gid with no capabilities, `NO_NEW_PRIVS` and a seccomp filter. The host environment does not reach a
virtme-ng guest, which is why the wrapper passes the flag on the command line.

### Spawner death is logged with its cause

When the control channel closes, avd reaps the spawner
(`ps_client_reap_spawner()`, waiting up to 500 ms because the channel closes a
moment before the process becomes reapable) and logs how it ended after the
usual "privsep spawner lost" line: a lockdown step (`exited with status 16 +
step: lockdown step N failed`), any other exit status, `SIGSYS` (usually the
spawner's own seccomp filter lacking a call its libc issued, but a wait status
cannot tell that from a signal sent by another process, so the log says "its
seccomp filter, or an external signal"), or another signal. A spawner
declared hung is still running, so it is neither waited for nor reaped there;
`ps_client_stop()` kills and reaps it. Once reaped, the client clears its pid so
a later stop never signals a reused one. This is covered by the "Dead spawner
nobody else reaps" and "spawner status text" cases in
`tests/test_privsep_client.sh`, and `tests/test_perform_scan.sh` now requires
the exact cause (`lockdown step 1 failed`) for its failed-lockdown case.

## Out of scope

Fuzzing the netlink and control-socket parsers and the metrics work from
#105; the BPF LSM fast path from #177.
