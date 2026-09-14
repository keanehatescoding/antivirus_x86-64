# Spike: fanotify `FAN_OPEN_EXEC_PERM` exec enforcement (#102)

**This is a spike, not a component.** It is not built by the normal `make`
path, not installed, not loaded at runtime, and not covered by the test
suite. It exists to answer design questions on
[#102](../../../../issues/102) with running code instead of assertions,
and it should either grow into a real implementation or be deleted.

Companion to [`spike/bpf-lsm/`](../bpf-lsm/), which settled the other half
of the question.

## What it answers

`spike/bpf-lsm/` established that a BPF LSM program can deny an exec, and
also that it **cannot park waiting for a YARA verdict from `avd`**. #102
then proposes fanotify permission events as the primitive that can — the
enforcement path, with BPF LSM demoted to an optional cached fast path.

That proposal was written from documentation. Nothing had run. Three
claims had to hold for it to carry enforcement:

1. The exec is really **held** — not merely observed — until userspace
   replies, so `avd` may take as long as YARA needs.
2. A denial actually **refuses** the exec.
3. The fd delivered with the event **is the image about to run**, so
   scanning it is not racing a re-open of the path (#88).

All three hold. A fourth claim #102 made does not — see
**Correction** below.

## Result

```
== PHASE 1: marked target, FAN_ALLOW (expect: RUNS) ==
RESULT: PASS -> allowed exec runs, and one permission event was delivered
        events=1 exec_errno=0 marker=A exited_ok=1

== PHASE 2: stall 300 ms before FAN_ALLOW (expect: exec HELD) ==
RESULT: PASS -> exec did not start until the listener responded
        target started 301.7 ms after fork, 1.0 ms after the response

== PHASE 2 CONTROL: same stall, FAN_CLASS_NOTIF (expect: NOT held) ==
RESULT: PASS -> notification-class exec ran immediately, so phase 2 measured real blocking
        target started 1.5 ms after fork, 299.1 ms BEFORE the response point

== PHASE 3: FAN_DENY (expect: exec REFUSED with EPERM) ==
RESULT: PASS -> denied exec is refused, and the image never runs
        execl failed with Operation not permitted (1), target never started

== PHASE 4: unmarked sibling while the mark is live (expect: RUNS, no event) ==
RESULT: PASS -> unmarked exec unaffected
        events=0 marker=U - denial and delay are keyed on the mark

== PHASE 5: swap the path mid-event (expect: fd and exec both see the ORIGINAL) ==
RESULT: PASS -> scanning the event fd cannot be raced by replacing the path
        held fd = original (18296 B), path now = decoy (18296 B), exec ran marker=A
```

### Phase 2's control carries the weight

"The listener slept 300 ms and the exec took 300 ms" is true whether or
not the kernel waits for anyone — the listener's own sleep accounts for
it either way. So phase 2 is re-run against a `FAN_CLASS_NOTIF` listener,
where the kernel does **not** wait, with the identical stall. The target
starts 1.5 ms after fork there, 299 ms *before* the point a permission
listener would have replied. That gap is the measurement; without it,
phase 2 measures its own `sleep()`.

Getting this right took two attempts, and the first one is worth
recording because it would have read as a pass. The start time was
originally taken when the *listener* read the target's report — but the
listener is asleep for 300 ms by construction, so it noticed the
notification-class target late and credited the kernel with a delay that
was entirely its own. `target.c` now stamps `CLOCK_MONOTONIC` itself, in
the target, before anything else. The listener's clock never enters the
measurement.

### Phase 5 is the #88 claim, performed rather than argued

While the exec is held, the listener renames a *different* binary over
the target's path — the TOCTOU race in #88, run deliberately at the worst
possible moment — and then asks three questions:

| question | answer required |
|---|---|
| what does the **held fd** contain? | the original image |
| what does the **path** contain now? | the decoy — or the swap silently didn't happen and the first answer is worthless |
| which image actually **ran**? | the original, identified by its marker byte |

All three hold. Scanning the event fd cannot be raced by replacing the
path, because the fd is not a path.

### Every assertion was verified in its failing direction

A check that cannot fail proves nothing. One mutant per phase, each
breaking exactly the thing that phase claims to detect; every one must
turn that phase red:

| mutant | change | phase must fail |
|---|---|---|
| p1 | deny the baseline exec | 1 |
| p2 | remove the stall | 2 |
| p2c | point the control at a permission mark | 2 CONTROL |
| p3 | answer `FAN_ALLOW` where the phase denies | 3 |
| p4 | also mark the "unmarked" sibling | 4 |
| p5 | skip the path swap | 5 |

```
ok p1  ok p2  ok p2c  ok p3  ok p4  ok p5
ALL ASSERTIONS CAN FAIL
```

## Correction to #102: the denial errno is not selectable here

#102 lists `FAN_DENY_ERRNO(err)` among the mechanism's properties, as
though the errno a blocked exec sees is ours to choose. On this kernel it
is not, for `FAN_OPEN_EXEC_PERM`:

```
== OBSERVATION 3b: is the denial errno selectable? ==
  FAN_CLASS_CONTENT:     response REJECTED; exec refused with Operation not permitted
                         write(response) -> Invalid argument
  FAN_CLASS_PRE_CONTENT: response REJECTED; exec refused with Operation not permitted
                         write(response) -> Invalid argument
```

`write()` of the errno-carrying response returns `EINVAL` on **both**
permission classes, including `FAN_CLASS_PRE_CONTENT`, which is the class
the restriction is usually attributed to. Both classes were tried
precisely so the answer is attributed to the class rather than to the
kernel version. A denied exec gets `EPERM`.

This is recorded as an **observation, not an assertion** — the spike does
not fail over it, because a design can live with `EPERM`. What phase 3b
*does* assert is that both probes still refused the exec, so the
fallback-to-plain-`FAN_DENY` cannot have quietly turned a denial into an
allow. No kernel `.c` is installed on this machine
(`/usr/lib/modules/$(uname -r)/build` has only `Kconfig`), so this is an
empirical result, not one traced to the check that produces it. Anything
in the design that wants to distinguish "blocked by AV" from an ordinary
permission failure needs another channel.

## What this does NOT prove

The scope here is one listener, one marked inode, and a "verdict" that is
just a `sleep()`. Left untested, and each one is a real design question:

- **Mount-wide marking.** Every mark here is `FAN_MARK_ADD` on an
  individual inode. A real deployment wants `FAN_MARK_MOUNT`, which is a
  different risk class entirely — it puts the listener in the path of
  *every* exec on the mount.
- **`avd`'s own re-entrancy.** A permission-event listener whose own
  file access generates events it must answer deadlocks. Inode marks on
  throwaway files cannot reproduce that; mount marks can, trivially.
  This is the single largest unknown before any migration.
- **Throughput.** One round-trip per exec, with YARA at the far end. No
  numbers here.
- **What generates events.** `FAN_OPEN_EXEC_PERM` covers `execve()` and
  `open_exec()`, so a script exec should also raise an event for its
  interpreter — untested, because confirming it means marking `/bin/sh`
  with a permission mark on a live machine, which would put every shell
  exec on the system behind this listener. Needs a VM. It matters: it
  decides whether one `execve` costs one round-trip or several.
- **Library `mmap`.** Not covered by this event at all; `FAN_OPEN_PERM`
  would be needed if that is in scope.
- **Unresponsive-listener policy.** An `avd` that stops answering stalls
  execs. That interacts directly with the existing fail-open/fail-closed
  policy and is a policy decision, not a mechanism one.

## Why this needs no VM, unlike the BPF LSM spike

`spike/bpf-lsm/` runs its enforcement half inside QEMU because a bad
program on `bprm_check_security` denies *every* exec on the system, and
once no exec works you cannot run `bpftool` to detach it.

fanotify has a safety property that hook does not: marks are
per-inode. Everything here is `FAN_MARK_ADD` on individual files inside a
`mktemp -d` directory, never `FAN_MARK_MOUNT`, so the only execs that can
ever block on this listener are of the three binaries it just built.
Crashing is survivable too — closing the fanotify fd releases any pending
permission event as ALLOW, and process exit closes it.

That property is what makes this spike runnable on a live desktop. It is
also exactly the property a mount-wide deployment gives up.

## Running it

```sh
make          # builds the listener and three exec targets
sudo make check   # or: pkexec ./run_spike.sh
```

Needs root: `FAN_CLASS_CONTENT` requires `CAP_SYS_ADMIN`. Needs
`CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` (checked at
`fanotify_init()`, with a pointed error if absent).

`run_spike.sh` does its work in `$(mktemp -d)` and removes it on exit,
including on interrupt. It preflights by running a target by hand,
outside fanotify entirely — if the work directory is `noexec`, every
phase would fail and phase 3's denial would be indistinguishable from a
file that simply cannot run. Set `TMPDIR` to an exec-permitting
directory in that case.
