# Spike: eBPF LSM exec interception (#102)

**This is a spike, not a component.** It is not built by the normal `make`
path, not installed, not loaded at runtime, and not covered by the test
suite. It exists to answer design questions on
[#102](../../../../issues/102) with running code instead of assertions,
and it should either grow into a real implementation or be deleted.

## What it answers

#87 (deterministic cold-pathname fail-open) and #88 (TOCTOU on the
re-opened exec target) share one root cause: exec is intercepted with a
kprobe on `__x64_sys_execve`, which runs in atomic context and fires
before the kernel commits to the image. The proposed fix is an LSM hook.
Before designing around that, three things needed confirming:

1. Is `bprm_check_security` actually **sleepable** under BPF LSM? If not,
   the route closes #88 but leaves #87 open.
2. Is a **denying return value** (`-EPERM`) even legal on this hook, or
   is it clamped so the program could only ever observe?
3. Does it see the kernel's **own resolved file**, rather than a path
   string it has to re-open?

## Result

```
== TEST: lsm.s/bprm_check_security (expect: verifier ACCEPTS) ==
RESULT: ACCEPTED -> hook is sleepable; -EPERM is within the
        verifier's permitted return range

== CONTROL: lsm.s/task_kill, not sleepable (expect: REJECTED) ==
RESULT: REJECTED for the expected reason
bpf_lsm_task_kill is not sleepable
```

The control carries the weight: it requests `lsm.s/` (sleepable) on a hook
absent from `sleepable_lsm_hooks` and is rejected by the verifier's own
message. Without it, a load that "just worked" would not prove `lsm.s`
was enforced at all. The control is matched against that exact diagnostic,
not merely against a non-zero exit, so an unrelated failure (missing
object, no privileges, bad pin path) fails the run instead of silently
passing it.

### What the load-only test does NOT prove

`bpftool prog load` runs the **verifier**. It does not attach anything and
does not exec anything, so on its own it answers question 2 only in the
narrow sense that `bpf_lsm_get_retval_range()` permits a negative return
on this hook, so `-EPERM` survives verification — not that the kernel was
observed refusing an exec.

`run_vm_test.sh` closes that gap; see **Enforcement** below.

Corroborated in the kernel source for both versions CI builds: `v6.12`
and `v6.18` `kernel/bpf/bpf_lsm.c` both list
`BTF_ID(func, bpf_lsm_bprm_check_security)` in `sleepable_lsm_hooks`, and
neither lists it in `bpf_lsm_disabled_hooks`.
`bpf_lsm_get_retval_range()` gives non-bool hooks `-MAX_ERRNO..0`, which
is why returning `-EPERM` verifies.

### #87 is structurally absent here, not merely survivable

The framing on #102 was "sleepable, so it can fault in cold pages." It is
better than that: by `bprm_check_security` the pathname is already in
kernel memory (copied by `getname()`), so there is **no
`strncpy_from_user()` to fail**. Likewise `bprm->file` is the kernel's own
resolved, already-open file, so there is no second open for #88 to race.

## Constraints found

- **`bpf_d_path()` is not callable from this hook.** `btf_allowlist_d_path`
  (`kernel/trace/bpf_trace.c`) covers `security_file_open`,
  `security_file_permission`, `security_inode_getattr`,
  `security_path_truncate` and some vfs functions — not
  `bprm_check_security`. This spike keys on `dev`/`ino` via CO-RE instead.
  Inode identity is the better key for a hash lookup anyway, but the
  existing path-based matching and logging needs rethinking, not porting.
- **No blocking userspace round-trip.** A sleepable program can fault in
  user memory; it cannot park waiting for a YARA verdict from `avd`. That
  is what `FAN_OPEN_EXEC_PERM` (fanotify) is for — see #102. The likely
  shape is fanotify for enforcement, BPF LSM as an optional fast path for
  cached inode verdicts.

## Enforcement

`run_vm_test.sh` attaches the program inside a throwaway QEMU VM and
proves it actually denies an exec:

```
ENFORCE_TEST: program loaded
ENFORCE_TEST: attached to bprm_check_security
ENFORCE_TEST: control exec succeeded (unblocked file runs)
ENFORCE_TEST: blocking dev=0x3 ino=18
ENFORCE_TEST: blocked target denied with EPERM
ENFORCE_TEST: PASS
```

The guest's PID 1 is `enforce_test.c`: it loads the object, attaches an
LSM link, execs an unblocked file, inserts a second file's `{dev, ino}`
into `blocked_files`, and execs that one. The run passes only if the
first exec succeeds and the second fails with `EPERM`.

The control exec is not decoration. A program that broke exec outright
would deny the blocked target too, and without the control that failure
would read as a pass. The assertion has also been checked in the failing
direction: with the map insertion removed, the blocked target runs and
the script reports `FAIL`.

Rather than building a kernel, this boots the **host's own kernel image**.
BPF LSM attach needs vmlinux BTF (`CONFIG_DEBUG_INFO_BTF=y`) plus
`CONFIG_BPF_LSM=y`, and the `tinyconfig` kernel that
`.github/workflows/qemu-boot-test.yml` builds has neither; adding them
means `pahole` and a much heavier build. Nothing from the host filesystem
is mounted — the guest gets only the assembled initramfs. `lsm=` is
passed explicitly on the guest cmdline so the result does not depend on
this machine's boot parameters.

This is **not** wired into CI. Doing so needs a BTF-enabled kernel on the
runner, which is a separate cost decision.

## Running it

```sh
make          # builds both objects (generates vmlinux.h from local BTF)
make check    # load-only verifier test; needs root, attaches nothing
make enforce  # attach-and-deny test in QEMU; no root, needs qemu + cpio
```

`run_spike.sh` **loads and never attaches.** A loaded-but-unattached BPF
LSM program gates nothing, so no exec on the machine is affected, and
both programs are freed on exit since nothing is pinned.

`run_vm_test.sh` attaches, but only ever inside the VM — it never loads
anything on the host, which is why it needs no privileges. Keep it that
way: a buggy program on this hook can deny every exec on the system, and
once no exec works you cannot run `bpftool` to detach it. That is the
whole reason the enforcement half runs in a VM.

`vmlinux.h` is generated from the running kernel's BTF and is
`.gitignore`d — it is machine-specific and ~164k lines.
