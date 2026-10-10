# Security Policy

This is a kernel module (`av.ko`) paired with a root-privileged userspace
daemon (`avd`), a polkit-gated CLI (`avctl`), and a GTK4 GUI (`av-gui`). Bugs
here can mean kernel panics, privilege escalation, or a root daemon acting on
the wrong file — please report privately rather than opening a public issue
or PR.

## Supported versions

Tags exist for past milestones (`v0.1.0` through `v0.9.0`), but `master`
is currently well over a hundred commits ahead of the latest one. Only
current `master` HEAD is supported.

| Version                    | Supported |
| ---------------------------- | :-------: |
| `master` (HEAD)               | ✅ |
| `v0.9.0` and earlier tags     | ❌ |

When you report something, include the commit SHA you tested against
(`git rev-parse HEAD`).

## Scope

**In scope:**

- `av/` — the kernel module: kprobe hooks on execve/openat/unlink/rename and
  friends, signature matching, behavioral heuristics, and the netlink
  channel to `avd`
- `userspace/avd/` — the root-privileged scanning/quarantine daemon and its
  Unix control socket (`/run/avd/control.sock`)
- `userspace/avctl/` — the CLI and its polkit policy (`org.hyprav.avctl.policy`,
  the per-verb `org.hyprav.avctl.*` actions)
- `userspace/av-gui/` — the GTK4 console and its `pkexec` bridge to `avctl`
- Packaging under `debian/` and `packaging/` — the DKMS `postinst`/`prerm`
  scripts run as root, so a bad one is a real finding, not just a build issue

**Out of scope:**

- Bugs in YARA, libfuzzy (ssdeep, opt-in builds only), or the vendored TLSH code itself —
  report those upstream, unless the issue is specifically in how this
  project calls them
- "You didn't catch my sample" — detection/evasion gaps in the rules
  themselves are tracked in `docs/evasion-findings.md`, not security bugs

## What counts as a security issue

For a kernel-level tool the bar is wider than for typical userspace
software. All of the following are in scope:

- Kernel panics, hangs, or memory corruption reachable from an unprivileged
  process — a crafted syscall sequence, a malformed netlink message, or a
  file that triggers a bug during scanning
- Privilege escalation, whether through the kernel module, `avd` running
  as root, or `avctl`/polkit (e.g. a privileged verb running without going
  through the real, *installed*, polkit-gated path)
- Auth bypass on either IPC channel — the netlink `genl` channel (should
  require `CAP_NET_ADMIN` and be pinned to the registered daemon's portid)
  or `avd`'s control socket (authenticated via `SO_PEERCRED`)
- Quarantine bugs — path traversal, symlink races, or anything that makes
  quarantine act on a file other than the one that was actually scanned
- Anything that leaves the system fail-open after an operator has
  explicitly set `avctl policy set fail-closed`

`docs/netlink-protocol.md`'s "Known limitations" section and the README's
"TOCTOU protection" section are the closest thing this project has to a
running threat-model doc, and worth a skim before reporting — daemon
impersonation, forged scan requests, and a module-unload use-after-free
were all real findings there, already patched, not hypotheticals. That's
the caliber of report this section is asking for.

## Already-known, already-accepted tradeoffs

Please don't file a report for these — they're deliberate and documented,
not oversights. A *new* way to defeat one of them is still very welcome:

- **Fail-open by default.** If `avd` is unreachable or times out, the
  kernel module lets the exec through rather than blocking it, so a
  crashed daemon can't become a system-wide DoS. `avctl policy set
  fail-closed` opts out of this. See `docs/netlink-protocol.md`.
- **Kill-after-exec, not exec-time blocking** (kernel side). Exec is
  intercepted by a kprobe on `security_bprm_check`, which pins the
  kernel's own `bprm->file` and hashes that exact file on a workqueue —
  so there is no pathname copy to fail (#87's cold-pathname bypass) and
  no path re-open that could hash a different inode (half of #88). But a
  kprobe can't veto the exec, and the verdict is asynchronous, so a
  malicious binary still runs briefly before it's killed. Exec-time prevention via
  fanotify `FAN_OPEN_EXEC_PERM` in `avd` is tracked in #176, under #102.
  Writeup in the comment above `av_work_fn()` in `av/main.c`.
- **x86_64 only.** The behavioral hooks probe `__x64_sys_*` by symbol
  name, so the module will not build or load on arm64.

## Reporting

Preferred: GitHub's private vulnerability reporting on this repo
(Security tab → **Report a vulnerability**). If that isn't turned on,
email **159132270+keanehatescoding@users.noreply.github.com**.

Please include:

- The commit SHA you tested against
- Kernel version and distro (`uname -r`), and whether you installed via
  `insmod` directly or one of the DKMS packages
- Repro steps or a PoC, and what you expected vs. what actually happened
- Whether this was in a VM or on bare metal — this project is developed
  and tested exclusively in VMs, snapshotted before every run. If you hit
  a kernel panic on bare metal, say so up front.

## What to expect

This is a solo, final-year-project maintainer, not a security team, so
please don't expect a corporate SLA. I'll aim to acknowledge reports within
about a week and keep you posted while I work through it. There's no bug
bounty. I'd ask for reasonable time to land a fix before any public
disclosure — happy to agree a specific timeline once I understand the
report.

## Good-faith testing

If you're testing kernel-panic or privilege-escalation scenarios, please
do it in a VM you control — the same way this project's own test suite
does — not against a shared or production machine.
