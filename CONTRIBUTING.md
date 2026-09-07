# Contributing

Thanks for looking at this. It's a final-year project — a kernel module
plus a root daemon, a polkit-gated CLI, and a GUI — so a couple of things
below are stricter than a typical userspace repo. Read the safety note
before you build anything.

## Before you build anything

**Do this in a VM, and snapshot it first.** A broken kernel module can
hang or crash whatever it's loaded on. The whole project is developed
this way: snapshot → build → `insmod` → test → check `dmesg` → `rmmod`,
restore the snapshot if something goes wrong. Please don't test
kernel-module changes on hardware you can't afford to lose, and don't
test anything — kernel-side or not — against a machine that isn't yours.

Found something security-relevant instead of a regular bug (a crash an
unprivileged process can trigger, a privilege-escalation path, an auth
bypass on the netlink or control-socket channel)? That goes through
[`SECURITY.md`](SECURITY.md), not a public issue or PR.

## Getting set up

```bash
git clone https://github.com/keanehatescoding/antivirus.git
cd antivirus
scripts/setup-hooks.sh    # one-time: wires git to .githooks/
```

Dependencies, by component:

```bash
# av/ — the kernel module
sudo apt install build-essential linux-headers-$(uname -r) git

# userspace/avd
sudo apt install libnl-genl-3-dev libyara-dev libfuzzy-dev
# TLSH is vendored in userspace/avd/tlsh_core.c — no libtlsh needed

# userspace/av-gui
sudo apt install python3 python3-gi gir1.2-gtk-4.0
```

Arch/Fedora equivalents live in `packaging/arch/PKGBUILD` and
`packaging/fedora/hyprav.spec` if you're not on a Debian-based distro.

This file only covers the mechanics of contributing — for how the pieces
actually work together, the README is the real reference.

## Building and testing

Every component builds the same way:

```bash
make                     # default: GCC
make CC=clang LLVM=1     # av/ only — build against a Clang-built kernel
```

`tests/` scripts mostly need root, since they load/unload the module and
start/stop `avd`:

| Touched                | Run at least                                                         |
| ----------------------- | --------------------------------------------------------------------- |
| `av/`                    | `sudo tests/test_detection.sh`, `sudo tests/test_sigtable.sh`         |
| `userspace/avd/`         | `sudo tests/test_avd_socket.sh`                                       |
| hashing code (either)    | `tests/test_sha256.sh`, `tests/test_tlsh_core.sh` — no root needed    |
| broader / not sure       | `sudo tests/run_all.sh` — builds everything, runs the full set        |

CI re-runs a version of this on every push across three tiers: compile
across gcc/clang against the kernel versions pinned in
`.github/kernel-versions.json` (`build-matrix.yml`), a real QEMU boot
that loads the module and checks clean-vs-EICAR detection
(`qemu-boot-test.yml`), and a packaging build for `.deb`/`.pkg.tar.zst`/
`.rpm` (`build-packages.yml`).

## What runs automatically

- **On commit** — `.githooks/pre-commit` lints staged files only:
  `cppcheck` on `av/*.c`, `gcc -fsyntax-only -Wall -Wextra` on
  `avctl`/`avd` changes, a `yara` compile check on rule changes,
  `shellcheck` on scripts. Quick, no build, no `insmod`.
- **On push** — `.githooks/pre-push` runs the full suite
  (`pkexec tests/run_all.sh`), but only when the push touches `av/`,
  `userspace/avctl/`, `userspace/avd/`, `userspace/av-gui/`, `rules/`,
  `corpus/`, or `packaging/`. Docs-only pushes skip it.

Both accept `--no-verify` if you really need to skip them, but that's
best avoided — particularly right before a tag.

## Ground rules for kernel-side code

- **kprobe pre-handlers run in atomic context**: no sleeping, no file
  I/O, no `GFP_KERNEL`. Grab what you need with `GFP_ATOMIC` and hand the
  rest to the workqueue (`av_work_fn()`), same as the existing hooks.
  This one's non-negotiable, not stylistic — an early version hashed
  inline in the kprobe handler and left the kernel in a bad state after
  every `execve` (see the `v0.1.0` note at the top of `av/main.c`).
- The netlink `genl_family` layout and the hooked syscall symbol names
  are both kernel-version-sensitive. That's exactly what the
  `build-matrix.yml` matrix exists to catch — "works on my kernel" isn't
  enough on its own.
- x86_64 only, for now — the module resolves `__x64_sys_execve` by
  symbol name. Porting to arm64 means finding the equivalent
  `__arm64_sys_*` symbols throughout, not just a `Makefile` tweak.

## Adding or changing YARA rules

Rules in `rules/` are held to a specific bar: a real sample that actually
triggers the condition (not just something that looks like it should),
plus negative controls against ordinary system binaries
(`/bin/ls`, `/bin/bash`, etc.) to rule out false positives. See the
`confidence` field and comments in `rules/elf_analysis.yar` for what that
looks like in practice. New rules should come with the same: how you got
the triggering sample, what you tested it against, and what the
false-positive pass looked like.

A rule that only catches one specific variant isn't a blocker — just say
so. `docs/evasion-findings.md` is where known, accepted detection gaps
already live.

## Branches and commits

Branches are generally `type/short-description` —
`feat/…`, `fix/…`, `ci/…`, `docs/…`, `test/…`, `packaging/…` show up in
the existing history, loosely rather than strictly enforced.

Commits mostly follow `type: description` or `type(scope): description`
(`fix:`, `ci:`, `avctl:`, `debian:`, `tests:` …) — keep the summary short
and put the "why" in the body if it needs one.

## Opening a PR

PRs target `master` directly — there's no separate release branch. Two
automated reviewers run on every PR: CodeRabbit and a Claude-based
reviewer (`.github/workflows/claude-code-review.yml`), both leaving
inline comments, plus a human pass from me. You can also drop `@claude`
in a PR or issue comment for on-demand help — see
`.github/workflows/claude.yml` for exactly what it responds to.

## License

GPL-3.0, same as the rest of the repo (`LICENSE`). Opening a PR here
means you're contributing under that same license — no separate CLA.
