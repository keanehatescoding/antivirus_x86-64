# Kernel-Level Linux Antivirus — Final Year Project

A Linux kernel-level antivirus built incrementally: starting from bare LKM
basics, through kprobe-based syscall hooking, to signature-based detection,
YARA/heuristic/entropy/fuzzy-hash scanning, and behavioral heuristics. `av/`
is the single evolving kernel module — milestones are marked with git tags,
not parallel folders. Four components: the kernel module (`av/`), a root
scanning/quarantine daemon (`avd`), a CLI (`avctl`), and a GTK4 GUI
(`av-gui`).

**📖 Full documentation lives in the [project wiki](../../wiki)** — architecture,
per-component internals, the detection engine, protocol specs, every manual
test walkthrough, evasion-testing findings, and CI/packaging details. This
README only covers what you need to get a build running.

**All development and testing happens inside a VM.** Kernel modules can and
will crash your kernel while you learn — snapshot your VM before every test
run.

```
snapshot the VM
insmod av.ko
test
dmesg | tail -50
rmmod av
# if it panics/hangs: restore snapshot, fix, repeat
```

## Repo layout

```
av/                  the kernel module — see wiki: Kernel Module
rules/               YARA rule tiers — see wiki: Detection Rules
corpus/               fuzzy-hash corpora (ssdeep + TLSH) — see wiki: Detection Rules
userspace/avctl/     CLI — see wiki: avctl CLI
userspace/avd/       scanning/quarantine daemon — see wiki: avd Daemon
userspace/av-gui/    GTK4 management console — see wiki: av gui
docs/                 protocol specs (also mirrored in the wiki)
packaging/            systemd unit, polkit policy, Flatpak/AppImage manifests
debian/, packaging/{arch,fedora}/  distro packages — see wiki: CI and Packaging
tests/                 automated + evasion + QEMU-boot CI tests — see wiki: Testing
scripts/               setup-hooks.sh, av-reload.sh
```

## Prerequisites (inside the VM)

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r) git
```

## Building

```bash
cd av
make
sudo insmod av.ko
dmesg | tail -20
sudo rmmod av
```

Targets x86_64 kernels 5.7+ only (hooks `__x64_sys_execve` by symbol name —
see the wiki's Architecture page for the arm64 note and why it isn't
supported). `make CC=clang LLVM=1` builds against a Clang-built kernel.

## Running the full stack

```bash
# daemon (root, scans/quarantines files)
cd userspace/avd && make && sudo make install
sudo systemctl enable --now avd.service

# CLI (manages signatures/trust/protected-paths/policy, talks to avd)
cd ../avctl && make && sudo make install

# GUI (optional, talks to avd + avctl, never touches the kernel module directly)
cd ../av-gui && make && sudo make install
av-gui
```

### IOC read access: the `hyprav` group

The signatures/trust/protected-path `/proc` entries are `0640
root:hyprav` — group ownership is applied at module load by the
packaged `modprobe.d` hook (or by `scripts/av-reload.sh` in the dev
`insmod` flow, which bypasses modprobe). Your desktop user must be a
member for the GUI dashboard and unprivileged `avctl save` to read
them (writes were already root-only and are unchanged):

```bash
getent group hyprav >/dev/null || sudo groupadd -r hyprav  # packaged installs already do this via sysusers
sudo usermod -aG hyprav "$USER"                            # then log out and back in
```

Without membership those reads fail with "permission denied" (see
[#143](https://github.com/keanehatescoding/antivirus_x86-64/issues/143));
with a manual `insmod` outside `av-reload.sh`, run
`sudo packaging/apply-ioc-group.sh` once after loading.

See the wiki's **Building and Running**, **avd Daemon**, **avctl CLI**, and
**av gui** pages for install-path overrides (`PREFIX`/`SYSCONFDIR`/`UNITDIR`/
`DESTDIR`), the systemd unit's security model, and the Flatpak/AppImage
builds.

## Testing

```bash
tests/run_all.sh
```

Runs the six automated test scripts (two standalone, four needing a VM
and root). See the wiki's **Testing** page for what each one checks and for
manual, step-by-step walkthroughs of every detection layer (signatures,
YARA, ELF analysis, entropy, fuzzy hashing, behavioral heuristics,
quarantine/TOCTOU). The EICAR antivirus test file — a standard, harmless
68-byte string every real AV vendor uses for exactly this purpose — is used
throughout instead of real malware.

## CI

Three tiers on every push: compile-matrix (gcc/clang × 3 kernel versions),
a QEMU boot test with real runtime detection, and a packaging build
(deb/Arch/Fedora). Details in the wiki's **CI and Packaging** page.

## Documentation index

- [Architecture](../../wiki/Architecture) — kernel vs. userspace split, kernel taint checks
- [Kernel Module](../../wiki/Kernel-Module) / [avd Daemon](../../wiki/avd-Daemon) / [avctl CLI](../../wiki/avctl-CLI) / [av-gui](../../wiki/av-gui)
- [Detection Rules](../../wiki/Detection-Rules) — YARA tiers, fuzzy-hash corpora
- [Behavioral Heuristics](../../wiki/Behavioral-Heuristics) — the kernel-side ransomware/self-delete/sensitive-path engine and its real false-positive incidents
- [Evasion Findings](../../wiki/Evasion-Findings) — adversarial testing against the engine itself
- [Netlink Protocol](../../wiki/Netlink-Protocol) / [avd Socket Protocol](../../wiki/avd-Socket-Protocol) — the two IPC channels
- [Testing](../../wiki/Testing) — automated tests and manual walkthroughs
- [CI and Packaging](../../wiki/CI-and-Packaging)

## Security

See [SECURITY.md](SECURITY.md) for scope, already-accepted tradeoffs
(fail-open by default, two documented kernel exec-interception gaps,
x86_64-only), and how to report a vulnerability privately.
