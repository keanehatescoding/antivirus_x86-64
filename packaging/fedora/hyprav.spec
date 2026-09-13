# Split package, same reasoning as packaging/arch/PKGBUILD and
# debian/control: av.ko is version-pinned to whatever kernel it's
# built against, so it ships as DKMS source (hyprav-dkms) and is
# rebuilt automatically against every installed kernel, instead of
# being compiled here at rpmbuild time. avd/avctl (hyprav) and the
# GTK4 console (hyprav-gui) are plain userspace and get built normally.
#
# TLSH fuzzy hashing needs no BuildRequires at all: it's vendored,
# pure C (userspace/avd/tlsh_core.c/.h), not linked against a system
# libtlsh. This used to be a real, confirmed-broken blocker here -
# Fedora's own tlsh.spec (checked f41 through f44 and rawhide at
# src.fedoraproject.org/rpms/tlsh) only ever built tlsh-doc and
# python3-tlsh, never a tlsh-devel/libtlsh.so/tlsh.h - so `BuildRequires:
# tlsh-devel` could never have resolved on Fedora. Vendoring the
# algorithm (rather than waiting on a Fedora package that was never
# going to appear) is what actually fixed this.

# Guarded %%if, not a bare %%global: a bare %%global unconditionally
# (re)defines the macro when the spec is parsed, which would silently
# discard a caller's `rpmbuild --define "gitcommit $SHA" ...` (exactly
# how .github/workflows/build-packages.yml pins this to the commit
# actually under test) - confirmed the hard way, a real CI run kept
# building "32d9af8" regardless of --define, because the tarball
# `git archive` produced was named after the real commit while %%prep's
# Source0 lookup used this hardcoded fallback instead. The pattern
# below is the standard "define a fallback only if not already
# defined" idiom - it expands to true (fallback applies) only when
# gitcommit is NOT already defined, false (fallback skipped, the
# --define value stands) when it is. NOTE: a literal %% is required
# throughout this comment, not just in the directives below it -
# confirmed the hard way, a real CI parse failure ("Macro %% has
# illegal name") once an earlier draft of this same comment quoted the
# unescaped macro syntax directly; RPM's spec parser expands %%-macros
# even inside # comments, unescaped %% is never actually inert here.
# An inline single-line form of the guard was also tried first and
# separately rejected by a real rpmspec parse before this %%if/%%endif
# block form replaced it - that form's parse failure was confirmed;
# whether this block form actually fixes the --define precedence
# itself (not just parses) is left for CI to confirm (this job is
# continue-on-error, so a miss here doesn't block builds either way).
%if 0%{!?gitcommit:1}
%global gitcommit 32d9af8
%endif

# Same guarded-%%global idiom as gitcommit above, so a real release
# build (.github/workflows/release.yml, triggered on a v* tag) can pass
# --define "pkgversion $VERSION" and get a Version: that actually
# matches the tag, instead of every release forever reporting this
# fallback string. Kept as a SEPARATE macro from gitcommit rather than
# folding gitcommit into Version's default here, because the two serve
# different callers: gitcommit only affects %prep's Source0 tarball
# lookup (build-packages.yml's PR/push CI job passes only gitcommit,
# never pkgversion, and must keep resolving Source0 to the commit it
# actually checked out); pkgversion only affects the displayed/compared
# package Version. A plain, unguarded rpmbuild (no --define at all,
# e.g. a developer running this spec by hand) still gets exactly
# today's literal string, unchanged.
%if 0%{!?pkgversion:1}
%global pkgversion 0.9.0.129.g%{gitcommit}
%endif

Name:           hyprav
Version:        %{pkgversion}
Release:        1%{?dist}
Summary:        Kernel-level Linux antivirus (kprobe execve/file monitor + YARA/entropy/fuzzy-hash daemon)

# SPDX identifier (current Fedora Licensing Guidelines). Older Fedora
# releases (pre F38-ish) used the short name "GPLv3" instead - adjust
# if targeting one of those.
License:        GPL-3.0-only
URL:            https://github.com/keanehatescoding/antivirus
Source0:        %{url}/archive/%{gitcommit}/antivirus-%{gitcommit}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  pkgconfig
BuildRequires:  pkgconfig(libnl-genl-3.0)
BuildRequires:  yara-devel
BuildRequires:  ssdeep-devel
BuildRequires:  systemd-rpm-macros
# userspace/av-gui/Makefile's `install` target (invoked in %install
# below) depends on `checkdeps`, which imports gi and loads GTK4
# before staging any files - needed at build time, not just via
# hyprav-gui's own runtime Requires further down.
BuildRequires:  python3-gobject
BuildRequires:  gtk4

# avctl is invoked as `pkexec avctl ...` by hyprav-gui (see
# pkexec_helper.py) and this package installs the polkit action
# (org.hyprav.avctl.policy) that authorizes it - pkexec itself isn't
# auto-pulled by RPM's dependency generator (that only covers shared
# libraries, not exec'd binaries), so it needs an explicit Requires.
Requires:       /usr/bin/pkexec

%description
HyprAV is a kprobe-based kernel module (av.ko) that hooks execve and
file events, does fast hash/counter checks in-kernel, and defers
anything heavier - YARA matching, ELF structural analysis, entropy
scoring, ssdeep/TLSH fuzzy hashing - to avd, a privileged userspace
daemon it talks to over netlink. avctl is the CLI (and polkit-gated
privileged entry point) for managing avd's signatures, trust list,
protected paths, policy, on-demand scans, and quarantine.

This base package installs avd and avctl. See hyprav-dkms for the
kernel module and hyprav-gui for the GTK4 management console.

%package -n hyprav-dkms
Summary:        HyprAV kprobe-based execve/file-event kernel module (DKMS)
Requires:       dkms
Requires(post): dkms
Requires(preun): dkms
# NOT noarch, despite shipping only source + a dkms.conf: the module
# hooks x86_64-specific kprobe symbols (see the description below), so
# a noarch build would let this install - and its %post run dkms -
# against unsupported architectures.
ExclusiveArch:  x86_64

%description -n hyprav-dkms
Out-of-tree kernel module (av.ko) that hooks execve and file events
via kprobes and talks to the avd userspace daemon over netlink for
anything heavier. Ships as DKMS source and is rebuilt automatically
against every installed kernel.

x86_64 only as shipped - the module hooks __x64_sys_execve by symbol
name; arm64 needs source changes to hook __arm64_sys_execve instead.

%package -n hyprav-gui
Summary:        GTK4 management console for HyprAV
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}
Requires:       python3
Requires:       python3-gobject
Requires:       gtk4

%description -n hyprav-gui
Dashboard (avd status + counts), detections (recent verdict history),
quarantine (list/restore/delete), an on-demand scan page, and
signatures/trust list/protected paths/policy management, sitting on
top of avd and avctl. A normal desktop app, not a daemon - launch it
on demand. Privileged actions go through pkexec avctl, gated by the
per-verb org.hyprav.avctl.* polkit actions installed by the base package.

%prep
%autosetup -n antivirus-%{gitcommit}

%build
make -C userspace/avd
make -C userspace/avctl

%install
make -C userspace/avd install DESTDIR=%{buildroot} PREFIX=%{_prefix} UNITDIR=%{_unitdir}
make -C userspace/avctl install DESTDIR=%{buildroot} PREFIX=%{_prefix} POLKIT_ACTIONDIR=%{_datadir}/polkit-1/actions
# 0700, not 0755: matches avd.c's own mkdir(quarantine_dir, 0700) -
# it holds quarantined malware. Confirmed on a real Debian 13 box
# (same underlying bug, different distro) that 0755 here just fights
# that at runtime for no reason.
install -dm700 %{buildroot}%{_localstatedir}/lib/av-quarantine

install -dm755 %{buildroot}%{_usrsrc}/hyprav-av-%{version}
cp -r av/* %{buildroot}%{_usrsrc}/hyprav-av-%{version}/
# KDIR override for the same reason as the Arch/Debian packaging:
# dkms may build against a kernel that isn't the one `uname -r`
# currently reports (e.g. mid kernel-upgrade, before reboot).
cat > %{buildroot}%{_usrsrc}/hyprav-av-%{version}/dkms.conf <<EOF
PACKAGE_NAME="hyprav-av"
PACKAGE_VERSION="%{version}"
BUILT_MODULE_NAME[0]="av"
DEST_MODULE_LOCATION[0]="/kernel/drivers/misc"
AUTOINSTALL="yes"
MAKE[0]="make KDIR=\${kernel_source_dir}"
CLEAN="make KDIR=\${kernel_source_dir} clean"
EOF

make -C userspace/av-gui install DESTDIR=%{buildroot} PREFIX=%{_prefix}

%check
# Known-answer suites for the vendored hashing code - pure userspace, no
# root or kernel module needed (see the headers of tests/test_sha256.sh
# and tests/test_tlsh_core.sh), so they are safe to run under rpmbuild.
# Covers #130's request for a minimal spec %check section.
./tests/test_sha256.sh
./tests/test_tlsh_core.sh

%post
%systemd_post avd.service

%preun
%systemd_preun avd.service

%postun
%systemd_postun_with_restart avd.service

%post -n hyprav-dkms
dkms add -m hyprav-av -v %{version} || :
dkms autoinstall -m hyprav-av -v %{version} || :

%preun -n hyprav-dkms
dkms remove -m hyprav-av -v %{version} --all || :

%files
%license LICENSE
%doc README.md
%{_bindir}/avd
%{_bindir}/avctl
%{_unitdir}/avd.service
%{_datadir}/polkit-1/actions/org.hyprav.avctl.policy
%dir %{_sysconfdir}/hyprav
%dir %{_sysconfdir}/hyprav/rules
%config(noreplace) %{_sysconfdir}/hyprav/rules/*.yar
%config(noreplace) %{_sysconfdir}/hyprav/fuzzy_hashes.txt
%config(noreplace) %{_sysconfdir}/hyprav/tlsh_hashes.txt
%attr(0700,root,root) %dir %{_localstatedir}/lib/av-quarantine

%files -n hyprav-dkms
%license LICENSE
%{_usrsrc}/hyprav-av-%{version}/

%files -n hyprav-gui
%license LICENSE
%{_bindir}/av-gui
%{_prefix}/lib/hyprav/av-gui/
%{_datadir}/applications/av-gui.desktop

%changelog
* Tue Aug 25 2026 keanehatescoding <159132270+keanehatescoding@users.noreply.github.com> - 0.9.0.129.g32d9af8-1
- Initial packaging: hyprav-dkms (av.ko kernel module), hyprav
  (avd daemon + avctl CLI), hyprav-gui (GTK4 console).
