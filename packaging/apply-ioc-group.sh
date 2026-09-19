#!/usr/bin/env bash
#
# packaging/apply-ioc-group.sh - chgrp the three IOC /proc entries
# (/proc/kernel_av_signatures, _trusted, _protected) to the hyprav
# trusted-reader group and enforce 0640 on them (see #143).
#
# Why userspace, not proc_set_group() in av.ko: the kernel cannot
# resolve group *names*, only numeric gids, so a kernel-side group
# would need a per-machine gid plumbed through a module_param and
# rendered into modprobe.d by every packager. chgrp after load does
# the same thing with no kernel code and no gid bookkeeping - the
# group is referenced by name, which is stable across machines.
#
# Invoked automatically by the /usr/lib/modprobe.d/hyprav.conf
# install hook on packaged installs (Debian/RPM/Arch all ship it -
# see debian/rules, packaging/fedora/hyprav.spec,
# packaging/arch/PKGBUILD) and by scripts/av-reload.sh after insmod
# in the dev flow, which bypasses modprobe. Safe to run by hand too:
#   sudo packaging/apply-ioc-group.sh
#
# Never fails the load: a missing group (dev machine before groupadd,
# minimal container) or a missing entry (module not loaded yet) just
# leaves the entries root:root 0640 - fail-closed for non-root reads,
# never world-readable, since av.ko creates them 0640 itself. The
# chmod also backports the 0640 reads to an already-built older
# module (0644) until it is rebuilt and reloaded.
set -uo pipefail

GROUP="hyprav"
ENTRIES=(kernel_av_signatures kernel_av_trusted kernel_av_protected)

if ! getent group "$GROUP" >/dev/null; then
    echo "apply-ioc-group: group $GROUP does not exist - leaving IOC /proc entries root-owned (0640)" >&2
    exit 0
fi

for entry in "${ENTRIES[@]}"; do
    path="/proc/$entry"
    [ -e "$path" ] || continue
    chgrp "$GROUP" "$path" \
        || echo "apply-ioc-group: chgrp $path failed" >&2
    chmod 0640 "$path" \
        || echo "apply-ioc-group: chmod $path failed" >&2
done

exit 0
