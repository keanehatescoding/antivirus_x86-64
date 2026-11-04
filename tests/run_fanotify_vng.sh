#!/usr/bin/env bash
#
# tests/run_fanotify_vng.sh - runs tests/test_fanotify_exec.sh inside a
# throwaway virtme-ng guest booted from the host's running kernel, so
# the fanotify exec-permission marks never touch the host. The guest
# sees the host filesystem through copy-on-write overlays (/home
# included), so the in-guest builds never write to the checkout.
#
# Needs virtme-ng (vng) and /dev/kvm. No root on the host:
#   tests/run_fanotify_vng.sh
#
# With --privsep the same checks run with avd started under AVD_PRIVSEP=1
# (scans in unprivileged workers, #103); the guest gets the hyprav-scan
# user created for it. The flag is passed on the guest command line,
# because the host environment does not reach the guest:
#   tests/run_fanotify_vng.sh --privsep
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v vng >/dev/null 2>&1; then
    echo "SKIP: virtme-ng (vng) not installed"
    exit 0
fi

exec vng --run --user root --cpus 2 -- \
    "$REPO_ROOT/tests/test_fanotify_exec.sh" "$@"
