#!/usr/bin/env bash
#
# tests/run_all.sh - builds everything and runs both test scripts.
# Used by .githooks/pre-push, and safe to run manually any time:
#   sudo tests/run_all.sh
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "run_all.sh needs root (insmod/rmmod). Re-run with sudo."
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAIL=0

echo "### building avctl ###"
make -C "$REPO_ROOT/userspace/avctl" || FAIL=1

echo
echo "### test_sha256.sh (known-answer tests for userspace/avd/sha256.c) ###"
# No kernel module/root needed for this one, unlike everything else
# here - it just doesn't hurt to run it under the same sudo invocation.
"$REPO_ROOT/tests/test_sha256.sh" || FAIL=1

echo
echo "### test_tlsh_core.sh (known-answer tests for userspace/avd/tlsh_core.c) ###"
# Same no-root-needed reasoning as test_sha256.sh above.
"$REPO_ROOT/tests/test_tlsh_core.sh" || FAIL=1

echo
echo "### test_corpus_format.sh (load-time corpus validation in userspace/avd/avd.c) ###"
# Same no-root-needed reasoning as test_sha256.sh above - avd loads
# both corpora before resolving the netlink family, so the expected
# genl fail-fast proves the run reached past the loaders.
"$REPO_ROOT/tests/test_corpus_format.sh" || FAIL=1

echo
echo "### test_avd_sigroute.sh (SIGINT/SIGTERM routing to avd main thread) ###"
# Same no-root-needed reasoning as test_sha256.sh above.
"$REPO_ROOT/tests/test_avd_sigroute.sh" || FAIL=1

echo
echo "### test_parser_robustness.sh (adversarial parser coverage for #105) ###"
# Same no-root-needed reasoning as test_sha256.sh above - pure
# userspace harness, no daemon or kernel module involved.
"$REPO_ROOT/tests/test_parser_robustness.sh" || FAIL=1

echo
echo "### test_detection.sh (build av/, load, exercise clean+EICAR, unload) ###"
"$REPO_ROOT/tests/test_detection.sh" || FAIL=1

echo
echo "### test_sigtable.sh (avctl/proc protocol) ###"
# test_detection.sh unloads the module as part of its own cleanup, so
# reload it here for the sigtable protocol tests.
insmod "$REPO_ROOT/av/av.ko" 2>/dev/null || true
# Apply the hyprav trusted-reader group to the fresh IOC entries
# (#143): a bare insmod bypasses the packaged modprobe.d hook, which
# would leave the group assertions in the protocol tests below with
# nothing to assert. Best-effort - no hyprav group on this machine
# just means those assertions skip (the mode checks still run).
"$REPO_ROOT/packaging/apply-ioc-group.sh" || true
"$REPO_ROOT/tests/test_sigtable.sh" || FAIL=1
echo
echo "### test_trust_protect.sh (avctl trust/protect protocol) ###"
# Same reasoning as test_sigtable.sh above - the module is still loaded
# here for the sigtable protocol tests.
"$REPO_ROOT/tests/test_trust_protect.sh" || FAIL=1
rmmod av 2>/dev/null || true

echo
echo "### test_avd_socket.sh (avd control socket / avctl scan+quarantine) ###"
# Builds+loads/unloads the module and starts/stops avd itself - no
# reload dance needed here, unlike test_sigtable.sh above.
"$REPO_ROOT/tests/test_avd_socket.sh" || FAIL=1

echo
echo "### test_netlink.sh (kernel<->avd Generic Netlink channel) ###"
# Builds+loads/unloads the module and starts/stops avd itself, same
# shape as test_avd_socket.sh above.
"$REPO_ROOT/tests/test_netlink.sh" || FAIL=1

echo
if [ "$FAIL" -ne 0 ]; then
    echo "run_all.sh: one or more test suites FAILED"
    exit 1
fi

echo "run_all.sh: all test suites passed"
exit 0
