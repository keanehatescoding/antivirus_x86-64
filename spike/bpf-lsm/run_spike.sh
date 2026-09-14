#!/bin/sh
# LOADS ONLY - never attaches. A loaded-but-unattached BPF LSM program
# gates nothing; no exec on this machine is affected. Both programs are
# freed the moment this script exits (nothing is pinned).
#
# SCOPE OF WHAT THIS PROVES: bpftool prog load runs the verifier. That
# establishes (a) the hook accepts a sleepable "lsm.s/" attachment, and
# (b) a negative return passes bpf_lsm_get_retval_range()'s check for
# this hook. It does NOT establish that an exec is actually denied at
# runtime - nothing is attached and nothing is exec'd here. Proving
# enforcement needs an attach-and-exec test in a throwaway VM (the
# tests/qemu-boot/ harness is the natural place); until that exists,
# do not read these results as "denial works".
set -u

D=$(dirname "$0")
# Honour the same override the Makefile exposes, so `make BPFTOOL=... check`
# tests the tool the caller selected rather than whatever is on $PATH.
BPFTOOL="${BPFTOOL:-bpftool}"
EXPECTED_CTL_MSG="bpf_lsm_task_kill is not sleepable"

echo "kernel: $(uname -r)"
echo

echo "== TEST: lsm.s/bprm_check_security (expect: verifier ACCEPTS) =="
if out=$("$BPFTOOL" prog load "$D/av_lsm_spike.bpf.o" /sys/fs/bpf/av_spike 2>&1); then
	echo "RESULT: ACCEPTED -> hook is sleepable; -EPERM is within the"
	echo "        verifier's permitted return range (enforcement untested)"
	rm -f /sys/fs/bpf/av_spike
	A=pass
else
	echo "RESULT: REJECTED (unexpected)"
	echo "$out" | tail -12
	A=fail
fi
echo

echo "== CONTROL: lsm.s/task_kill, not sleepable (expect: REJECTED) =="
if out=$("$BPFTOOL" prog load "$D/control_nonsleepable.bpf.o" /sys/fs/bpf/av_ctl 2>&1); then
	echo "RESULT: ACCEPTED -> UNEXPECTED; lsm.s not enforced, test above is void"
	rm -f /sys/fs/bpf/av_ctl
	B=fail
else
	# A bare non-zero exit is NOT enough: a missing object, a permission
	# error, or a bad pin path would all "fail" here and silently pass
	# the control. Only the specific verifier diagnostic counts.
	if echo "$out" | grep -qF "$EXPECTED_CTL_MSG"; then
		echo "RESULT: REJECTED for the expected reason"
		echo "$out" | grep -F "$EXPECTED_CTL_MSG" | head -1
		B=pass
	else
		echo "RESULT: failed, but NOT with the expected diagnostic."
		echo "        wanted: $EXPECTED_CTL_MSG"
		echo "$out" | tail -12
		B=fail
	fi
fi
echo

echo "=================================================="
if [ "$A" = pass ] && [ "$B" = pass ]; then
	echo "VERDICT: sleepable attach + permitted -EPERM return confirmed."
	echo "         Runtime enforcement NOT tested by this script."
	exit 0
fi
echo "VERDICT: inconclusive (A=$A B=$B)"
exit 1
