#!/bin/sh
# LOADS ONLY - never attaches. A loaded-but-unattached BPF LSM program
# gates nothing; no exec on this machine is affected. Both programs are
# freed the moment this script exits (nothing is pinned).
set -u
D=$(dirname "$0")
echo "kernel: $(uname -r)"
echo

echo "== TEST: lsm.s/bprm_check_security (expect: LOADS) =="
if out=$(bpftool prog load "$D/av_lsm_spike.bpf.o" /sys/fs/bpf/av_spike 2>&1); then
	echo "RESULT: LOADED -> hook IS sleepable, and -EPERM verified"
	rm -f /sys/fs/bpf/av_spike
	A=pass
else
	echo "RESULT: REJECTED"
	echo "$out" | tail -12
	A=fail
fi
echo

echo "== CONTROL: lsm.s/task_kill, not sleepable (expect: REJECTED) =="
if out=$(bpftool prog load "$D/control_nonsleepable.bpf.o" /sys/fs/bpf/av_ctl 2>&1); then
	echo "RESULT: LOADED -> UNEXPECTED; lsm.s not enforced, test above is void"
	rm -f /sys/fs/bpf/av_ctl
	B=fail
else
	echo "RESULT: REJECTED as expected"
	echo "$out" | grep -i "sleepable\|not sleep" | head -3
	B=pass
fi
echo
echo "=================================================="
[ "$A" = pass ] && [ "$B" = pass ] \
	&& echo "VERDICT: confirmed - eBPF LSM route is viable for #87 + #88" \
	|| echo "VERDICT: inconclusive (A=$A B=$B)"
