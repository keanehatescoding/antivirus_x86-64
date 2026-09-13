// SPDX-License-Identifier: GPL-2.0
/* CONTROL for the spike: identical "lsm.s/" (sleepable) request, but on
 * task_kill, which is NOT in sleepable_lsm_hooks. The verifier must
 * REJECT this. If it loads, "lsm.s/" is not actually being enforced and
 * the positive result on bprm_check_security proves nothing. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("lsm.s/task_kill")
int BPF_PROG(ctl_task_kill, struct task_struct *p, struct kernel_siginfo *info,
	     int sig, const struct cred *cred, int ret)
{
	return ret;
}
