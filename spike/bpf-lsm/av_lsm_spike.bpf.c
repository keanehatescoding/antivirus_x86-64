// SPDX-License-Identifier: GPL-2.0
/* Spike, NOT production: does an eBPF LSM program on bprm_check_security
 * actually give us what #87 and #88 need? Proves three things by loading:
 *   1. "lsm.s/" verifies      -> hook is sleepable (closes #87)
 *   2. bprm->file is readable -> kernel's own resolved file (closes #88)
 *   3. -EPERM verifies        -> we can actually block, not just observe
 * Never attaches in this form; see the runner. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* vmlinux.h carries no errno definitions. */
#define EPERM 1

char LICENSE[] SEC("license") = "GPL";

struct exec_event {
	__u64 ino;
	__u32 dev;
	__u32 pid;
	__s32 verdict;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} events SEC(".maps");

/* Inode identity. dev is part of the key, not just ino: inode numbers
 * are only unique within a filesystem, so keying on ino alone would let
 * a block on inode N for one device deny an unrelated executable that
 * happens to be inode N on another. */
struct file_id {
	__u64 ino;
	__u32 dev;
	__u32 __pad; /* explicit, so the key has no uninitialised padding */
};

/* Verdict cache keyed by inode identity - the "fast path in BPF" shape.
 * Empty here, so this spike allows everything. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct file_id);
	__type(value, __u8);
} blocked_files SEC(".maps");

SEC("lsm.s/bprm_check_security")
int BPF_PROG(av_bprm_check, struct linux_binprm *bprm, int ret)
{
	struct exec_event *e;
	struct file *f;
	struct file_id key = {};
	__u64 ino;
	__u32 dev;
	__u8 *blocked;

	/* Never override an earlier LSM's denial. */
	if (ret != 0)
		return ret;

	/* THE #88 FIX: this is the kernel's own already-resolved struct file
	 * for the exec it is about to commit to - not a second, later open of
	 * a path string that may now name a different inode. No re-open, so
	 * no window to race. */
	f = BPF_CORE_READ(bprm, file);
	if (!f)
		return 0;

	ino = BPF_CORE_READ(f, f_inode, i_ino);
	dev = BPF_CORE_READ(f, f_inode, i_sb, s_dev);

	/* THE #87 FIX: nothing here touches user memory at all. By
	 * bprm_check_security the pathname has already been copied in by
	 * getname(), so there is no strncpy_from_user() to fail on a cold
	 * page. The bypass is structurally absent, not merely survivable. */

	key.ino = ino;
	key.dev = dev;
	blocked = bpf_map_lookup_elem(&blocked_files, &key);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		e->ino = ino;
		e->dev = dev;
		e->pid = bpf_get_current_pid_tgid() >> 32;
		e->verdict = blocked ? -EPERM : 0;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}

	/* Proves a negative return verifies: bpf_lsm_get_retval_range() gives
	 * non-bool hooks -MAX_ERRNO..0, so this blocks the exec outright. */
	if (blocked)
		return -EPERM;

	return 0;
}
