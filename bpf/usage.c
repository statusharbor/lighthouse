// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// usage: what polling /proc cannot see (docs/eBPF/05-per-process-attribution.md):
// CPU of every exiting thread, logical file I/O per process and block
// request latency per device. Reads no file names, paths or contents.
#include "types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct sched_entity {
	__u64 sum_exec_runtime;
} __attribute__((preserve_access_index));

struct task_struct {
	int tgid;
	__u64 start_boottime;
	struct sched_entity se;
	struct task_struct *group_leader;
} __attribute__((preserve_access_index));

struct super_block {
	unsigned long s_magic;
} __attribute__((preserve_access_index));

struct inode {
	unsigned short i_mode;
	struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct gendisk {
	int major;
	int first_minor;
} __attribute__((preserve_access_index));

struct request_queue {
	struct gendisk *disk;
} __attribute__((preserve_access_index));

struct request {
	struct request_queue *q;
	struct gendisk *rq_disk; // before 5.17
} __attribute__((preserve_access_index));

// A process, as the identity cache keys it: thread-group ID and the group
// leader's start time.
struct proc_key {
	__u64 start_ns;
	__u32 tgid;
	__u32 pad;
};

struct cpu_val {
	__u64 cpu_ns;
	char comm[16];
};

struct io_val {
	__u64 read;
	__u64 write;
	char comm[16];
};

const struct proc_key *unused_proc_key __attribute__((unused));
const struct cpu_val *unused_cpu_val __attribute__((unused));
const struct io_val *unused_io_val __attribute__((unused));

// CPU of exited threads per process, read and cleared every interval.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct proc_key);
	__type(value, struct cpu_val);
} exits SEC(".maps");

// Logical file bytes per process, read and cleared every interval.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct proc_key);
	__type(value, struct io_val);
} fileio SEC(".maps");

// Threads inside a counted vfs_read (1) or vfs_write (2).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u32);
} inflight SEC(".maps");

#define LATENCY_BUCKETS 24

struct latency {
	__u64 buckets[LATENCY_BUCKETS]; // bucket i: [2^i, 2^(i+1)) microseconds
};

const struct latency *unused_latency __attribute__((unused));

// Block request latency per device (major << 20 | minor).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, struct latency);
} disks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64); // struct request pointer
	__type(value, __u64);
} issued SEC(".maps");

// Index of the request argument of block_rq_issue/complete: 0 since 5.11,
// 1 before (the request queue came first). Set by user space from BTF.
const volatile __u32 rq_arg = 0;

static __always_inline struct proc_key current_proc(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct proc_key k = {};
	k.tgid = bpf_get_current_pid_tgid() >> 32;
	k.start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
	return k;
}

SEC("raw_tracepoint/sched_process_exit")
int on_exit(void *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 ns = BPF_CORE_READ(task, se.sum_exec_runtime);
	if (!ns)
		return 0;
	struct proc_key k = current_proc();
	struct cpu_val *v = bpf_map_lookup_elem(&exits, &k);
	if (v) {
		__sync_fetch_and_add(&v->cpu_ns, ns);
		return 0;
	}
	struct cpu_val nv = {.cpu_ns = ns};
	bpf_get_current_comm(nv.comm, sizeof(nv.comm));
	bpf_map_update_elem(&exits, &k, &nv, BPF_NOEXIST);
	return 0;
}

#define S_IFMT 00170000
#define S_IFREG 0100000
#define S_IFBLK 0060000

// Regular files and block devices, outside pseudo and memory file systems
// (PRC-U-F2, PRC-U-F3).
static __always_inline int counted(struct file *f)
{
	unsigned short mode = BPF_CORE_READ(f, f_inode, i_mode) & S_IFMT;
	if (mode != S_IFREG && mode != S_IFBLK)
		return 0;
	switch (BPF_CORE_READ(f, f_inode, i_sb, s_magic)) {
	case 0x9fa0:     // proc
	case 0x62656572: // sysfs
	case 0x01021994: // tmpfs
	case 0x858458f6: // ramfs
	case 0x63677270: // cgroup2
	case 0x27e0eb:   // cgroup
	case 0x64626720: // debugfs
	case 0x74726163: // tracefs
	case 0xcafe4a11: // bpf
	case 0x73636673: // securityfs
		return 0;
	}
	return 1;
}

static __always_inline int enter(struct pt_regs *ctx, __u32 op)
{
	if (!counted((struct file *)ARG1(ctx)))
		return 0;
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&inflight, &tid, &op, BPF_ANY);
	return 0;
}

static __always_inline int leave(struct pt_regs *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u32 *op = bpf_map_lookup_elem(&inflight, &tid);
	if (!op)
		return 0;
	__u32 which = *op;
	bpf_map_delete_elem(&inflight, &tid);
	long ret = (long)RET(ctx);
	if (ret <= 0)
		return 0; // failed or empty (PRC-U-F4)
	struct proc_key k = current_proc();
	struct io_val *v = bpf_map_lookup_elem(&fileio, &k);
	if (!v) {
		struct io_val nv = {};
		bpf_get_current_comm(nv.comm, sizeof(nv.comm));
		bpf_map_update_elem(&fileio, &k, &nv, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&fileio, &k);
		if (!v)
			return 0;
	}
	if (which == 1)
		__sync_fetch_and_add(&v->read, ret);
	else
		__sync_fetch_and_add(&v->write, ret);
	return 0;
}

SEC("kprobe/vfs_read")
int on_read(struct pt_regs *ctx) { return enter(ctx, 1); }

SEC("kretprobe/vfs_read")
int on_read_ret(struct pt_regs *ctx) { return leave(ctx); }

SEC("kprobe/vfs_write")
int on_write(struct pt_regs *ctx) { return enter(ctx, 2); }

SEC("kretprobe/vfs_write")
int on_write_ret(struct pt_regs *ctx) { return leave(ctx); }

static __always_inline __u64 request_arg(struct bpf_raw_tracepoint_args *ctx)
{
	return rq_arg ? ctx->args[1] : ctx->args[0];
}

SEC("raw_tracepoint/block_rq_issue")
int on_rq_issue(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 rq = request_arg(ctx), now = bpf_ktime_get_ns();
	bpf_map_update_elem(&issued, &rq, &now, BPF_ANY);
	return 0;
}

SEC("raw_tracepoint/block_rq_complete")
int on_rq_complete(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 rq = request_arg(ctx);
	__u64 *start = bpf_map_lookup_elem(&issued, &rq);
	if (!start)
		return 0; // issued before the agent, or not seen (PRC-U-F9)
	__u64 us = (bpf_ktime_get_ns() - *start) / 1000;
	bpf_map_delete_elem(&issued, &rq);

	struct request *r = (struct request *)rq;
	struct gendisk *disk;
	if (bpf_core_field_exists(r->rq_disk))
		disk = BPF_CORE_READ(r, rq_disk);
	else
		disk = BPF_CORE_READ(r, q, disk);
	if (!disk)
		return 0;
	__u32 dev = ((__u32)BPF_CORE_READ(disk, major) << 20) | (__u32)BPF_CORE_READ(disk, first_minor);
	struct latency *l = bpf_map_lookup_elem(&disks, &dev);
	if (!l) {
		struct latency zero = {};
		bpf_map_update_elem(&disks, &dev, &zero, BPF_NOEXIST);
		l = bpf_map_lookup_elem(&disks, &dev);
		if (!l)
			return 0;
	}
	__u32 b = 0;
#pragma unroll
	for (int i = 0; i < LATENCY_BUCKETS - 1; i++) {
		if (us >= 2) {
			us >>= 1;
			b++;
		}
	}
	if (b < LATENCY_BUCKETS)
		__sync_fetch_and_add(&l->buckets[b], 1);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
