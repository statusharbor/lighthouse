// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// identity: process exec and exit events for the identity cache
// (docs/eBPF/01-foundation.md). User space keys processes by pid and start
// time and resolves container and pod from /proc. Never reads arguments
// or environment.
#include "types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Only the field read here; CO-RE relocates it against the running
// kernel's BTF. start_boottime is what /proc/<pid>/stat reports as
// starttime (in USER_HZ ticks), so both sides agree on the key.
struct task_struct {
	__u64 start_boottime;
} __attribute__((preserve_access_index));

enum event_type {
	EVENT_EXEC = 1,
	EVENT_EXIT = 2,
};

struct event {
	__u64 start_ns;
	__u64 cgroup_id;
	__u32 pid;
	__u32 type;
	char comm[16];
};

// Forces BTF for struct event so bpf2go generates the Go type.
const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost SEC(".maps");

static __always_inline int emit(__u32 type)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;

	// Thread exits are not process exits.
	if (type == EVENT_EXIT && tgid != (__u32)id)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 key = 0;
		__u64 *n = bpf_map_lookup_elem(&lost, &key);
		if (n)
			(*n)++;
		return 0;
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->start_ns = BPF_CORE_READ(task, start_boottime);
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->pid = tgid;
	e->type = type;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int on_exec(void *ctx)
{
	return emit(EVENT_EXEC);
}

SEC("raw_tracepoint/sched_process_exit")
int on_exit(void *ctx)
{
	return emit(EVENT_EXIT);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
