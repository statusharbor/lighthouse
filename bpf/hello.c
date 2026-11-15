// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// hello: the foundation's empty collector (docs/eBPF/01-foundation.md).
// Counts process starts so the pipeline, loading and transport can be
// proven on every kernel without shipping a feature.
#include "types.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} exec_count SEC(".maps");

SEC("raw_tracepoint/sched_process_exec")
int count_exec(void *ctx)
{
	__u32 key = 0;
	__u64 *v = bpf_map_lookup_elem(&exec_count, &key);
	if (v)
		(*v)++;
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
