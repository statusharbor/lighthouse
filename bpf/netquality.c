// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// netquality: TCP path quality per connection (docs/eBPF/04-network-quality.md).
// A socket iterator user space runs once per interval reads each
// established socket's smoothed RTT, retransmits, segments and bytes; the
// same fields are captured at close so short connections count; connect
// time goes into per-destination histograms. Reads no payloads.
#include "types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct task_struct {
	__u64 start_boottime;
} __attribute__((preserve_access_index));

struct in6_addr {
	__u8 s6_addr[16];
};

struct sock_common {
	__be32 skc_daddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	volatile unsigned char skc_state;
	struct in6_addr skc_v6_daddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct tcp_sock {
	__u32 srtt_us;       // smoothed RTT << 3, in microseconds
	__u32 total_retrans;
	__u32 data_segs_out;
	__u64 bytes_acked;
	__u64 bytes_received;
} __attribute__((preserve_access_index));

struct seq_file;

struct bpf_iter_meta {
	struct seq_file *seq;
	__u64 session_id;
	__u64 seq_num;
} __attribute__((preserve_access_index));

struct bpf_iter__tcp {
	struct bpf_iter_meta *meta;
	struct sock_common *sk_common;
	__u32 uid;
} __attribute__((preserve_access_index));

#define AF_INET 2
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7
#define TCP_LISTEN 10

// Who owns a connection, keyed by struct sock pointer: the process that
// called connect() (in its context, at SYN_SENT) or accept() (at the
// accept return).
struct owner {
	__u64 start_ns;      // owner's start_boottime (identity key)
	__u64 cgroup_id;
	__u64 connect_ns;    // SYN_SENT time, for connect duration; 0 if accepted
	__u32 pid;
	__u32 inbound;       // 1: accepted
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct owner);
} owners SEC(".maps");

// One socket's counters, from the iterator or at close.
struct sample {
	__u64 sk;
	__u64 bytes_acked;
	__u64 bytes_received;
	__u64 start_ns;
	__u64 cgroup_id;
	__u32 pid;           // 0: owner unknown (accepted, or opened before the agent)
	__u32 srtt_us;       // already shifted, microseconds
	__u32 total_retrans;
	__u32 data_segs_out;
	__u16 lport;
	__u16 dport;
	__u16 family;
	__u16 flags;         // 1: captured at close; 2: accepted (inbound)
	__u8 daddr[16];      // IPv4 in the first 4 bytes
	char comm[16];
};

const struct sample *unused_sample __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} closes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost SEC(".maps");

// Connect durations per destination: log2 buckets of microseconds
// (bucket i holds [2^i, 2^(i+1)) us), read and cleared every interval.
#define CONNECT_BUCKETS 24

struct dest_key {
	__u8 daddr[16];
	__u16 dport;
	__u16 family;
	__u32 pad;
};

struct connect_hist {
	__u64 count;
	__u64 sum_us;
	__u64 buckets[CONNECT_BUCKETS];
};

const struct dest_key *unused_dest_key __attribute__((unused));
const struct connect_hist *unused_connect_hist __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct dest_key);
	__type(value, struct connect_hist);
} connects SEC(".maps");

static __always_inline void read_dest(struct sock_common *skc, __u8 *daddr, __u16 *dport, __u16 *family)
{
	*family = BPF_CORE_READ(skc, skc_family);
	if (*family == AF_INET)
		BPF_CORE_READ_INTO((__be32 *)daddr, skc, skc_daddr);
	else
		BPF_CORE_READ_INTO((struct in6_addr *)daddr, skc, skc_v6_daddr);
	*dport = __builtin_bswap16(BPF_CORE_READ(skc, skc_dport));
}

static __always_inline void fill(struct sample *s, struct sock_common *skc)
{
	struct tcp_sock *tp = (struct tcp_sock *)skc;
	s->sk = (__u64)skc;
	s->srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;
	s->total_retrans = BPF_CORE_READ(tp, total_retrans);
	s->data_segs_out = BPF_CORE_READ(tp, data_segs_out);
	s->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
	s->bytes_received = BPF_CORE_READ(tp, bytes_received);
	s->lport = BPF_CORE_READ(skc, skc_num);
	read_dest(skc, s->daddr, &s->dport, &s->family);
	__u64 key = s->sk;
	struct owner *o = bpf_map_lookup_elem(&owners, &key);
	if (o) {
		s->pid = o->pid;
		s->start_ns = o->start_ns;
		s->cgroup_id = o->cgroup_id;
		if (o->inbound)
			s->flags |= 2;
		__builtin_memcpy(s->comm, o->comm, sizeof(s->comm));
	}
}

static __always_inline __u32 log2_us(__u64 us)
{
	__u32 b = 0;
#pragma unroll
	for (int i = 0; i < CONNECT_BUCKETS - 1; i++) {
		if (us >= 2) {
			us >>= 1;
			b++;
		}
	}
	return b;
}

SEC("iter/tcp")
int dump_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	if (!skc || BPF_CORE_READ(skc, skc_state) != TCP_ESTABLISHED)
		return 0;
	struct sample s = {};
	fill(&s, skc);
	bpf_seq_write(ctx->meta->seq, &s, sizeof(s));
	return 0;
}

// inet_sock_set_state(const struct sock *sk, int oldstate, int newstate)
SEC("raw_tracepoint/inet_sock_set_state")
int on_state(struct bpf_raw_tracepoint_args *ctx)
{
	struct sock_common *skc = (struct sock_common *)ctx->args[0];
	int oldstate = (int)ctx->args[1], newstate = (int)ctx->args[2];
	__u64 key = (__u64)skc;

	if (newstate == TCP_SYN_SENT) {
		struct owner o = {};
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		o.start_ns = BPF_CORE_READ(task, start_boottime);
		o.cgroup_id = bpf_get_current_cgroup_id();
		o.connect_ns = bpf_ktime_get_ns();
		o.pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(o.comm, sizeof(o.comm));
		bpf_map_update_elem(&owners, &key, &o, BPF_ANY);
		return 0;
	}
	if (oldstate == TCP_SYN_SENT && newstate == TCP_ESTABLISHED) {
		struct owner *o = bpf_map_lookup_elem(&owners, &key);
		if (!o || !o->connect_ns)
			return 0;
		__u64 us = (bpf_ktime_get_ns() - o->connect_ns) / 1000;
		struct dest_key k = {};
		read_dest(skc, k.daddr, &k.dport, &k.family);
		struct connect_hist *h = bpf_map_lookup_elem(&connects, &k);
		if (!h) {
			struct connect_hist zero = {};
			bpf_map_update_elem(&connects, &k, &zero, BPF_NOEXIST);
			h = bpf_map_lookup_elem(&connects, &k);
			if (!h)
				return 0;
		}
		__sync_fetch_and_add(&h->count, 1);
		__sync_fetch_and_add(&h->sum_us, us);
		__u32 b = log2_us(us);
		if (b < CONNECT_BUCKETS)
			__sync_fetch_and_add(&h->buckets[b], 1);
		return 0;
	}
	if (newstate != TCP_CLOSE)
		return 0;
	if (oldstate == TCP_SYN_SENT || oldstate == TCP_LISTEN) {
		bpf_map_delete_elem(&owners, &key);
		return 0; // never carried data
	}
	struct sample *s = bpf_ringbuf_reserve(&closes, sizeof(*s), 0);
	if (!s) {
		__u32 zero = 0;
		__u64 *n = bpf_map_lookup_elem(&lost, &zero);
		if (n)
			(*n)++;
	} else {
		__builtin_memset(s, 0, sizeof(*s));
		fill(s, skc);
		s->flags |= 1;
		bpf_ringbuf_submit(s, 0);
	}
	bpf_map_delete_elem(&owners, &key);
	return 0;
}

// inet_csk_accept returns the accepted socket in the accepting process's
// context, so server-side traffic is attributed to its process too.
SEC("kretprobe/inet_csk_accept")
int on_accept(struct pt_regs *ctx)
{
	__u64 key = (__u64)RET(ctx);
	if (!key)
		return 0;
	struct owner o = {.inbound = 1};
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	o.start_ns = BPF_CORE_READ(task, start_boottime);
	o.cgroup_id = bpf_get_current_cgroup_id();
	o.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(o.comm, sizeof(o.comm));
	bpf_map_update_elem(&owners, &key, &o, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
