// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// discovery: TCP listeners opening and closing, for the host service
// inventory, and outbound connections counted per source and destination,
// for dependency edges (docs/eBPF/03-service-discovery.md). Reads no
// arguments, environment or payloads, and never keys by source port.
#include "types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Only the fields read here; CO-RE relocates them per kernel.
struct task_struct {
	__u64 start_boottime;
} __attribute__((preserve_access_index));

struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct net {
	struct ns_common ns;
} __attribute__((preserve_access_index));

typedef struct {
	struct net *net;
} __attribute__((preserve_access_index)) possible_net_t;

struct in6_addr {
	__u8 s6_addr[16];
};

struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	possible_net_t skc_net;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct inode {
	unsigned long i_ino;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct socket {
	struct file *file;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	struct socket *sk_socket;
} __attribute__((preserve_access_index));

enum event_type {
	LISTEN_OPEN = 1,
	LISTEN_CLOSE = 2,
};

struct event {
	__u64 start_ns;     // listener process's start_boottime (identity key)
	__u64 cgroup_id;
	__u64 ino;          // socket inode, the same number /proc/net/tcp shows
	__u32 type;
	__u32 pid;          // process calling listen(); the closer for LISTEN_CLOSE
	__u32 netns;        // network namespace inode
	__u16 port;         // host order
	__u16 family;       // AF_INET or AF_INET6
	__u8 addr[16];      // bind address; IPv4 in the first 4 bytes
	char comm[16];
};

const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost SEC(".maps");

#define AF_INET 2
#define AF_INET6 10
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7
#define TCP_LISTEN 10

// Who started each pending connect: connect() moves the socket to SYN_SENT
// in the caller's context, but SYN_SENT -> ESTABLISHED happens in softirq,
// where the current task is unrelated.
struct owner {
	__u64 start_ns;
	__u64 cgroup_id;
	__u32 pid;
	__u32 pad;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64); // struct sock pointer
	__type(value, struct owner);
} owners SEC(".maps");

// Established connections per source group and destination, read and
// cleared by user space every interval.
struct edge_key {
	__u64 cgroup_id;
	__u8 daddr[16];     // IPv4 in the first 4 bytes
	__u16 dport;        // host order
	__u16 family;
	__u32 pad;
	char comm[16];
};

struct edge_val {
	__u64 count;
	__u64 start_ns;     // one process of the group, to resolve its identity
	__u32 pid;
	__u32 pad;
};

const struct edge_key *unused_edge_key __attribute__((unused));
const struct edge_val *unused_edge_val __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct edge_key);
	__type(value, struct edge_val);
} edges SEC(".maps");

static __always_inline void track_connect(struct sock *sk, int oldstate, int newstate)
{
	__u64 key = (__u64)sk;
	if (newstate == TCP_SYN_SENT) {
		struct owner o = {};
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		o.start_ns = BPF_CORE_READ(task, start_boottime);
		o.cgroup_id = bpf_get_current_cgroup_id();
		o.pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(o.comm, sizeof(o.comm));
		bpf_map_update_elem(&owners, &key, &o, BPF_ANY);
		return;
	}
	if (oldstate != TCP_SYN_SENT)
		return;
	struct owner *o = bpf_map_lookup_elem(&owners, &key);
	if (!o)
		return;
	if (newstate == TCP_ESTABLISHED) {
		struct edge_key k = {};
		k.cgroup_id = o->cgroup_id;
		__builtin_memcpy(k.comm, o->comm, sizeof(k.comm));
		k.family = BPF_CORE_READ(sk, __sk_common.skc_family);
		if (k.family == AF_INET)
			BPF_CORE_READ_INTO(&k.daddr, sk, __sk_common.skc_daddr);
		else
			BPF_CORE_READ_INTO(&k.daddr, sk, __sk_common.skc_v6_daddr);
		k.dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
		struct edge_val *v = bpf_map_lookup_elem(&edges, &k);
		if (v) {
			__sync_fetch_and_add(&v->count, 1);
		} else {
			struct edge_val nv = {.count = 1, .start_ns = o->start_ns, .pid = o->pid};
			bpf_map_update_elem(&edges, &k, &nv, BPF_NOEXIST);
		}
	}
	// Established or failed (DSC-U-F7: no edge), the connect is done.
	bpf_map_delete_elem(&owners, &key);
}

// inet_sock_set_state(const struct sock *sk, int oldstate, int newstate).
// listen() moves a socket to LISTEN in the caller's context; closing it
// moves LISTEN to CLOSE. Every other transition returns at once.
SEC("raw_tracepoint/inet_sock_set_state")
int on_sock_state(struct bpf_raw_tracepoint_args *ctx)
{
	int oldstate = (int)ctx->args[1], newstate = (int)ctx->args[2];
	if (newstate == TCP_SYN_SENT || oldstate == TCP_SYN_SENT) {
		track_connect((struct sock *)ctx->args[0], oldstate, newstate);
		return 0;
	}
	__u32 type;
	if (newstate == TCP_LISTEN)
		type = LISTEN_OPEN;
	else if (oldstate == TCP_LISTEN && newstate == TCP_CLOSE)
		type = LISTEN_CLOSE;
	else
		return 0;

	struct sock *sk = (struct sock *)ctx->args[0];
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 key = 0;
		__u64 *n = bpf_map_lookup_elem(&lost, &key);
		if (n)
			(*n)++;
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->type = type;
	e->ino = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	e->port = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (e->family == AF_INET)
		BPF_CORE_READ_INTO(&e->addr, sk, __sk_common.skc_rcv_saddr);
	else if (e->family == AF_INET6)
		BPF_CORE_READ_INTO(&e->addr, sk, __sk_common.skc_v6_rcv_saddr);
	if (type == LISTEN_OPEN) {
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		e->start_ns = BPF_CORE_READ(task, start_boottime);
		e->cgroup_id = bpf_get_current_cgroup_id();
		bpf_get_current_comm(e->comm, sizeof(e->comm));
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
