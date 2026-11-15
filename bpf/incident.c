// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// incident: OOM kills, abnormal process exits, fatal-signal senders and
// TCP failure counters for the incident context panel
// (docs/eBPF/02-incident-context.md). Reads no arguments, environment,
// memory contents or packet payloads.
#include "types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Only the fields read here; CO-RE relocates them per kernel.
struct task_struct {
	int exit_code;
	int tgid;
	__u64 start_boottime;
	char comm[16];
	struct task_struct *real_parent;
} __attribute__((preserve_access_index));

struct oom_control {
	void *memcg; // set when a memory cgroup limit caused the OOM
	struct task_struct *chosen;
} __attribute__((preserve_access_index));

struct in6_addr {
	__u8 s6_addr[16];
};

struct sock_common {
	__be32 skc_daddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	int sk_err;
} __attribute__((preserve_access_index));

enum event_type {
	EVENT_OOM = 1,
	EVENT_EXIT = 2,
};

struct event {
	__u64 ts_ns;        // bpf_ktime_get_boot_ns at the event
	__u64 start_ns;     // subject's start_boottime (identity key)
	__u64 cgroup_id;    // current task's cgroup (the exiting task for exits)
	__u32 type;
	__u32 pid;          // subject: victim for OOM, exiting process for exits
	__u32 other_pid;    // OOM: triggering task; exit: fatal-signal sender
	__s32 exit_code;    // raw exit code (signal | core << 7 | status << 8)
	__u32 ppid;         // exit: parent tgid
	__u32 flags;        // OOM: 1 = memory cgroup limit
	__u32 sender_sig;   // exit: signal the sender sent (9 or 15), 0 if none
	__u32 pad;
	char comm[16];
	char other_comm[16];
	char parent_comm[16];
};

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

// Last SIGKILL/SIGTERM sent to a process, so its exit can name the sender.
struct sender {
	__u32 pid;
	__u32 sig;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct sender);
} senders SEC(".maps");

static __always_inline struct event *reserve(void)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 key = 0;
		__u64 *n = bpf_map_lookup_elem(&lost, &key);
		if (n)
			(*n)++;
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_boot_ns();
	return e;
}

SEC("kprobe/oom_kill_process")
int on_oom_kill(struct pt_regs *ctx)
{
	struct oom_control *oc = (struct oom_control *)ARG1(ctx);
	struct task_struct *victim = BPF_CORE_READ(oc, chosen);
	if (!victim)
		return 0;
	struct event *e = reserve();
	if (!e)
		return 0;
	e->type = EVENT_OOM;
	e->pid = BPF_CORE_READ(victim, tgid);
	e->start_ns = BPF_CORE_READ(victim, start_boottime);
	BPF_CORE_READ_STR_INTO(&e->comm, victim, comm);
	e->other_pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(e->other_comm, sizeof(e->other_comm));
	e->flags = BPF_CORE_READ(oc, memcg) ? 1 : 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// signal_generate(int sig, struct kernel_siginfo *info,
//                 struct task_struct *task, int group, int result)
SEC("raw_tracepoint/signal_generate")
int on_signal(struct bpf_raw_tracepoint_args *ctx)
{
	int sig = (int)ctx->args[0];
	if (sig != 9 && sig != 15)
		return 0;
	struct task_struct *target = (struct task_struct *)ctx->args[2];
	__u32 tgid = BPF_CORE_READ(target, tgid);
	struct sender s = {
		.pid = bpf_get_current_pid_tgid() >> 32,
		.sig = sig,
	};
	bpf_get_current_comm(s.comm, sizeof(s.comm));
	bpf_map_update_elem(&senders, &tgid, &s, BPF_ANY);
	return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int on_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	if (tgid != (__u32)id)
		return 0; // thread exit (INC-U-F3)

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	int code = BPF_CORE_READ(task, exit_code);
	struct sender *s = bpf_map_lookup_elem(&senders, &tgid);
	if (code == 0) {
		if (s)
			bpf_map_delete_elem(&senders, &tgid);
		return 0; // clean exit (INC-U-F1)
	}

	struct event *e = reserve();
	if (!e)
		return 0;
	e->type = EVENT_EXIT;
	e->pid = tgid;
	e->exit_code = code;
	e->start_ns = BPF_CORE_READ(task, start_boottime);
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	BPF_CORE_READ_STR_INTO(&e->parent_comm, task, real_parent, comm);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	if (s) {
		e->other_pid = s->pid;
		e->sender_sig = s->sig;
		__builtin_memcpy(e->other_comm, s->comm, sizeof(e->other_comm));
		bpf_map_delete_elem(&senders, &tgid);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// TCP counters, read and cleared by user space once per interval. Keyed by
// both ports so user space can tell inbound from outbound sockets.
enum conn_kind {
	CONN_CONNECT_FAILED = 1,
	CONN_RESET_SENT = 2,
	CONN_RESET_RECEIVED = 3,
	CONN_RETRANSMIT = 4,
};

struct conn_key {
	__u8 addr[16];      // peer address; IPv4 in the first 4 bytes
	__u16 rport;        // peer port, host order
	__u16 lport;        // local port, host order
	__u16 family;       // AF_INET or AF_INET6
	__u8 kind;
	__u8 err;           // connect failures: socket error (0: closed by the app)
};

const struct conn_key *unused_conn_key __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct conn_key);
	__type(value, __u64);
} conns SEC(".maps");

#define AF_INET 2
#define AF_INET6 10
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7

static __always_inline void count(struct sock *sk, __u8 kind, __u8 err)
{
	struct conn_key k = {};
	k.family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (k.family == AF_INET)
		BPF_CORE_READ_INTO(&k.addr, sk, __sk_common.skc_daddr);
	else if (k.family == AF_INET6)
		BPF_CORE_READ_INTO(&k.addr, sk, __sk_common.skc_v6_daddr);
	else
		return;
	k.rport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	k.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	k.kind = kind;
	k.err = err;
	__u64 *n = bpf_map_lookup_elem(&conns, &k);
	if (n) {
		__sync_fetch_and_add(n, 1);
		return;
	}
	__u64 one = 1;
	bpf_map_update_elem(&conns, &k, &one, BPF_NOEXIST);
}

// inet_sock_set_state(const struct sock *sk, int oldstate, int newstate).
// Only TCP calls it. SYN_SENT -> CLOSE is a failed connect; the kernel
// sets sk_err (refused, timed out, unreachable) before the state change.
SEC("raw_tracepoint/inet_sock_set_state")
int on_sock_state(struct bpf_raw_tracepoint_args *ctx)
{
	if ((int)ctx->args[1] != TCP_SYN_SENT || (int)ctx->args[2] != TCP_CLOSE)
		return 0;
	struct sock *sk = (struct sock *)ctx->args[0];
	count(sk, CONN_CONNECT_FAILED, (__u8)BPF_CORE_READ(sk, sk_err));
	return 0;
}

// tcp_send_reset(const struct sock *sk, const struct sk_buff *skb, ...).
// sk is NULL for a reset to a closed port, which is what a port scan
// produces (INC-E-F4), so those are not counted.
SEC("raw_tracepoint/tcp_send_reset")
int on_send_reset(struct bpf_raw_tracepoint_args *ctx)
{
	struct sock *sk = (struct sock *)ctx->args[0];
	if (sk)
		count(sk, CONN_RESET_SENT, 0);
	return 0;
}

// tcp_receive_reset(struct sock *sk)
SEC("raw_tracepoint/tcp_receive_reset")
int on_receive_reset(struct bpf_raw_tracepoint_args *ctx)
{
	count((struct sock *)ctx->args[0], CONN_RESET_RECEIVED, 0);
	return 0;
}

// tcp_retransmit_skb(const struct sock *sk, const struct sk_buff *skb, ...)
SEC("raw_tracepoint/tcp_retransmit_skb")
int on_retransmit(struct bpf_raw_tracepoint_args *ctx)
{
	count((struct sock *)ctx->args[0], CONN_RETRANSMIT, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
