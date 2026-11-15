// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// dns: DNS query and response headers on UDP port 53, from cgroup_skb
// programs on the root cgroup (docs/eBPF/04-network-quality.md). Reads the
// IP and UDP headers and the 12-byte DNS header only: never the queried
// name or the answers. Always lets the packet through.
#include "types.h"
#include <bpf/bpf_helpers.h>

// The start of the UAPI context; the verifier rewrites accesses by offset,
// so only the leading fields up to protocol are declared.
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
};

struct event {
	__u64 ts_ns;         // bpf_ktime_get_ns
	__u8 resolver[16];   // IPv4 in the first 4 bytes
	__u16 family;        // 4 or 6
	__u16 client_port;   // the querying socket's port
	__u16 txid;
	__u16 flags;         // DNS header flags: QR, opcode, TC, RCODE
	__u8 response;       // 1: ingress response from the resolver
	__u8 pad[7];
};

const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost SEC(".maps");

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_UDP 17
#define DNS_PORT 53

static __always_inline void dns(struct __sk_buff *skb, __u8 response)
{
	__u8 ipv[1];
	__u32 udp_off, addr_off;
	__u16 family;
	if (skb->protocol == __builtin_bswap16(ETH_P_IP)) {
		__u8 hdr[20];
		if (bpf_skb_load_bytes(skb, 0, hdr, sizeof(hdr)) < 0 || hdr[9] != IPPROTO_UDP)
			return;
		udp_off = (hdr[0] & 0x0f) * 4;
		addr_off = response ? 12 : 16; // the resolver: source of a response, destination of a query
		family = 4;
	} else if (skb->protocol == __builtin_bswap16(ETH_P_IPV6)) {
		if (bpf_skb_load_bytes(skb, 6, ipv, 1) < 0 || ipv[0] != IPPROTO_UDP)
			return; // extension headers before UDP are not followed
		udp_off = 40;
		addr_off = response ? 8 : 24;
		family = 6;
	} else {
		return;
	}
	__u16 ports[2];
	if (bpf_skb_load_bytes(skb, udp_off, ports, sizeof(ports)) < 0)
		return;
	__u16 sport = __builtin_bswap16(ports[0]), dport = __builtin_bswap16(ports[1]);
	if (response ? sport != DNS_PORT : dport != DNS_PORT)
		return;
	__u16 dnshdr[2];
	if (bpf_skb_load_bytes(skb, udp_off + 8, dnshdr, sizeof(dnshdr)) < 0)
		return;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 zero = 0;
		__u64 *n = bpf_map_lookup_elem(&lost, &zero);
		if (n)
			(*n)++;
		return;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->family = family;
	e->response = response;
	e->client_port = response ? dport : sport;
	e->txid = __builtin_bswap16(dnshdr[0]);
	e->flags = __builtin_bswap16(dnshdr[1]);
	if (family == 4)
		bpf_skb_load_bytes(skb, addr_off, e->resolver, 4);
	else
		bpf_skb_load_bytes(skb, addr_off, e->resolver, 16);
	bpf_ringbuf_submit(e, 0);
}

SEC("cgroup_skb/egress")
int dns_egress(struct __sk_buff *skb)
{
	dns(skb, 0);
	return 1;
}

SEC("cgroup_skb/ingress")
int dns_ingress(struct __sk_buff *skb)
{
	dns(skb, 1);
	return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
