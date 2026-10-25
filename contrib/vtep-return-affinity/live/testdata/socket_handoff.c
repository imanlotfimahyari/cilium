/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Integration driver for the real hand-off helpers, not production Cilium.
 * The root-owned policy map is a test verdict source, not Cilium policy.
 */
#include <bpf/ctx/skb.h>
#define VTEP_SOCKET_MAX_TICKETS 8
#ifdef VTEP_HANDOFF_CILIUM_CORE
#define ENABLE_IPV4 1
#define TUNNEL_MODE 1
/* The live fixture supplies the actual VXLAN ifindex as a load-time constant. */
volatile const __u32 handoff_tunnel_ifindex;
#define ENCAP_IFINDEX handoff_tunnel_ifindex
#define ENABLE_VTEP_RETURN_SOCKET_AFFINITY 1
#include "bpf_lxc.c"
#else
#define ENABLE_VTEP_RETURN_SOCKET_AFFINITY 1
#include "lib/vtep_return_socket.h"
#endif
#include "lib/eth.h"

volatile const __u64 handoff_netns_cookie;
volatile const __u32 handoff_pod_ifindex;
volatile const __u32 handoff_tunnel_ifindex;
volatile const __u8 handoff_pod_mac[6];

#ifdef VTEP_HANDOFF_CILIUM_CORE
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__array(values, int());
} handoff_core_entries __section_maps_btf = {
	.values = { [0] = &cil_lxc_policy, [1] = &cil_from_container },
};
#endif

struct handoff_counters {
	__u64 admitted;
	__u64 ingress_denied;
	__u64 untrusted;
	__u64 admission_failed;
	__u64 assigned;
	__u64 assignment_failed;
	__u64 tunnel;
	__u64 native;
	__u64 reply_drop;
	__u64 synack_drop;
	__u64 data_drop;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32); /* client port, host order */
	__type(value, __u32); /* bit 0 ingress, bit 1 egress */
} handoff_policy __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct handoff_counters);
} handoff_stats __section_maps_btf;

struct handoff_debug {
	__s32 error, syn_result;
	__u32 op, family;
	__u64 saved_token;
	__be32 saved_local, saved_remote, context_local, context_remote;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct handoff_debug);
} handoff_diagnostics __section_maps_btf;

static __always_inline struct handoff_counters *handoff_count(void)
{
	__u32 zero = 0;

	return map_lookup_elem(&handoff_stats, &zero);
}

static __always_inline int handoff_ingress(struct __sk_buff *ctx, bool tunneled)
{
	struct handoff_counters *count = handoff_count();
	__u8 pod_mac[6] __align_stack_8;
#ifndef VTEP_HANDOFF_CILIUM_CORE
	struct bpf_tunnel_key tunnel = {};
	struct iphdr ip;
	struct tcphdr tcp;
	struct ethhdr eth;
	__u32 port, *verdict;
	__be32 peer = 0;
	int ret;
#endif

	if (!count)
		return TC_ACT_SHOT;
#ifdef VTEP_HANDOFF_CILIUM_CORE
	/* Only the network fixture is synthetic: normal endpoint policy, CT,
	 * post-policy admission and return forwarding are actual bpf_lxc.c.
	 */
	struct ethhdr eth;
	struct bpf_tunnel_key metadata = {};
	__u32 identity = WORLD_IPV4_ID;

	if (ctx_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0)
		return TC_ACT_SHOT;
	if (eth.h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK; /* Native underlay ARP stays in its own namespace. */
	for (int i = 0; i < ETH_ALEN; i++)
		pod_mac[i] = handoff_pod_mac[i];
	if (eth_store_daddr(ctx, pod_mac, 0) < 0)
		return TC_ACT_SHOT;
	if (tunneled) {
		if (ctx_get_tunnel_key(ctx, &metadata, sizeof(metadata), 0) < 0)
			return TC_ACT_SHOT;
		identity = get_id_from_tunnel_id(metadata.tunnel_id, bpf_htons(ETH_P_IP));
	}
	local_delivery_fill_meta(ctx, identity, true, true, false, tunneled, 0);
	tail_call_static(ctx, handoff_core_entries, 0);
	return TC_ACT_SHOT;
#else
	if (ctx_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0 || eth.h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	if (ctx_load_bytes(ctx, sizeof(eth), &ip, sizeof(ip)) < 0 || ip.ihl != 5 ||
	    ip.protocol != IPPROTO_TCP || ip.daddr != bpf_htonl(0xc633640a) ||
	    ctx_load_bytes(ctx, sizeof(eth) + sizeof(ip), &tcp, sizeof(tcp)) < 0)
		return TC_ACT_SHOT;
	if (tunneled) {
		if (ctx_get_tunnel_key(ctx, &tunnel, sizeof(tunnel), 0) < 0 || tunnel.tunnel_id != 2)
			goto untrusted;
		peer = bpf_htonl(tunnel.remote_ipv4);
		if (!map_lookup_elem(&cilium_vtep_peers4, &peer))
			goto untrusted;
	}
	port = bpf_ntohs(tcp.source);
	verdict = map_lookup_elem(&handoff_policy, &port);
	if (!verdict || !(*verdict & 1)) {
		__sync_fetch_and_add(&count->ingress_denied, 1);
		return TC_ACT_SHOT;
	}
	for (int i = 0; i < ETH_ALEN; i++)
		pod_mac[i] = handoff_pod_mac[i];
	if (eth_store_daddr(ctx, pod_mac, 0) < 0)
		return TC_ACT_SHOT;
	if (tcp.syn && !tcp.ack) {
		ret = vtep_socket_admit4(ctx, handoff_netns_cookie,
					tunneled ? VTEP_SOCKET_TUNNEL : VTEP_SOCKET_NATIVE, peer, true);
		if (ret) {
			__sync_fetch_and_add(&count->admission_failed, 1);
			return TC_ACT_SHOT;
		}
		__sync_fetch_and_add(&count->admitted, 1);
	}
	/* Direct endpoint delivery: no subsequent source-MAC rewrite. */
	return ctx_redirect_peer(ctx, (int)handoff_pod_ifindex, 0);
untrusted:
	__sync_fetch_and_add(&count->untrusted, 1);
	return TC_ACT_SHOT;
#endif
}

__section("tc/handoff_overlay")
int handoff_from_overlay(struct __sk_buff *ctx)
{
	return handoff_ingress(ctx, true);
}

__section("tc/handoff_native")
int handoff_from_native(struct __sk_buff *ctx)
{
	return handoff_ingress(ctx, false);
}

#ifdef VTEP_HANDOFF_CILIUM_CORE
/* A Cilium overlay peer ignores the inner next-hop MAC when delivering a
 * decapsulated packet. Model only that receive property on the Linux peer.
 */
__section("tc/handoff_remote_receive")
int handoff_remote_receive(struct __sk_buff *ctx)
{
	ctx_change_type(ctx, PACKET_HOST);
	return TC_ACT_OK;
}

/* A locally generated kubelet-style probe enters on host veth egress, where
 * the real policy entrypoint must return OK rather than redirect to itself.
 */
__section("tc/handoff_host")
int handoff_from_host(struct __sk_buff *ctx)
{
	struct ethhdr eth;
	__u8 pod_mac[6] __align_stack_8;

	if (ctx_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0 ||
	    eth.h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	for (int i = 0; i < ETH_ALEN; i++)
		pod_mac[i] = handoff_pod_mac[i];
	if (eth_store_daddr(ctx, pod_mac, 0) < 0)
		return TC_ACT_SHOT;
	local_delivery_fill_meta(ctx, HOST_ID, false, false, true, false, 0);
	tail_call_static(ctx, handoff_core_entries, 0);
	return TC_ACT_SHOT;
}
#endif

__section("sockops")
int handoff_socket(struct bpf_sock_ops *ctx)
{
	struct handoff_counters *count = handoff_count();
	__u32 op = ctx->op;
	int ret = vtep_socket_sockops4(ctx);

	if (ret < 0) {
		__u32 zero = 0;
		struct handoff_debug *debug = map_lookup_elem(&handoff_diagnostics, &zero);
		struct vtep_socket_saved_syn syn = {};

		if (debug) {
			debug->error = ret;
			debug->op = op;
			debug->family = ctx->family;
			debug->syn_result = get_socket_opt(ctx, IPPROTO_TCP, TCP_BPF_SYN_MAC, &syn, sizeof(syn));
			debug->saved_token = vtep_socket_decode4(syn.eth.h_source);
			debug->saved_local = syn.ip.daddr;
			debug->saved_remote = syn.ip.saddr;
			debug->context_local = ctx->local_ip4;
			debug->context_remote = ctx->remote_ip4;
		}
	}

	if (op == BPF_SOCK_OPS_HDR_OPT_LEN_CB)
		ctx->reply = 0; /* No TCP options are added by this experiment. */
	if (count && ret < 0)
		__sync_fetch_and_add(&count->assignment_failed, 1);
	if (count && !ret && (op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB ||
			     op == BPF_SOCK_OPS_TCP_CONNECT_CB))
		__sync_fetch_and_add(&count->assigned, 1);
	return 1;
}

__section("tc/handoff_reply")
int handoff_from_pod(struct __sk_buff *ctx)
{
#ifdef VTEP_HANDOFF_CILIUM_CORE
	tail_call_static(ctx, handoff_core_entries, 1);
	return TC_ACT_SHOT;
#else
	struct handoff_counters *count = handoff_count();
	struct bpf_tunnel_key tunnel = {};
	const struct vtep_socket_peer *destination;
	struct iphdr ip;
	struct tcphdr tcp;
	__be32 peer = 0;
	__u8 pod_mac[6] __align_stack_8;
	__u32 port, *verdict;
	int action;

	if (!count)
		return TC_ACT_SHOT;
	if (ctx_load_bytes(ctx, sizeof(struct ethhdr), &ip, sizeof(ip)) < 0 ||
	    ip.version != 4 || ip.protocol != IPPROTO_TCP)
		return TC_ACT_OK;
	if (ip.ihl != 5 || ip.saddr != bpf_htonl(0xc633640a) ||
	    ctx_load_bytes(ctx, sizeof(struct ethhdr) + sizeof(ip), &tcp, sizeof(tcp)) < 0)
		return TC_ACT_SHOT;
	port = bpf_ntohs(tcp.dest);
	verdict = map_lookup_elem(&handoff_policy, &port);
	action = vtep_socket_reply4(ctx, handoff_netns_cookie, verdict && (*verdict & 2), &peer);
	for (int i = 0; i < ETH_ALEN; i++)
		pod_mac[i] = handoff_pod_mac[i];
	if (action != VTEP_SOCKET_DROP && eth_store_saddr(ctx, pod_mac, 0) < 0)
		action = VTEP_SOCKET_DROP;
	if (action == VTEP_SOCKET_PASS) {
		__sync_fetch_and_add(&count->native, 1);
		return TC_ACT_OK;
	}
	if (action == VTEP_SOCKET_REDIRECT) {
		destination = map_lookup_elem(&cilium_vtep_peers4, &peer);
		if (destination && !eth_store_daddr(ctx, destination->mac, 0)) {
			tunnel.remote_ipv4 = bpf_ntohl(peer);
			tunnel.tunnel_id = 2;
			tunnel.tunnel_ttl = 64;
			if (!ctx_set_tunnel_key(ctx, &tunnel, sizeof(tunnel), 0)) {
				__sync_fetch_and_add(&count->tunnel, 1);
				return ctx_redirect(ctx, (int)handoff_tunnel_ifindex, 0);
			}
		}
	}
	__sync_fetch_and_add(&count->reply_drop, 1);
	if (tcp.syn && tcp.ack)
		__sync_fetch_and_add(&count->synack_drop, 1);
	if (bpf_ntohs(ip.tot_len) > sizeof(ip) + (__u32)tcp.doff * 4)
		__sync_fetch_and_add(&count->data_drop, 1);
	return TC_ACT_SHOT;
#endif
}

__section("tc/handoff_before_queue")
int handoff_before_queue(struct __sk_buff *ctx)
{
	struct handoff_counters *count = handoff_count();

	if (vtep_socket_before_queue4(ctx, handoff_netns_cookie) < 0) {
		if (count)
			__sync_fetch_and_add(&count->synack_drop, 1);
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}

__section("tc/handoff_collect")
int handoff_collect(__maybe_unused struct __sk_buff *ctx)
{
	return vtep_socket_collect4() ? TC_ACT_SHOT : TC_ACT_OK;
}

#ifndef VTEP_HANDOFF_CILIUM_CORE
BPF_LICENSE("GPL");
#endif
