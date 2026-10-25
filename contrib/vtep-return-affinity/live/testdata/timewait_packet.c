/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#define VTEP_SOCKET_MAX_TICKETS 8
#define ENABLE_VTEP_RETURN_SOCKET_AFFINITY 1
#include "lib/vtep_return_timewait_producer.h"

volatile const __u64 tw_netns_cookie;
volatile const __u32 tw_tunnel_ifindex;
volatile const __u8 tw_pod_mac[6];

/* Same synthetic policy verdict as the existing handoff driver. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} handoff_policy __section_maps_btf;

/* Test receiver sink: taps still observe ACK delivery, but a now-closed old
 * client must not inject an unrelated RST into a reused server-side tuple.
 * This deliberately does not claim tenant isolation between outer peers.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u32);
} tw_capture_ports __section_maps_btf;

__section("tc/tw_capture")
int tw_capture_only(struct __sk_buff *ctx)
{
	struct iphdr ip;
	struct tcphdr tcp;
	__u32 port;

	if (ctx_load_bytes(ctx, sizeof(struct ethhdr), &ip, sizeof(ip)) < 0 ||
	    ip.version != 4 || ip.ihl != 5 || ip.protocol != IPPROTO_TCP ||
	    ctx_load_bytes(ctx, sizeof(struct ethhdr) + sizeof(ip), &tcp, sizeof(tcp)) < 0)
		return (-1);
	port = bpf_ntohs(tcp.dest);
	return map_lookup_elem(&tw_capture_ports, &port) ? TC_ACT_SHOT : (-1);
}

struct tw_route_stats { __u64 tunnel, native, denied; };
struct {
 __uint(type, BPF_MAP_TYPE_ARRAY);
 __uint(max_entries, 1);
 __type(key, __u32);
 __type(value, struct tw_route_stats);
} tw_route_stats __section_maps_btf;
static __always_inline struct tw_route_stats *tw_route_counters(void)
{
 __u32 zero = 0;
 return map_lookup_elem(&tw_route_stats, &zero);
}

__section("tc/tw_stamp")
int tw_stamp(struct __sk_buff *ctx)
{
 return vtep_timewait_stamp4(ctx, tw_netns_cookie) < 0 ? TC_ACT_SHOT : (-1);
}
/* A separate synthetic-verdict fixture, not production Cilium policy/CT.
 * Consume only a previously issued proof. Unknown ACKs fall through to the
 * existing fail-closed socket driver; never look up the current tuple owner.
 */
__section("tc/tw_route")
int tw_route(struct __sk_buff *ctx)
{
	struct vtep_socket_key key = { .netns_cookie = tw_netns_cookie };
	const struct tw_proof *found;
	struct vtep_socket_control control;
	struct bpf_tunnel_key tunnel = { .tunnel_id = 2, .tunnel_ttl = 64 };
	const struct vtep_socket_peer *destination;
	struct tw_route_stats *stats = tw_route_counters();
	struct tw_proof proof;
	struct ethhdr eth;
	__u8 mac[6] __align_stack_8;
	__u32 port, *verdict;
	__be32 peer;

	if (ctx_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0)
		return (-1);
	key.token = vtep_socket_decode4(eth.h_source);
	found = map_lookup_elem(&cilium_vtep_tw_proof4, &key);
	if (!key.token || !found)
		return (-1);
	proof = *found;
	if (map_delete_elem(&cilium_vtep_tw_proof4, &key))
		return TC_ACT_SHOT;
	port = bpf_ntohs(proof.reply.record.flow.client_port);
	verdict = map_lookup_elem(&handoff_policy, &port);
	if (!verdict || !(*verdict & 2) ||
	    !vtep_socket_control4(key.netns_cookie, &control) ||
	    proof.reply.record.owner.netns_cookie != key.netns_cookie ||
	    control.generation != proof.reply.record.owner.generation ||
	    proof.expires_ns <= ktime_get_ns() || !tw_packet_matches(ctx, &proof.reply) ||
	    !vtep_socket_origin4(proof.reply.record.owner.origin, proof.reply.record.owner.peer))
		goto deny;
	for (int i = 0; i < ETH_ALEN; i++)
		mac[i] = tw_pod_mac[i];
	if (ctx_store_bytes(ctx, ETH_ALEN, mac, sizeof(mac), 0) < 0)
		goto deny;
	if (proof.reply.record.owner.origin == VTEP_SOCKET_NATIVE) {
		if (stats)
			__sync_fetch_and_add(&stats->native, 1);
		return TC_ACT_OK;
	}
	peer = proof.reply.record.owner.peer;
	destination = map_lookup_elem(&cilium_vtep_peers4, &peer);
	if (!destination || ctx_store_bytes(ctx, 0, destination->mac, ETH_ALEN, 0) < 0)
		goto deny;
	tunnel.remote_ipv4 = bpf_ntohl(peer);
	if (ctx_set_tunnel_key(ctx, &tunnel, sizeof(tunnel), 0) < 0)
		goto deny;
	if (stats)
		__sync_fetch_and_add(&stats->tunnel, 1);
	return ctx_redirect(ctx, tw_tunnel_ifindex, 0);
deny:
	if (stats)
		__sync_fetch_and_add(&stats->denied, 1);
	return TC_ACT_SHOT;
}


__section("tc/tw_collect")
int tw_collect_proofs(__maybe_unused struct __sk_buff *ctx)
{
 return vtep_timewait_collect4() < 0 ? TC_ACT_SHOT : TC_ACT_OK;
}
BPF_LICENSE("GPL");
