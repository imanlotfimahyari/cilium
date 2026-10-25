/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#define TUNNEL_MODE 1
#define ENCAP_IFINDEX 1
#define ENABLE_VTEP_RETURN_SOCKET_AFFINITY 1
#define VTEP_SOCKET_MAX_TICKETS 8

/* ProgRun cannot supply outer tunnel metadata. Only that kernel helper is
 * substituted here; endpoint entrypoints, CT and policy lookups are Cilium's.
 * The separate live suite tests actual VXLAN metadata and socket ownership.
 */
static __u32 test_remote, test_vni;
static __always_inline int
test_tunnel_key(__maybe_unused struct __sk_buff *ctx, struct bpf_tunnel_key *key,
		__maybe_unused __u32 size, __maybe_unused __u64 flags)
{
	key->remote_ipv4 = test_remote;
	key->tunnel_id = test_vni;
	return 0;
}
#undef ctx_get_tunnel_key
#define ctx_get_tunnel_key test_tunnel_key

#include "lib/bpf_lxc.h"
#include "lib/policy.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_two })
ASSIGN_CONFIG(__u64, endpoint_netns_cookie, 10)
ASSIGN_CONFIG(bool, enable_vtep, true)
ASSIGN_CONFIG(bool, enable_bpf_routing, true)
ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_VXLAN)

static __always_inline int make_syn(struct __ctx_buff *ctx, __u16 port, bool egress)
{
	struct pktgen builder;
	struct tcphdr *tcp;

	pktgen__init(&builder, ctx);
	tcp = pktgen__push_ipv4_tcp_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
					  egress ? v4_pod_two : v4_pod_one,
					  egress ? v4_pod_one : v4_pod_two,
					  bpf_htons(port), bpf_htons(8080));
	if (!tcp)
		return TEST_ERROR;
	tcp->syn = 1;
	tcp->seq = bpf_htonl(123);
	pktgen__finish(&builder);
	return 0;
}

#define INGRESS_CASE(name, port, allowed, tunneled, known_peer, vni, ready, proxy) \
PKTGEN(PROG_TYPE, #name) \
int name ## _packet(struct __ctx_buff *ctx) \
{ \
	return make_syn(ctx, port, false); \
} \
SETUP(PROG_TYPE, #name) \
int name ## _setup(struct __ctx_buff *ctx) \
{ \
	__u64 ns = 10, nonce = 0; \
	__be32 peer = v4_node_one; \
	struct vtep_socket_control control = { .generation = 1, .ticket_ttl_ns = 30000000000ULL, \
		.phase = ready ? VTEP_SOCKET_READY : VTEP_SOCKET_RETIRED }; \
	struct vtep_socket_key key = { .netns_cookie = ns, .token = 1 }; \
	struct vtep_socket_peer destination = {}; \
	map_delete_elem(&cilium_vtep_admit4, &key); \
	map_update_elem(&cilium_vtep_sock_ctl4, &ns, &control, BPF_ANY); \
	map_update_elem(&cilium_vtep_nonce4, &ns, &nonce, BPF_ANY); \
	map_update_elem(&cilium_vtep_peers4, &peer, &destination, BPF_ANY); \
	test_remote = bpf_ntohl(known_peer ? v4_node_one : v4_node_two); \
	test_vni = vni; \
	policy_add_entry(false, 0, 0, 0, 0, !allowed, proxy); \
	ctx_store_meta(ctx, CB_SRC_LABEL, WORLD_IPV4_ID); \
	ctx_store_meta(ctx, CB_DELIVERY_FLAGS, tunneled ? CB_DELIVERY_FLAGS_FROM_TUNNEL : 0); \
	return pod_receive_packet_by_tailcall(ctx); \
} \
CHECK(PROG_TYPE, #name) \
int name ## _check(struct __ctx_buff *ctx) \
{ \
	struct vtep_socket_key key = { .netns_cookie = 10, .token = 1 }; \
	const struct vtep_socket_ticket *ticket; \
	__u8 source[6] __align_stack_8; \
	__u32 status; \
	bool success = allowed && known_peer && vni == WORLD_ID && ready && !proxy; \
	test_init(); \
	assert(ctx_load_bytes(ctx, 0, &status, sizeof(status)) == 0); \
	assert(status == (success ? CTX_ACT_OK : CTX_ACT_DROP)); \
	ticket = map_lookup_elem(&cilium_vtep_admit4, &key); \
	assert((ticket != NULL) == success); \
	assert(ctx_load_bytes(ctx, sizeof(status) + ETH_ALEN, source, sizeof(source)) == 0); \
	if (success && ticket) { \
		assert(ticket->origin == (tunneled ? VTEP_SOCKET_TUNNEL : VTEP_SOCKET_NATIVE)); \
		assert(ticket->peer == (tunneled ? v4_node_one : 0)); \
		assert(ticket->flow.pod_addr == v4_pod_two); \
		assert(ticket->flow.client_addr == v4_pod_one); \
		assert(vtep_socket_decode4(source) == 1); \
	} else { \
		assert(memcmp(source, (const void *)mac_one, ETH_ALEN) == 0); \
	} \
	test_finish(); \
}

INGRESS_CASE(core_ingress_allowed, 41001, true, true, true, WORLD_ID, true, 0)
INGRESS_CASE(core_ingress_denied, 41002, false, true, true, WORLD_ID, true, 0)
INGRESS_CASE(core_native_allowed, 41003, true, false, true, WORLD_ID, true, 0)
INGRESS_CASE(core_unknown_peer, 41004, true, true, false, WORLD_ID, true, 0)
INGRESS_CASE(core_wrong_vni, 41005, true, true, true, 1234, true, 0)
INGRESS_CASE(core_unready, 41006, true, true, true, WORLD_ID, false, 0)
INGRESS_CASE(core_proxy_excluded, 41007, true, true, true, WORLD_ID, true, bpf_htons(15000))

#define EGRESS_CASE(name, port, denied) \
PKTGEN(PROG_TYPE, #name) \
int name ## _packet(struct __ctx_buff *ctx) { return make_syn(ctx, port, true); } \
SETUP(PROG_TYPE, #name) \
int name ## _setup(struct __ctx_buff *ctx) \
{ \
	policy_add_entry(true, 0, 0, 0, 0, denied, 0); \
	return pod_send_packet(ctx); \
} \
CHECK(PROG_TYPE, #name) \
int name ## _check(struct __ctx_buff *ctx) \
{ \
	struct metrics_key key = { .reason = -DROP_POLICY_DENY, .dir = METRIC_EGRESS }; \
	__u32 status; \
	test_init(); \
	assert(ctx_load_bytes(ctx, 0, &status, sizeof(status)) == 0); \
	assert(status == CTX_ACT_DROP); \
	if (denied) \
		assert_metrics_count(key, 1); \
	else { \
		key.reason = -DROP_INVALID; \
		assert_metrics_count(key, 1); \
	} \
	test_finish(); \
}

EGRESS_CASE(core_egress_denied, 41008, true)
EGRESS_CASE(core_egress_unknown_owner, 41009, false)

#include "lib/ipcache.h"

#define CLUSTER_CASE(name, port, cached_id, tunnel_node, packet_node, vni, allowed) \
PKTGEN(PROG_TYPE, #name) \
int name ## _packet(struct __ctx_buff *ctx) { return make_syn(ctx, port, false); } \
SETUP(PROG_TYPE, #name) \
int name ## _setup(struct __ctx_buff *ctx) \
{ \
 __u64 ns = 10, nonce = 0; \
 struct vtep_socket_control control = { .generation = 1, .ticket_ttl_ns = 30000000000ULL, .phase = VTEP_SOCKET_READY }; \
 struct vtep_socket_key key = { .netns_cookie = 10, .token = 1 }; \
 map_delete_elem(&cilium_vtep_admit4, &key); \
 map_update_elem(&cilium_vtep_sock_ctl4, &ns, &control, BPF_ANY); \
 map_update_elem(&cilium_vtep_nonce4, &ns, &nonce, BPF_ANY); \
 ipcache_v4_add_entry(v4_pod_one, 0, cached_id, tunnel_node, 0); \
 test_remote = bpf_ntohl(packet_node); test_vni = vni; \
 policy_add_entry(false, 0, 0, 0, 0, false, 0); \
 ctx_store_meta(ctx, CB_SRC_LABEL, 1234); \
 ctx_store_meta(ctx, CB_DELIVERY_FLAGS, CB_DELIVERY_FLAGS_FROM_TUNNEL); \
 return pod_receive_packet_by_tailcall(ctx); \
} \
CHECK(PROG_TYPE, #name) \
int name ## _check(struct __ctx_buff *ctx) \
{ \
 struct vtep_socket_key key = { .netns_cookie = 10, .token = 1 }; \
 const struct vtep_socket_ticket *ticket; \
 __u32 status; \
 test_init(); \
 assert(ctx_load_bytes(ctx, 0, &status, sizeof(status)) == 0); \
 assert(status == (allowed ? CTX_ACT_OK : CTX_ACT_DROP)); \
 ticket = map_lookup_elem(&cilium_vtep_admit4, &key); \
 assert((ticket != NULL) == allowed); \
 if (allowed && ticket) { assert(ticket->origin == VTEP_SOCKET_NATIVE); assert(ticket->peer == 0); } \
 test_finish(); \
}

CLUSTER_CASE(core_cluster_native, 41100, 1234, v4_node_two, v4_node_two, 1234, true)
CLUSTER_CASE(core_cluster_wrong_identity, 41101, 5678, v4_node_two, v4_node_two, 1234, false)
CLUSTER_CASE(core_cluster_wrong_peer, 41102, 1234, v4_node_one, v4_node_two, 1234, false)
CLUSTER_CASE(core_cluster_wrong_vni, 41103, 1234, v4_node_two, v4_node_two, 5678, false)
CLUSTER_CASE(core_cluster_world_not_native, 41104, WORLD_IPV4_ID, v4_node_two, v4_node_two, WORLD_ID, false)
CLUSTER_CASE(core_cluster_missing_identity, 41105, 0, v4_node_two, v4_node_two, 1234, false)
