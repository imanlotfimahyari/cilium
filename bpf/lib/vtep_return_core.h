/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
/* This file was not reviewed by a human before submission */

#pragma once

#include "vtep_return_socket.h"
#ifdef ENABLE_VTEP_RETURN_COOKIE_AFFINITY
#include "vtep_return_cookie.h"
#endif
#ifdef ENABLE_VTEP_RETURN_TIMEWAIT_AFFINITY
#include "vtep_return_timewait.h"
#endif

static __always_inline bool vtep_core_enabled4(void)
{
	return CONFIG(enable_vtep) && CONFIG(enable_bpf_routing) &&
	       (CONFIG(tunnel_protocol) == TUNNEL_PROTOCOL_VXLAN ||
		(CONFIG(tunnel_protocol) == TUNNEL_PROTOCOL_GENEVE && !CONFIG(dsr_cfg).enable));
}

/* Integration for selected direct-veth IPv4/TCP endpoints. The experimental
 * agent controller installs sockops and pre-queue attachments before publishing
 * namespace readiness and completing synchronous CNI ADD.
 * Direct pod traffic uses the configured VXLAN or Geneve overlay.
 */
static __always_inline int
vtep_core_admit4(struct __ctx_buff *ctx, bool from_tunnel, __u32 source_identity, __u16 proxy_port,
		bool translated)
{
	struct bpf_tunnel_key tunnel = {};
	struct iphdr ip;
	struct tcphdr tcp;
	__be32 peer = 0;
	__u32 origin = VTEP_SOCKET_NATIVE;

	if (ctx_load_bytes(ctx, ETH_HLEN, &ip, sizeof(ip)) < 0)
		return DROP_INVALID;
	if (ip.protocol != IPPROTO_TCP)
		return CTX_ACT_OK;
	if (ip.ihl != 5 || (ip.frag_off & bpf_htons(0x3fff)) ||
	    ctx_load_bytes(ctx, ETH_HLEN + sizeof(ip), &tcp, sizeof(tcp)) < 0)
		return DROP_INVALID;
#ifndef ENABLE_VTEP_RETURN_COOKIE_AFFINITY
	if (!tcp.syn || tcp.ack)
		return CTX_ACT_OK;
#else
	if ((!tcp.syn || tcp.ack) && (!tcp.ack || tcp.syn || tcp.rst || tcp.fin))
		return CTX_ACT_OK;
#endif
	if (!vtep_core_enabled4() || proxy_port || translated ||
	    tc_index_from_ingress_proxy(ctx) || tc_index_from_egress_proxy(ctx))
		return DROP_INVALID;
	if (from_tunnel) {
		if (ctx_get_tunnel_key(ctx, &tunnel, sizeof(tunnel), 0) < 0)
			return DROP_NO_TUNNEL_KEY;
		peer = bpf_htonl(tunnel.remote_ipv4);
		if (!peer)
			return DROP_NO_TUNNEL_ENDPOINT;
		if (map_lookup_elem(&cilium_vtep_peers4, &peer)) {
			if (tunnel.tunnel_id != WORLD_ID)
				return DROP_NO_TUNNEL_KEY;
			origin = VTEP_SOCKET_TUNNEL;
		} else {
			const struct remote_endpoint_info *info;

			/* Ordinary inter-node pod traffic also arrives through the overlay.
			 * Only the authoritative IP cache may classify it as native:
			 * require source address, identity, VNI and exact node peer to
			 * agree. An unknown WORLD tunnel never acquires native status.
			 */
			info = lookup_ip4_remote_endpoint(ip.saddr, 0);
			if (!source_identity || identity_is_world(source_identity) ||
			    source_identity == HOST_ID || !info ||
			    info->sec_identity != source_identity ||
			    get_id_from_tunnel_id(tunnel.tunnel_id, bpf_htons(ETH_P_IP)) != source_identity ||
			    !info->flag_has_tunnel_ep || info->flag_ipv6_tunnel_ep ||
			    info->tunnel_endpoint.ip4.be32 != peer)
				return DROP_NO_TUNNEL_ENDPOINT;
			peer = 0;
		}
	}
	/* ipv4_policy has returned its normal verdict by this point. The caller
	 * has already performed local delivery's final Ethernet rewrite.
	 */
#ifdef ENABLE_VTEP_RETURN_COOKIE_AFFINITY
	if (!tcp.syn || tcp.ack)
		return vtep_cookie_admit_ack4(ctx, CONFIG(endpoint_netns_cookie), origin, peer, &ip, &tcp) ?
			DROP_INVALID : CTX_ACT_OK;
#endif
	if (vtep_socket_admit4(ctx, CONFIG(endpoint_netns_cookie), origin, peer, true))
		return DROP_INVALID;
	return CTX_ACT_OK;
}

/* Resolve ownership against the socket-side packet before any address or
 * port rewrite. On success, a zero peer denotes native ownership. Flow
 * admission still depends on the normal policy and conntrack verdicts.
 */
static __always_inline int
vtep_core_reply_peer4(struct __ctx_buff *ctx, __be32 *peer)
{
	int action;

	*peer = 0;
	if (!vtep_core_enabled4())
		return DROP_INVALID;
#ifdef ENABLE_VTEP_RETURN_TIMEWAIT_AFFINITY
	{
		bool claimed;

		action = vtep_timewait_reply4(ctx, CONFIG(endpoint_netns_cookie), peer, &claimed);
		if (!claimed)
			action = vtep_socket_reply4(ctx, CONFIG(endpoint_netns_cookie), true, peer);
	}
#else
	action = vtep_socket_reply4(ctx, CONFIG(endpoint_netns_cookie), true, peer);
#endif
#ifdef ENABLE_VTEP_RETURN_COOKIE_AFFINITY
	if (action == VTEP_SOCKET_DROP)
		action = vtep_cookie_reply4(ctx, CONFIG(endpoint_netns_cookie), peer, true);
#endif
	return action == VTEP_SOCKET_DROP ? DROP_INVALID : CTX_ACT_OK;
}

/* Encapsulation uses the proven peer. Native connections continue through
 * ordinary Cilium routing, and failed ownership proofs never reach here.
 */
static __always_inline int
vtep_core_forward_reply4(struct __ctx_buff *ctx, struct trace_ctx *trace, __be32 peer)
{
	struct remote_endpoint_info info = {};
	const struct vtep_socket_peer *destination;
	union macaddr source = CONFIG(interface_mac);

	if (eth_store_saddr(ctx, source.addr, 0) < 0)
		return DROP_WRITE_ERROR;
	if (!peer)
		return CTX_ACT_OK;
	destination = map_lookup_elem(&cilium_vtep_peers4, &peer);
	if (!destination)
		return DROP_NO_TUNNEL_ENDPOINT;
	if (eth_store_daddr(ctx, destination->mac, 0) < 0)
		return DROP_WRITE_ERROR;
	info.tunnel_endpoint.ip4.be32 = peer;
	info.flag_has_tunnel_ep = true;
	return __encap_and_redirect_with_nodeid(ctx, &info, SECLABEL_IPV4,
					      world_ipv4_id(), world_ipv4_id(), trace,
					      bpf_htons(ETH_P_IP));
}

static __always_inline int
vtep_core_reply4(struct __ctx_buff *ctx, struct trace_ctx *trace)
{
	__be32 peer;
	int ret;

	ret = vtep_core_reply_peer4(ctx, &peer);
	if (IS_ERR(ret))
		return ret;

	return vtep_core_forward_reply4(ctx, trace, peer);
}
