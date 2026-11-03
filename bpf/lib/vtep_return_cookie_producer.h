/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#pragma once

#include "vtep_return_cookie.h"
#include "vtep_return_timewait_owner.h"

static long BPF_FUNC(probe_read_kernel, void *dst, __u32 size, const void *src);
struct sk_buff {
	unsigned char *head;
	__u16 mac_header, network_header, transport_header;
} __attribute__((preserve_access_index));
struct tcp_sock { __u32 rcv_nxt, snd_una; } __attribute__((preserve_access_index));

/* ctx[6] is the newly constructed SYN-ACK skb, ctx[5] the original SYN.
 * The loader checks the six-argument ABI and enum TCP_SYNACK_COOKIE=2.
 * Cookie skbs intentionally have no request socket attached. Do not guess one.
 */
__section("fexit/tcp_make_synack")
int ck_synack_created(__u64 *ctx)
{
	struct sock *listener = (void *)ctx[0];
	struct sk_buff *syn = (void *)ctx[5], *packet = (void *)ctx[6];
	struct vtep_socket_saved_syn headers;
	struct vtep_socket_control control;
	struct vtep_cookie_packet association = {};
	const struct vtep_socket_ticket *ticket;
	struct vtep_cookie_stats *stats;
	struct tcphdr tcp;
	__u64 identity = ctx[6], netns;

	if (ctx[4] != 2 || !listener || !syn || !packet ||
	    listener->__sk_common.skc_state != 10)
		return 0;
	netns = listener->__sk_common.skc_net.net->net_cookie;
	if (!vtep_socket_control4(netns, &control))
		return 0;
	stats = vtep_cookie_stats4();
	if (probe_read_kernel(&headers, sizeof(headers), syn->head + syn->mac_header) ||
	    probe_read_kernel(&tcp, sizeof(tcp), packet->head + packet->transport_header) ||
	    headers.eth.h_proto != bpf_htons(ETH_P_IP) || headers.ip.version != 4 ||
	    headers.ip.ihl != 5 || headers.ip.protocol != IPPROTO_TCP ||
	    (headers.ip.frag_off & bpf_htons(0x3fff)) ||
	    !headers.tcp.syn || headers.tcp.ack || headers.tcp.fin || headers.tcp.rst ||
	    !tcp.syn || !tcp.ack || tcp.rst || tcp.fin ||
	    tcp.source != headers.tcp.dest || tcp.dest != headers.tcp.source ||
	    bpf_ntohl(tcp.ack_seq) != bpf_ntohl(headers.tcp.seq) + 1)
		goto reject;
	association.ticket.netns_cookie = netns;
	association.ticket.token = vtep_socket_decode4(headers.eth.h_source);
	if (!association.ticket.token)
		goto reject;
	ticket = map_lookup_elem(&cilium_vtep_admit4, &association.ticket);
	if (!ticket || ticket->generation != control.generation || ticket->request_cookie ||
	    ticket->expires_ns <= ktime_get_ns() || ticket->origin != VTEP_SOCKET_TUNNEL ||
	    !ticket->peer || !map_lookup_elem(&cilium_vtep_peers4, &ticket->peer) ||
	    ticket->flow.pod_addr != headers.ip.daddr || ticket->flow.client_addr != headers.ip.saddr ||
	    ticket->flow.pod_port != headers.tcp.dest || ticket->flow.client_port != headers.tcp.source ||
	    ticket->flow.syn_seq != headers.tcp.seq)
		goto reject;
	association.key.netns = netns;
	association.key.generation = control.generation;
	association.key.local = headers.ip.daddr;
	association.key.remote = headers.ip.saddr;
	association.key.local_port = tcp.source;
	association.key.remote_port = tcp.dest;
	association.key.client_isn = bpf_ntohl(headers.tcp.seq);
	association.key.server_isn = bpf_ntohl(tcp.seq);
	if (!cookie_peer_issue(&association.key, ticket->peer, jiffies64(), VTEP_COOKIE_PERIOD))
		goto reject;
	if (map_update_elem(&ck_output_packet, &identity, &association, BPF_NOEXIST)) {
		/* A stale pointer collision must invalidate, never authorize a reuse. */
		map_delete_elem(&ck_output_packet, &identity);
		if (stats)
			__sync_fetch_and_add(&stats->pressure, 1);
		return 0;
	}
	if (stats)
		__sync_fetch_and_add(&stats->issued, 1);
	return 0;
reject:
	if (stats)
		__sync_fetch_and_add(&stats->rejected, 1);
	return 0; /* No packet association: the pre-queue guard drops the SYN-ACK. */
}

/* Kernel has already validated the cookie and returned the actual child.
 * Do not dereference request_sock: it may have been freed before this return.
 */
__section("fexit/tcp_get_cookie_sock")
int ck_child_created(__u64 *ctx)
{
	struct sock *listener = (void *)ctx[0], *child = (void *)ctx[4];
	struct sk_buff *skb = (void *)ctx[1];
	struct tcp_sock *tp = (void *)child;
	struct vtep_socket_saved_syn headers;
	struct vtep_socket_control control;
	struct vtep_socket_key token = {};
	struct vtep_cookie_ack proof, *marker;
	const struct vtep_cookie_ack *found;
	struct vtep_cookie_stats *stats;
	struct cookie_peer_key actual;
	__u64 netns;
	__u32 rcv_nxt = 0, snd_una = 0;

	if (!listener || !child || !skb)
		return 0;
	netns = listener->__sk_common.skc_net.net->net_cookie;
	if (!vtep_socket_control4(netns, &control))
		return 0;
	stats = vtep_cookie_stats4();
	if (listener->__sk_common.skc_state != 10 || child->__sk_common.skc_state != 3 ||
	    child->__sk_common.skc_net.net->net_cookie != netns ||
	    (child->__sk_common.skc_family != AF_INET && child->__sk_common.skc_family != AF_INET6) ||
	    probe_read_kernel(&headers, sizeof(headers), skb->head + skb->mac_header) ||
	    probe_read_kernel(&rcv_nxt, sizeof(rcv_nxt), &tp->rcv_nxt) ||
	    probe_read_kernel(&snd_una, sizeof(snd_una), &tp->snd_una) ||
	    headers.eth.h_proto != bpf_htons(ETH_P_IP) || headers.ip.version != 4 ||
	    headers.ip.ihl != 5 || headers.ip.protocol != IPPROTO_TCP ||
	    (headers.ip.frag_off & bpf_htons(0x3fff)) ||
	    !headers.tcp.ack || headers.tcp.syn || headers.tcp.rst || headers.tcp.fin ||
	    headers.ip.saddr != child->__sk_common.skc_daddr ||
	    headers.ip.daddr != child->__sk_common.skc_rcv_saddr ||
	    headers.tcp.source != child->__sk_common.skc_dport ||
	    headers.tcp.dest != bpf_htons(child->__sk_common.skc_num) ||
	    bpf_ntohl(headers.tcp.seq) != rcv_nxt || bpf_ntohl(headers.tcp.ack_seq) != snd_una)
		goto reject;
	token.netns_cookie = netns;
	token.token = vtep_socket_decode4(headers.eth.h_source);
	if (!token.token)
		goto reject;
	found = map_lookup_elem(&cilium_vtep_ck_ack4, &token);
	if (!found)
		goto reject;
	proof = *found;
	if (map_delete_elem(&cilium_vtep_ck_ack4, &token))
		goto reject;
	actual = vtep_cookie_key4(netns, control.generation, &headers.ip, &headers.tcp, true);
	if (proof.reserved || proof.expires_ns <= ktime_get_ns() ||
	    memcmp(&actual, &proof.key, sizeof(actual)) || !proof.peer ||
	    !map_lookup_elem(&cilium_vtep_peers4, &proof.peer) ||
	    !cookie_peer_consume(&actual, proof.peer, jiffies64()))
		goto reject;
	marker = sk_storage_get(&vtep_ck_child4, (void *)child, &proof, BPF_SK_STORAGE_GET_F_CREATE);
	if (!marker || marker->key.netns != netns || marker->key.generation != control.generation ||
	    marker->peer != proof.peer)
		goto reject;
	return 0;
reject:
	if (stats)
		__sync_fetch_and_add(&stats->rejected, 1);
	return 0;
}

/* Positive means the exact cookie skb was stamped. Zero means ordinary path;
 * negative refuses. SYN-ACKs without any valid producer remain fail-closed.
 */
static __always_inline int vtep_cookie_stamp4(struct __sk_buff *ctx, __u64 netns)
{
	__u64 identity = (__u64)ctx;
	const struct vtep_cookie_packet *found;
	struct vtep_cookie_packet packet;
	struct vtep_socket_control control;
	struct cookie_peer_key actual;
	struct iphdr ip;
	struct tcphdr tcp;
	__u8 mac[6] __align_stack_8;
	__be32 peer;

	found = map_lookup_elem(&ck_output_packet, &identity);
	if (!found)
		return 0;
	packet = *found;
	map_delete_elem(&ck_output_packet, &identity);
	if (packet.ticket.netns_cookie != netns || !vtep_socket_control4(netns, &control) ||
	    packet.key.generation != control.generation)
		return -EPERM;
	if (ctx_load_bytes(ctx, sizeof(struct ethhdr), &ip, sizeof(ip)) < 0 ||
	    ctx_load_bytes(ctx, sizeof(struct ethhdr) + sizeof(ip), &tcp, sizeof(tcp)) < 0)
		return -EPERM;
	actual = vtep_cookie_key4(netns, control.generation, &ip, &tcp, false);
	if (memcmp(&actual, &packet.key, sizeof(actual)))
		return -EPERM;
	vtep_socket_encode4(packet.ticket.token, mac);
	if (ctx_store_bytes(ctx, ETH_ALEN, mac, sizeof(mac), 0) < 0 ||
	    vtep_cookie_reply4(ctx, netns, &peer, false) != VTEP_SOCKET_REDIRECT)
		return -EPERM;
	return 1;
}
