/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Experimental direct-veth IPv4/TCP hand-off.
 * Call admission only after peer validation and ingress policy, after the last
 * source-MAC rewrite, immediately before local delivery. MAC is an opaque
 * admission token, not a peer address or authorization by itself. Linux
 * TCP_SAVE_SYN=2 keeps it with the actual request and accepted socket.
 */
#ifndef ENABLE_VTEP_RETURN_SOCKET_AFFINITY
#error "VTEP socket ownership is an opt-in experiment"
#endif

#include <bpf/api.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include "endian.h"
#include "socket.h"

#ifndef VTEP_SOCKET_MAX_TICKETS
#define VTEP_SOCKET_MAX_TICKETS 4096
#endif

#define VTEP_SOCKET_READY 1
#define VTEP_SOCKET_RETIRED 2
#define VTEP_SOCKET_NATIVE 1
#define VTEP_SOCKET_TUNNEL 2
#define VTEP_SOCKET_PASS 0
#define VTEP_SOCKET_REDIRECT 1
#define VTEP_SOCKET_DROP 2
#define VTEP_SOCKET_NONCE_MAX ((1ULL << 46) - 1)
#define VTEP_SOCKET_TCP_SAVE_SYN 27
#define VTEP_SOCKET_ENOSPC 28

static void *BPF_FUNC(sk_storage_get, const void *map, struct bpf_sock *sk,
		     void *value, __u64 flags);
static struct bpf_sock *BPF_FUNC(sk_fullsock, struct bpf_sock *sk);
static int BPF_FUNC(sock_ops_cb_flags_set, struct bpf_sock_ops *ctx, int flags);

struct vtep_socket_control {
	__u64 generation;
	__u64 ticket_ttl_ns;
	__u32 phase;
	__u32 reserved;
};

struct vtep_socket_key {
	__u64 netns_cookie;
	__u64 token;
};

struct vtep_socket_flow {
	__be32 pod_addr;
	__be32 client_addr;
	__be16 pod_port;
	__be16 client_port;
	__be32 syn_seq;
};

struct vtep_socket_ticket {
	__u64 generation;
	__u64 expires_ns;
	__u64 request_cookie;
	__be32 peer;
	__u32 origin;
	struct vtep_socket_flow flow;
};

struct vtep_socket_request {
	struct vtep_socket_ticket ticket;
	__u64 nonce;
};

struct vtep_socket_owner {
	__u64 netns_cookie;
	__u64 generation;
	__u64 socket_cookie;
	__be32 peer;
	__u32 origin;
};

struct vtep_socket_peer {
	__u8 mac[6];
	__u8 reserved[2];
};

/* Exact configured outer endpoint -> inner destination MAC. A client-prefix
 * lookup cannot disambiguate external peers which share a client prefix.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __be32);
	__type(value, struct vtep_socket_peer);
} cilium_vtep_peers4 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u64);
	__type(value, struct vtep_socket_control);
} cilium_vtep_sock_ctl4 __section_maps_btf;

/* Separate from control updates: replacing readiness must not reset or race
 * the admission counter. Initialize once before READY, pin/reuse, never reset
 * for a surviving namespace. Saturation rejects admission; it never wraps.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u64);
	__type(value, __u64);
} cilium_vtep_nonce4 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VTEP_SOCKET_MAX_TICKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, struct vtep_socket_key);
	__type(value, struct vtep_socket_ticket);
} cilium_vtep_admit4 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VTEP_SOCKET_MAX_TICKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, struct vtep_socket_key);
	__type(value, struct vtep_socket_request);
} cilium_vtep_req4 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, int);
	__type(value, struct vtep_socket_owner);
} cilium_vtep_sock4 __section_maps_btf;

static __always_inline bool
vtep_socket_control4(__u64 netns, struct vtep_socket_control *out)
{
	const struct vtep_socket_control *c;

	c = map_lookup_elem(&cilium_vtep_sock_ctl4, &netns);
	if (!netns || !c)
		return false;
	*out = *c;
	return out->generation && out->ticket_ttl_ns && !out->reserved &&
	       out->phase == VTEP_SOCKET_READY;
}

static __always_inline bool vtep_socket_origin4(__u32 origin, __be32 peer)
{
	return (origin == VTEP_SOCKET_NATIVE && !peer) ||
	       (origin == VTEP_SOCKET_TUNNEL && peer);
}

static __always_inline __u64 vtep_socket_nonce4(__u64 netns)
{
	__u64 *counter, previous;

	counter = map_lookup_elem(&cilium_vtep_nonce4, &netns);
	if (!counter)
		return 0;
#pragma unroll
	for (int i = 0; i < 8; i++) {
		previous = *counter;
		if (previous >= VTEP_SOCKET_NONCE_MAX)
			return 0;
		if (__sync_val_compare_and_swap(counter, previous, previous + 1) == previous)
			return previous + 1;
	}
	return 0; /* Bounded contention rejects this admission. */
}

static __always_inline __u64 vtep_socket_decode4(const __u8 mac[6])
{
	if ((mac[0] & 3) != 2)
		return 0;
	return ((__u64)(mac[0] >> 2) << 40) | ((__u64)mac[1] << 32) |
	       ((__u64)mac[2] << 24) | ((__u64)mac[3] << 16) |
	       ((__u64)mac[4] << 8) | mac[5];
}

static __always_inline void vtep_socket_encode4(__u64 nonce, __u8 mac[6])
{
	mac[0] = (__u8)((nonce >> 40) << 2) | 2;
	mac[1] = (__u8)(nonce >> 32);
	mac[2] = (__u8)(nonce >> 24);
	mac[3] = (__u8)(nonce >> 16);
	mac[4] = (__u8)(nonce >> 8);
	mac[5] = (__u8)nonce;
}

/* Caller has validated the configured outer peer/VNI (or explicit native
 * origin), selected the endpoint, and obtained the normal ingress verdict.
 * This helper changes only Ethernet source bytes: no IP, TCP or client SNAT.
 */
static __always_inline int
vtep_socket_admit4(struct __sk_buff *ctx, __u64 netns, __u32 origin,
		   __be32 peer, bool policy_allowed)
{
	struct vtep_socket_control control, after;
	struct vtep_socket_ticket ticket = {};
	struct vtep_socket_key key = { .netns_cookie = netns };
	struct iphdr ip;
	struct tcphdr tcp;
	__u8 mac[6] __align_stack_8;
	__u64 now;
	int ret;

	if (!policy_allowed || !vtep_socket_origin4(origin, peer) ||
	    !vtep_socket_control4(netns, &control))
		return -EPERM;
	if (ctx_load_bytes(ctx, sizeof(struct ethhdr), &ip, sizeof(ip)) < 0 ||
	    ip.version != 4 || ip.ihl != 5 || ip.protocol != IPPROTO_TCP ||
	    (ip.frag_off & bpf_htons(0x3fff)) ||
	    ctx_load_bytes(ctx, sizeof(struct ethhdr) + sizeof(ip), &tcp, sizeof(tcp)) < 0 ||
	    tcp.doff < 5 || !tcp.syn || tcp.ack || tcp.fin || tcp.rst ||
	    bpf_ntohs(ip.tot_len) != sizeof(ip) + (__u32)tcp.doff * 4)
		return -EINVAL; /* No fragments, IP options or SYN payload/TFO. */
	key.token = vtep_socket_nonce4(netns);
	if (!key.token)
		return -VTEP_SOCKET_ENOSPC;
	now = ktime_get_ns();
	if (control.ticket_ttl_ns > ~0ULL - now)
		return -EINVAL;
	ticket.generation = control.generation;
	ticket.expires_ns = now + control.ticket_ttl_ns;
	ticket.peer = peer;
	ticket.origin = origin;
	ticket.flow.pod_addr = ip.daddr;
	ticket.flow.client_addr = ip.saddr;
	ticket.flow.pod_port = tcp.dest;
	ticket.flow.client_port = tcp.source;
	ticket.flow.syn_seq = tcp.seq;
	ret = map_update_elem(&cilium_vtep_admit4, &key, &ticket, BPF_NOEXIST);
	if (ret)
		return ret;
	vtep_socket_encode4(key.token, mac);
	if (ctx_store_bytes(ctx, ETH_ALEN, mac, sizeof(mac), 0) < 0 ||
	    !vtep_socket_control4(netns, &after) || after.generation != control.generation) {
		map_delete_elem(&cilium_vtep_admit4, &key);
		return -EPERM;
	}
	return 0;
}

struct vtep_socket_saved_syn {
	struct ethhdr eth;
	struct iphdr ip;
	struct tcphdr tcp;
} __packed;

static __always_inline bool
vtep_socket_saved4(struct bpf_sock_ops *ctx, __u64 netns,
		   struct vtep_socket_key *key, struct vtep_socket_ticket *ticket)
{
	struct vtep_socket_saved_syn syn = {};
	struct vtep_socket_control control;
	const struct vtep_socket_ticket *found;
	int ret;

	ret = get_socket_opt(ctx, IPPROTO_TCP, TCP_BPF_SYN_MAC, &syn, sizeof(syn));
	/* Options can make the complete saved SYN longer; the copied fixed
	 * headers still contain all fields used for binding the ticket.
	 */
	if ((ret < (int)sizeof(syn) && ret != -VTEP_SOCKET_ENOSPC) ||
	    syn.eth.h_proto != bpf_htons(ETH_P_IP) || syn.ip.version != 4 || syn.ip.ihl != 5 ||
	    syn.ip.protocol != IPPROTO_TCP || !syn.tcp.syn || syn.tcp.ack ||
	    syn.ip.daddr != ctx->local_ip4 || syn.ip.saddr != ctx->remote_ip4 ||
	    syn.tcp.dest != bpf_htons((__u16)ctx->local_port) ||
	    syn.tcp.source != bpf_htons((__u16)bpf_ntohl(ctx->remote_port)))
		return false;
	key->netns_cookie = netns;
	key->token = vtep_socket_decode4(syn.eth.h_source);
	if (!key->token || !vtep_socket_control4(netns, &control))
		return false;
	found = map_lookup_elem(&cilium_vtep_admit4, key);
	if (!found)
		return false;
	*ticket = *found;
	return ticket->generation == control.generation &&
	       ticket->expires_ns > ktime_get_ns() &&
	       vtep_socket_origin4(ticket->origin, ticket->peer) &&
	       ticket->flow.pod_addr == syn.ip.daddr && ticket->flow.client_addr == syn.ip.saddr &&
	       ticket->flow.pod_port == syn.tcp.dest && ticket->flow.client_port == syn.tcp.source &&
	       ticket->flow.syn_seq == syn.tcp.seq;
}

static __always_inline bool
vtep_socket_publish4(struct bpf_sock *sk, const struct vtep_socket_owner *initial)
{
	const struct vtep_socket_owner *owner;

	owner = sk_storage_get(&cilium_vtep_sock4, sk, (void *)initial,
			       BPF_SK_STORAGE_GET_F_CREATE);
	return owner && owner->netns_cookie == initial->netns_cookie &&
	       owner->generation == initial->generation && owner->socket_cookie == initial->socket_cookie &&
	       owner->origin == initial->origin && owner->peer == initial->peer;
}

/* Linux can accept IPv4 on an AF_INET6 listener without assigning an IPv6
 * address to the pod. Enable saving on the listener, then require both child
 * addresses to be IPv4-mapped and consistent with the kernel's IPv4 fields.
 * This does not enable IPv6 forwarding or infer an owner from an address.
 */
static __always_inline bool vtep_socket_ipv4_context4(struct bpf_sock_ops *ctx)
{
	if (ctx->family == AF_INET)
		return true;
	if (ctx->family != AF_INET6)
		return false;
	if (ctx->op == BPF_SOCK_OPS_TCP_LISTEN_CB)
		return true;
	return ctx->local_ip4 && ctx->remote_ip4 &&
	       !ctx->local_ip6[0] && !ctx->local_ip6[1] &&
	       ctx->local_ip6[2] == bpf_htonl(0xffff) && ctx->local_ip6[3] == ctx->local_ip4 &&
	       !ctx->remote_ip6[0] && !ctx->remote_ip6[1] &&
	       ctx->remote_ip6[2] == bpf_htonl(0xffff) && ctx->remote_ip6[3] == ctx->remote_ip4;
}

/* Returns 0 on a successful relevant transition, negative on failed binding,
 * and 1 for an irrelevant callback. Failure never grants ordinary forwarding.
 */
static __always_inline int vtep_socket_sockops4(struct bpf_sock_ops *ctx)
{
	struct vtep_socket_key ticket_key = {}, request_key = {};
	struct vtep_socket_control control, after;
	struct vtep_socket_request request = {};
	struct vtep_socket_owner initial = {};
	struct vtep_socket_ticket *live;
	struct bpf_sock *sk = ctx->sk;
	const struct vtep_socket_request *existing;
	__u64 netns = get_netns_cookie(ctx), previous;
	int save = 2, ret;

	if (!vtep_socket_ipv4_context4(ctx) || !vtep_socket_control4(netns, &control))
		return 1;
	if (ctx->op == BPF_SOCK_OPS_TCP_LISTEN_CB) {
		ret = set_socket_opt(ctx, IPPROTO_TCP, VTEP_SOCKET_TCP_SAVE_SYN, &save, sizeof(save));
		if (ret)
			return ret;
		return sock_ops_cb_flags_set(ctx, ctx->bpf_sock_ops_cb_flags |
					     BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
	}
	initial.netns_cookie = netns;
	initial.generation = control.generation;
	initial.socket_cookie = get_socket_cookie(ctx);
	if (!initial.socket_cookie)
		return -EINVAL;
	if (ctx->op == BPF_SOCK_OPS_TCP_CONNECT_CB) {
		if (!sk || !ctx->is_fullsock)
			return -EINVAL;
		initial.origin = VTEP_SOCKET_NATIVE;
		return vtep_socket_publish4(sk, &initial) ? 0 : -EPERM;
	}
	if (ctx->op != BPF_SOCK_OPS_HDR_OPT_LEN_CB &&
	    ctx->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
		return 1;
	if (ctx->op == BPF_SOCK_OPS_HDR_OPT_LEN_CB &&
	    ((ctx->skb_tcp_flags & 0x12) != 0x12 ||
	     ctx->args[0] == BPF_WRITE_HDR_TCP_SYNACK_COOKIE))
		return 1; /* SYN cookies have no durable saved SYN in this mode. */
	if (!vtep_socket_saved4(ctx, netns, &ticket_key, &request.ticket))
		return -EPERM;
	if (ctx->op == BPF_SOCK_OPS_HDR_OPT_LEN_CB) {
		request_key.netns_cookie = netns;
		request_key.token = initial.socket_cookie;
		live = map_lookup_elem(&cilium_vtep_admit4, &ticket_key);
		if (!live)
			return -ENOENT;
		previous = __sync_val_compare_and_swap(&live->request_cookie, 0, request_key.token);
		if (previous && previous != request_key.token)
			return -EPERM;
		request.ticket.request_cookie = request_key.token;
		request.nonce = ticket_key.token;
		ret = map_update_elem(&cilium_vtep_req4, &request_key, &request, BPF_NOEXIST);
		if (ret) {
			existing = map_lookup_elem(&cilium_vtep_req4, &request_key);
			if (!existing || existing->nonce != request.nonce ||
			    existing->ticket.generation != request.ticket.generation ||
			    existing->ticket.peer != request.ticket.peer ||
			    existing->ticket.origin != request.ticket.origin)
				return ret;
		}
		/* A late request callback cannot leave an orphan after transfer/GC. */
		if (!map_lookup_elem(&cilium_vtep_admit4, &ticket_key) ||
		    !vtep_socket_control4(netns, &after) || after.generation != control.generation) {
			map_delete_elem(&cilium_vtep_req4, &request_key);
			return -EPERM;
		}
		return 0;
	}
	if (!sk || !ctx->is_fullsock || !request.ticket.request_cookie)
		return -EINVAL;
	initial.peer = request.ticket.peer;
	initial.origin = request.ticket.origin;
	if (!vtep_socket_publish4(sk, &initial))
		return -EPERM;
	/* Immutable socket ownership is published before any temporary deletion.
	 * Keys use never-reused admission/request cookies, not a reusable tuple.
	 */
	map_delete_elem(&cilium_vtep_admit4, &ticket_key);
	request_key.netns_cookie = netns;
	request_key.token = request.ticket.request_cookie;
	map_delete_elem(&cilium_vtep_req4, &request_key);
	return 0;
}

/* Call only after the normal egress verdict. No owner is UNKNOWN, never native.
 * Missing request metadata also drops; it cannot inherit a replacement tuple.
 */
static __always_inline int
vtep_socket_reply4(struct __sk_buff *ctx, __u64 netns, bool policy_allowed, __be32 *peer)
{
	struct vtep_socket_control control;
	const struct vtep_socket_owner *owner;
	const struct vtep_socket_request *request;
	const struct vtep_socket_ticket *ticket;
	struct vtep_socket_key key = { .netns_cookie = netns };
	struct vtep_socket_key ticket_key = { .netns_cookie = netns };
	struct bpf_sock *sk = ctx->sk;
	struct ethhdr eth;
	struct iphdr ip;
	struct tcphdr tcp;

	*peer = 0;
	if (!policy_allowed || !vtep_socket_control4(netns, &control) ||
	    ctx_load_bytes(ctx, sizeof(struct ethhdr), &ip, sizeof(ip)) < 0 ||
	    ip.version != 4 || ip.ihl != 5 || ip.protocol != IPPROTO_TCP ||
	    (ip.frag_off & bpf_htons(0x3fff)) ||
	    ctx_load_bytes(ctx, sizeof(struct ethhdr) + sizeof(ip), &tcp, sizeof(tcp)) < 0 ||
	    tcp.doff < 5)
		return VTEP_SOCKET_DROP;
	key.token = get_socket_cookie(ctx);
	if (sk && key.token) {
		sk = sk_fullsock(sk);
		if (sk) {
			owner = sk_storage_get(&cilium_vtep_sock4, sk, 0, 0);
			if (owner && owner->socket_cookie == key.token && owner->netns_cookie == netns &&
			    owner->generation == control.generation &&
			    vtep_socket_origin4(owner->origin, owner->peer)) {
				*peer = owner->peer;
				return owner->origin == VTEP_SOCKET_TUNNEL ?
					VTEP_SOCKET_REDIRECT : VTEP_SOCKET_PASS;
			}
		}
	}
	if (!tcp.syn || !tcp.ack || tcp.fin || tcp.rst ||
	    bpf_ntohs(ip.tot_len) != sizeof(ip) + (__u32)tcp.doff * 4)
		return VTEP_SOCKET_DROP;
	/* A queue may orphan a request-socket SYN-ACK. Its pre-queue stamp is
	 * only a lookup token: require the live policy-approved ticket, matching
	 * tuple/ACK and kernel-created request binding. Never infer a peer from
	 * MAC bytes, and never use this fallback for application data.
	 */
	if (!key.token) {
		if (ctx_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0)
			return VTEP_SOCKET_DROP;
		ticket_key.token = vtep_socket_decode4(eth.h_source);
		if (!ticket_key.token)
			return VTEP_SOCKET_DROP;
		ticket = map_lookup_elem(&cilium_vtep_admit4, &ticket_key);
		if (!ticket || !ticket->request_cookie || ticket->generation != control.generation ||
		    ticket->expires_ns <= ktime_get_ns())
			return VTEP_SOCKET_DROP;
		key.token = ticket->request_cookie;
	}
	request = map_lookup_elem(&cilium_vtep_req4, &key);
	if (!request || request->ticket.generation != control.generation ||
	    (ticket_key.token && request->nonce != ticket_key.token) ||
	    request->ticket.expires_ns <= ktime_get_ns() ||
	    request->ticket.flow.pod_addr != ip.saddr || request->ticket.flow.client_addr != ip.daddr ||
	    request->ticket.flow.pod_port != tcp.source || request->ticket.flow.client_port != tcp.dest ||
	    tcp.ack_seq != bpf_htonl(bpf_ntohl(request->ticket.flow.syn_seq) + 1) ||
	    !vtep_socket_origin4(request->ticket.origin, request->ticket.peer))
		return VTEP_SOCKET_DROP;
	*peer = request->ticket.peer;
	return request->ticket.origin == VTEP_SOCKET_TUNNEL ? VTEP_SOCKET_REDIRECT : VTEP_SOCKET_PASS;
}

/* Run on the selected pod's TC egress before a possible orphaning qdisc.
 * Only an actual request socket can publish the existing ticket's token.
 * The host revalidates the ticket after the queue, and restores the real MAC.
 */
static __always_inline int vtep_socket_stamp_request4(struct __sk_buff *ctx, __u64 netns)
{
	struct vtep_socket_key key = { .netns_cookie = netns };
	const struct vtep_socket_request *request;
	__u8 mac[6] __align_stack_8;
	__be32 peer;

	key.token = get_socket_cookie(ctx);
	if (!key.token || vtep_socket_reply4(ctx, netns, true, &peer) == VTEP_SOCKET_DROP)
		return -EPERM;
	request = map_lookup_elem(&cilium_vtep_req4, &key);
	if (!request)
		return -ENOENT;
	vtep_socket_encode4(request->nonce, mac);
	return ctx_store_bytes(ctx, ETH_ALEN, mac, sizeof(mac), 0);
}

/* Only SYN-ACK request skbs need the pre-queue token. ARP and socket-owned
 * application packets must reach the normal endpoint policy/ownership checks.
 */
static __always_inline int vtep_socket_before_queue4(struct __sk_buff *ctx, __u64 netns)
{
	struct iphdr ip;
	struct tcphdr tcp;

	if (ctx_load_bytes(ctx, sizeof(struct ethhdr), &ip, sizeof(ip)) < 0 ||
	    ip.version != 4 || ip.ihl != 5 || ip.protocol != IPPROTO_TCP ||
	    ctx_load_bytes(ctx, sizeof(struct ethhdr) + sizeof(ip), &tcp, sizeof(tcp)) < 0)
		return 0;
	if (tcp.syn && tcp.ack)
		return vtep_socket_stamp_request4(ctx, netns);
	return 0;
}

/* Privileged control-plane collection, not a packet-path scan. Nonce keys are
 * immutable and never reused. Expiry only aborts pending handshakes; a missing
 * ticket/request never permits ordinary forwarding. Established socket storage
 * is not touched. Request cookies also prevent late work aliasing a new tuple.
 */
static long
vtep_socket_collect_admit4(void *map, const struct vtep_socket_key *key,
			   const struct vtep_socket_ticket *ticket, const __u64 *now)
{
	struct vtep_socket_control control;

	if (ticket->expires_ns <= *now || !vtep_socket_control4(key->netns_cookie, &control) ||
	    ticket->generation != control.generation)
		map_delete_elem(map, key);
	return 0;
}

static long
vtep_socket_collect_request4(void *map, const struct vtep_socket_key *key,
			     const struct vtep_socket_request *request, const __u64 *now)
{
	struct vtep_socket_key ticket_key = { key->netns_cookie, request->nonce };
	struct vtep_socket_control control;

	if (request->ticket.expires_ns <= *now ||
	    !vtep_socket_control4(key->netns_cookie, &control) ||
	    request->ticket.generation != control.generation ||
	    !map_lookup_elem(&cilium_vtep_admit4, &ticket_key))
		map_delete_elem(map, key);
	return 0;
}

static __always_inline int vtep_socket_collect4(void)
{
	__u64 now = ktime_get_ns();

	if (for_each_map_elem(&cilium_vtep_admit4, &vtep_socket_collect_admit4, &now, 0) < 0)
		return -EINVAL;
	if (for_each_map_elem(&cilium_vtep_req4, &vtep_socket_collect_request4, &now, 0) < 0)
		return -EINVAL;
	return 0;
}
