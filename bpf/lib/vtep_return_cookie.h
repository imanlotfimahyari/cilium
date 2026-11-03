/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#pragma once

#include "vtep_return_socket.h"
#define VTEP_COOKIE_LEDGER_CAPACITY VTEP_SOCKET_MAX_TICKETS
#include "vtep_return_cookie_ledger.h"

/* Loader requires the reviewed CONFIG_HZ=1000, never a timing estimate. */
#define VTEP_COOKIE_PERIOD 60000ULL

struct vtep_cookie_ack {
	struct cookie_peer_key key;
	__be32 peer;
	__u32 reserved;
	__u64 expires_ns;
};
struct vtep_cookie_packet {
	struct vtep_socket_key ticket;
	struct cookie_peer_key key;
};
struct vtep_cookie_stats { __u64 issued, bound, rejected, pressure; };

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VTEP_SOCKET_MAX_TICKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, struct vtep_socket_key);
	__type(value, struct vtep_cookie_ack);
} cilium_vtep_ck_ack4 __section_maps_btf;
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, int);
	__type(value, struct vtep_cookie_ack);
} vtep_ck_child4 __section_maps_btf;
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VTEP_SOCKET_MAX_TICKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u64);
	__type(value, struct vtep_cookie_packet);
} ck_output_packet __section_maps_btf;
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u32);
	__type(value, struct vtep_cookie_stats);
} vtep_ck_stats __section_maps_btf;

static long BPF_FUNC(sk_storage_delete, const void *map, struct bpf_sock *sk);

static __always_inline struct vtep_cookie_stats *vtep_cookie_stats4(void)
{
	__u32 zero = 0;

	return map_lookup_elem(&vtep_ck_stats, &zero);
}

static __always_inline struct cookie_peer_key
vtep_cookie_key4(__u64 netns, __u64 generation, const struct iphdr *ip,
		 const struct tcphdr *tcp, bool inbound)
{
	struct cookie_peer_key key = { .netns = netns, .generation = generation };

	key.local = inbound ? ip->daddr : ip->saddr;
	key.remote = inbound ? ip->saddr : ip->daddr;
	key.local_port = inbound ? tcp->dest : tcp->source;
	key.remote_port = inbound ? tcp->source : tcp->dest;
	key.client_isn = bpf_ntohl(inbound ? tcp->seq : tcp->ack_seq) - 1;
	key.server_isn = bpf_ntohl(inbound ? tcp->ack_seq : tcp->seq) - (inbound ? 1 : 0);
	return key;
}

/* Called at the same final post-policy point as SYN admission. Ordinary data
 * without matching issued evidence is unchanged. Packet-supplied MAC bytes
 * cannot choose a peer: this function replaces them with a never-reused nonce.
 */
static __always_inline int
vtep_cookie_admit_ack4(struct __sk_buff *ctx, __u64 netns, __u32 origin, __be32 peer,
		      const struct iphdr *ip, const struct tcphdr *tcp)
{
	struct vtep_socket_control control, after;
	struct vtep_socket_key token = { .netns_cookie = netns };
	struct vtep_cookie_ack ack = {};
	struct cookie_peer_record *record;
	struct vtep_cookie_stats *stats;
	__u8 mac[6] __align_stack_8;
	__u64 now;
	__u32 state;

	if (!tcp->ack || tcp->syn || tcp->rst || tcp->fin)
		return 0;
	if (!vtep_socket_control4(netns, &control))
		return -EPERM;
	ack.key = vtep_cookie_key4(netns, control.generation, ip, tcp, true);
	record = map_lookup_elem(&cookie_peer_ledger, &ack.key);
	if (!record || record->expires <= jiffies64())
		return 0;
	if (origin != VTEP_SOCKET_TUNNEL)
		return -EPERM;
	state = __sync_val_compare_and_swap(&record->state, 0, 0);
	if (record->peer != peer || state == COOKIE_PEER_QUARANTINED || state == COOKIE_PEER_COLLECTING)
		return -EPERM;
	if (state == COOKIE_PEER_CONSUMED)
		return 0; /* Existing socket traffic never needs another handoff. */
	if (state != COOKIE_PEER_ISSUED || tcp->doff < 5 ||
	    bpf_ntohs(ip->tot_len) < sizeof(*ip) + (__u32)tcp->doff * 4)
		return -EPERM;
	ack.peer = peer;
	now = ktime_get_ns();
	if (control.ticket_ttl_ns > ~0ULL - now)
		return -EINVAL;
	ack.expires_ns = now + control.ticket_ttl_ns;
	token.token = vtep_socket_nonce4(netns);
	if (!token.token || map_update_elem(&cilium_vtep_ck_ack4, &token, &ack, BPF_NOEXIST)) {
		stats = vtep_cookie_stats4();
		if (stats)
			__sync_fetch_and_add(&stats->pressure, 1);
		return -VTEP_SOCKET_ENOSPC;
	}
	vtep_socket_encode4(token.token, mac);
	if (ctx_store_bytes(ctx, ETH_ALEN, mac, sizeof(mac), 0) < 0 ||
	    !vtep_socket_control4(netns, &after) || after.generation != control.generation) {
		map_delete_elem(&cilium_vtep_ck_ack4, &token);
		return -EPERM;
	}
	return 0;
}

/* A socket-local proof can only be created by the validated child fexit hook.
 * The passive callback supplies that child's real SO_COOKIE, before app replies.
 */
static __always_inline int
vtep_socket_cookie_established4(struct bpf_sock_ops *ctx, struct vtep_socket_owner *initial)
{
	const struct vtep_socket_owner *owner;
	const struct vtep_cookie_ack *proof;
	struct vtep_cookie_stats *stats;
	struct bpf_sock *sk = ctx->sk;

	if (!sk)
		return -EPERM;
	owner = sk_storage_get(&cilium_vtep_sock4, sk, 0, 0);
	if (owner && owner->netns_cookie == initial->netns_cookie &&
	    owner->generation == initial->generation && owner->socket_cookie == initial->socket_cookie &&
	    vtep_socket_origin4(owner->origin, owner->peer))
		return 1;
	proof = sk_storage_get(&vtep_ck_child4, sk, 0, 0);
	if (!proof)
		return 0;
	if (proof->reserved || proof->expires_ns <= ktime_get_ns() ||
	    proof->key.netns != initial->netns_cookie || proof->key.generation != initial->generation ||
	    proof->key.local != ctx->local_ip4 || proof->key.remote != ctx->remote_ip4 ||
	    proof->key.local_port != bpf_htons((__u16)ctx->local_port) ||
	    proof->key.remote_port != bpf_htons((__u16)bpf_ntohl(ctx->remote_port)) ||
	    !proof->peer || !map_lookup_elem(&cilium_vtep_peers4, &proof->peer))
		return -EPERM;
	initial->peer = proof->peer;
	initial->origin = VTEP_SOCKET_TUNNEL;
	if (!vtep_socket_publish4(sk, initial))
		return -EPERM;
	sk_storage_delete(&vtep_ck_child4, sk);
	stats = vtep_cookie_stats4();
	if (stats)
		__sync_fetch_and_add(&stats->bound, 1);
	return 1;
}

/* Normal egress policy/CT has already allowed this SYN-ACK. Match the original
 * SYN ticket and a kernel-issued ledger record; a tuple alone is insufficient.
 */
static __always_inline int
vtep_cookie_reply4(struct __sk_buff *ctx, __u64 netns, __be32 *peer, bool consume)
{
	struct vtep_socket_control control;
	struct vtep_socket_key token = { .netns_cookie = netns };
	const struct vtep_socket_ticket *ticket;
	struct cookie_peer_record *record;
	struct cookie_peer_key key;
	struct ethhdr eth;
	struct iphdr ip;
	struct tcphdr tcp;

	if (!vtep_socket_control4(netns, &control) ||
	    ctx_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0 ||
	    ctx_load_bytes(ctx, sizeof(eth), &ip, sizeof(ip)) < 0 ||
	    ip.version != 4 || ip.ihl != 5 || ip.protocol != IPPROTO_TCP ||
	    (ip.frag_off & bpf_htons(0x3fff)) ||
	    ctx_load_bytes(ctx, sizeof(eth) + sizeof(ip), &tcp, sizeof(tcp)) < 0 ||
	    !tcp.syn || !tcp.ack || tcp.rst || tcp.fin || tcp.doff < 5 ||
	    bpf_ntohs(ip.tot_len) != sizeof(ip) + (__u32)tcp.doff * 4)
		return VTEP_SOCKET_DROP;
	token.token = vtep_socket_decode4(eth.h_source);
	if (!token.token)
		return VTEP_SOCKET_DROP;
	ticket = map_lookup_elem(&cilium_vtep_admit4, &token);
	if (!ticket || ticket->request_cookie || ticket->generation != control.generation ||
	    ticket->expires_ns <= ktime_get_ns() || ticket->origin != VTEP_SOCKET_TUNNEL ||
	    !ticket->peer || ticket->flow.pod_addr != ip.saddr || ticket->flow.client_addr != ip.daddr ||
	    ticket->flow.pod_port != tcp.source || ticket->flow.client_port != tcp.dest ||
	    bpf_ntohl(ticket->flow.syn_seq) + 1 != bpf_ntohl(tcp.ack_seq))
		return VTEP_SOCKET_DROP;
	key = vtep_cookie_key4(netns, control.generation, &ip, &tcp, false);
	record = map_lookup_elem(&cookie_peer_ledger, &key);
	if (!record || record->peer != ticket->peer || record->expires <= jiffies64() ||
	    __sync_val_compare_and_swap(&record->state, 0, 0) != COOKIE_PEER_ISSUED)
		return VTEP_SOCKET_DROP;
	*peer = ticket->peer;
	if (consume && map_delete_elem(&cilium_vtep_admit4, &token)) {
		*peer = 0;
		return VTEP_SOCKET_DROP;
	}
	return VTEP_SOCKET_REDIRECT;
}

static long vtep_cookie_collect_ack(void *map, const struct vtep_socket_key *key,
				  const struct vtep_cookie_ack *ack, const __u64 *now)
{
	struct vtep_socket_control control;

	if (ack->expires_ns <= *now || !vtep_socket_control4(key->netns_cookie, &control) ||
	    control.generation != ack->key.generation)
		map_delete_elem(map, key);
	return 0;
}

static __always_inline int vtep_cookie_collect4(void)
{
	__u64 now = ktime_get_ns();

	return (cookie_peer_collect(jiffies64()) < 0 ||
		for_each_map_elem(&cilium_vtep_ck_ack4, &vtep_cookie_collect_ack, &now, 0) < 0) ? -EINVAL : 0;
}

/* Runs in the selected pod's namespace after Cilium policy, before Linux TCP.
 * A consumed cookie may carry ordinary packets for its exact owned socket, but
 * must not create an unowned replacement child after that socket is unhashed.
 * Lookup by tuple is only a way to find an existing socket; immutable storage
 * on that exact socket supplies authority. Listener/request/TIME-WAIT objects
 * are never treated as an established owner.
 */
static __always_inline int vtep_cookie_pod_ingress4(struct __sk_buff *ctx, __u64 netns)
{
	struct vtep_socket_control control;
	struct cookie_peer_key key;
	struct cookie_peer_record *record;
	const struct vtep_cookie_ack *proof;
	const struct vtep_socket_owner *owner;
	struct vtep_socket_key token = { .netns_cookie = netns };
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *found, *full;
	struct ethhdr eth;
	struct iphdr ip;
	struct tcphdr tcp;
	__u32 state;
	int result = -EPERM;

	if (ctx_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0)
		return -EINVAL;
	if (eth.h_proto != bpf_htons(ETH_P_IP))
		return 0;
	if (ctx_load_bytes(ctx, sizeof(eth), &ip, sizeof(ip)) < 0)
		return -EINVAL;
	if (ip.protocol != IPPROTO_TCP)
		return 0;
	/* TC has no get_netns_cookie helper on the reviewed kernels. The agent
	 * binds this constant to the verified namespace/veth before CNI commit;
	 * BPF_F_CURRENT_NETNS below uses that pod-side device's actual netns.
	 */
	if (!vtep_socket_control4(netns, &control) ||
	    ip.version != 4 || ip.ihl != 5 || (ip.frag_off & bpf_htons(0x3fff)) ||
	    ctx_load_bytes(ctx, sizeof(eth) + sizeof(ip), &tcp, sizeof(tcp)) < 0 || tcp.doff < 5)
		return -EPERM;
	if (!tcp.ack || tcp.syn || tcp.rst || tcp.fin)
		return 0;
	key = vtep_cookie_key4(netns, control.generation, &ip, &tcp, true);
	record = map_lookup_elem(&cookie_peer_ledger, &key);
	if (!record || record->expires <= jiffies64())
		return 0; /* Unrelated normal handshake or expired kernel cookie. */
	state = __sync_val_compare_and_swap(&record->state, 0, 0);
	if (state == COOKIE_PEER_ISSUED) {
		token.token = vtep_socket_decode4(eth.h_source);
		if (!token.token)
			return -EPERM;
		proof = map_lookup_elem(&cilium_vtep_ck_ack4, &token);
		if (!proof || proof->reserved || proof->peer != record->peer ||
		    proof->expires_ns <= ktime_get_ns() || memcmp(&key, &proof->key, sizeof(key)))
			return -EPERM;
	}
	if (state != COOKIE_PEER_ISSUED && state != COOKIE_PEER_CONSUMED)
		return -EPERM;
	tuple.ipv4.saddr = ip.saddr;
	tuple.ipv4.daddr = ip.daddr;
	tuple.ipv4.sport = tcp.source;
	tuple.ipv4.dport = tcp.dest;
	found = skc_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	if (!found)
		return -EPERM;
	if (found->state == BPF_TCP_LISTEN) {
		result = state == COOKIE_PEER_ISSUED ? 0 : -EPERM;
		goto release;
	}
	if (found->state == BPF_TCP_TIME_WAIT)
		goto release;
	full = sk_fullsock(found);
	if (!full)
		goto release;
	owner = sk_storage_get(&cilium_vtep_sock4, full, 0, 0);
	if (owner && owner->netns_cookie == netns && owner->generation == control.generation &&
	    owner->socket_cookie && owner->origin == VTEP_SOCKET_TUNNEL && owner->peer == record->peer)
		result = 0;
release:
	sk_release(found);
	return result;
}
