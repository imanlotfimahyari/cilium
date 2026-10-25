/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Capability probe only. Peers come from synthetic test admissions, not real
 * Cilium ingress. This object neither changes routing nor authorizes packets.
 */
#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include "lib/endian.h"
#include "lib/socket.h"

static void *BPF_FUNC(sk_storage_get, const void *map, struct bpf_sock *sk,
		     void *value, __u64 flags);
static struct bpf_sock *BPF_FUNC(sk_fullsock, struct bpf_sock *sk);
static int BPF_FUNC(sock_ops_cb_flags_set, struct bpf_sock_ops *ctx, int flags);

struct socket_owner {
	__u64 cookie;
	__be32 peer;
	__u32 reserved;
};

struct packet_evidence {
	__u64 packets;
	__u64 with_socket;
	__u64 with_storage;
	__u64 cookie;
	__be32 peer;
	__u32 reserved;
};

struct socket_evidence {
	__u64 established_cookie;
	__u64 close_wait;
	__u64 closed;
	__u64 errors;
	struct packet_evidence at[3]; /* cgroup egress, pod TC egress, host TC ingress */
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct socket_owner);
} socket_owners __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, __u32); /* client port, host order */
	__type(value, __be32);
} socket_admissions __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, __u32); /* client port, host order */
	__type(value, struct socket_evidence);
} socket_observations __section_maps_btf;

static __always_inline struct socket_evidence *observation(__u32 port)
{
	struct socket_evidence empty = {};
	struct socket_evidence *found;

	found = map_lookup_elem(&socket_observations, &port);
	if (!found) {
		map_update_elem(&socket_observations, &port, &empty, BPF_NOEXIST);
		found = map_lookup_elem(&socket_observations, &port);
	}
	return found;
}

__section("sockops")
int socket_identity_established(struct bpf_sock_ops *ctx)
{
	struct socket_owner initial = {}, *owner;
	struct socket_evidence *record;
	struct bpf_sock *sk = ctx->sk;
	__u32 port;
	__be32 *peer;

	if (ctx->family != AF_INET || ctx->local_port != 8080 ||
	    ctx->local_ip4 != bpf_htonl(0xc633640a) || !ctx->is_fullsock || !sk)
		return 1;
	port = bpf_ntohl(ctx->remote_port);
	peer = map_lookup_elem(&socket_admissions, &port);
	if (!peer || !*peer)
		return 1;
	record = observation(port);
	if (!record)
		return 1;
	if (ctx->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
		initial.cookie = get_socket_cookie(ctx);
		initial.peer = *peer;
		owner = sk_storage_get(&socket_owners, sk, &initial,
				       BPF_SK_STORAGE_GET_F_CREATE);
		if (!owner || !initial.cookie || owner->cookie != initial.cookie ||
		    owner->peer != initial.peer || owner->reserved) {
			__sync_fetch_and_add(&record->errors, 1);
			return 1;
		}
		record->established_cookie = owner->cookie;
		if (sock_ops_cb_flags_set(ctx, ctx->bpf_sock_ops_cb_flags |
					 BPF_SOCK_OPS_STATE_CB_FLAG))
			__sync_fetch_and_add(&record->errors, 1);
	} else if (ctx->op == BPF_SOCK_OPS_STATE_CB) {
		if (ctx->args[1] == BPF_TCP_CLOSE_WAIT)
			__sync_fetch_and_add(&record->close_wait, 1);
		if (ctx->args[1] == BPF_TCP_CLOSE)
			__sync_fetch_and_add(&record->closed, 1);
	}
	return 1;
}

static __always_inline void observe_packet(struct __sk_buff *ctx, __u32 offset, __u32 stage)
{
	struct socket_evidence *record;
	struct packet_evidence *evidence;
	struct socket_owner *owner;
	struct bpf_sock *sk;
	struct iphdr ip;
	struct tcphdr tcp;
	__u32 port, headers;

	if (ctx_load_bytes(ctx, offset, &ip, sizeof(ip)) < 0 ||
	    ip.version != 4 || ip.ihl < 5 || ip.protocol != IPPROTO_TCP ||
	    ip.saddr != bpf_htonl(0xc633640a))
		return;
	if (ctx_load_bytes(ctx, offset + (__u32)ip.ihl * 4, &tcp, sizeof(tcp)) < 0 ||
	    tcp.source != bpf_htons(8080) || tcp.doff < 5)
		return;
	headers = (__u32)ip.ihl * 4 + (__u32)tcp.doff * 4;
	if (bpf_ntohs(ip.tot_len) <= headers)
		return; /* Measure application data, not pre-establishment SYN-ACKs. */
	port = bpf_ntohs(tcp.dest);
	record = observation(port);
	if (!record)
		return;
	evidence = &record->at[stage];
	__sync_fetch_and_add(&evidence->packets, 1);
	evidence->cookie = get_socket_cookie(ctx);
	evidence->peer = 0;
	sk = ctx->sk;
	if (!sk)
		return;
	sk = sk_fullsock(sk);
	if (!sk)
		return;
	__sync_fetch_and_add(&evidence->with_socket, 1);
	owner = sk_storage_get(&socket_owners, sk, 0, 0);
	if (owner && owner->cookie == evidence->cookie && owner->peer && !owner->reserved) {
		__sync_fetch_and_add(&evidence->with_storage, 1);
		evidence->peer = owner->peer;
	}
}

__section("cgroup_skb/egress")
int socket_identity_cgroup(struct __sk_buff *ctx)
{
	observe_packet(ctx, 0, 0);
	return 1;
}

__section("tc/socket_pod")
int socket_identity_pod(struct __sk_buff *ctx)
{
	observe_packet(ctx, sizeof(struct ethhdr), 1);
	return TC_ACT_OK;
}

__section("tc/socket_host")
int socket_identity_host(struct __sk_buff *ctx)
{
	observe_packet(ctx, sizeof(struct ethhdr), 2);
	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
