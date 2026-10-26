/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Capability probe only: no packet verdicts, peer selection, production maps,
 * pins or routing changes. A validated cookie child gets socket-local evidence
 * before its passive-established callback. This is not return-affinity support.
 */
#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include "lib/endian.h"
#include "lib/socket.h"

static void *BPF_FUNC(sk_storage_get, const void *map, struct bpf_sock *sk,
		     void *value, __u64 flags);
static long BPF_FUNC(probe_read_kernel, void *dst, __u32 size, const void *src);

struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
struct possible_net_t { struct net *net; } __attribute__((preserve_access_index));
struct sock_common {
	__be32 skc_daddr, skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num, skc_family;
	__u8 skc_state;
	struct possible_net_t skc_net;
} __attribute__((preserve_access_index));
struct sock { struct sock_common __sk_common; } __attribute__((preserve_access_index));
struct tcp_sock { __u32 rcv_nxt, snd_una; } __attribute__((preserve_access_index));
struct sk_buff {
	unsigned char *head;
	__u16 network_header, transport_header;
} __attribute__((preserve_access_index));

volatile const __u32 cookie_probe_inum;
volatile const __u64 cookie_probe_namespace;

struct cookie_child_marker {
	__u64 netns_cookie, socket_cookie;
	__u32 client_isn, server_isn;
	__be32 local, remote;
	__u16 local_port, remote_port, family, reserved;
};
struct cookie_child_observation {
	__u64 created, established, missing, errors;
	struct cookie_child_marker marker;
};
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cookie_child_marker);
} cookie_child_markers __section_maps_btf;
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, struct cookie_child_observation);
} cookie_child_observations __section_maps_btf;

static __always_inline struct cookie_child_observation *cookie_observation(__u32 port)
{
	struct cookie_child_observation empty = {}, *found;

	found = map_lookup_elem(&cookie_child_observations, &port);
	if (!found) {
		map_update_elem(&cookie_child_observations, &port, &empty, BPF_NOEXIST);
		found = map_lookup_elem(&cookie_child_observations, &port);
	}
	return found;
}

/* Linux 6.8/6.12: four arguments followed by the child return value. The Go
 * loader checks that exact BTF prototype before raw context indexing. A failed
 * cookie check never reaches this successful-return branch. Do not dereference
 * request_sock here: tcp_get_cookie_sock may already have released it.
 */
__section("fexit/tcp_get_cookie_sock")
int cookie_child_created(__u64 *ctx)
{
	struct sock *listener = (void *)ctx[0], *child = (void *)ctx[4];
	struct sk_buff *skb = (void *)ctx[1];
	struct cookie_child_marker initial = {}, *marker;
	struct cookie_child_observation *record;
	struct tcp_sock *tp = (void *)child;
	struct iphdr ip;
	struct tcphdr tcp;
	__u32 port, rcv_nxt = 0, snd_una = 0;

	if (!listener || !child || !skb || !cookie_probe_inum || !cookie_probe_namespace ||
	    listener->__sk_common.skc_net.net->ns.inum != cookie_probe_inum ||
	    child->__sk_common.skc_net.net->ns.inum != cookie_probe_inum ||
	    child->__sk_common.skc_num != 8080 ||
	    child->__sk_common.skc_rcv_saddr != bpf_htonl(0xc633640a))
		return 0;
	port = bpf_ntohs(child->__sk_common.skc_dport);
	record = cookie_observation(port);
	if (!record)
		return 0;
	if (listener->__sk_common.skc_state != 10 || child->__sk_common.skc_state != 3 ||
	    (child->__sk_common.skc_family != AF_INET && child->__sk_common.skc_family != AF_INET6) ||
	    probe_read_kernel(&ip, sizeof(ip), skb->head + skb->network_header) ||
	    probe_read_kernel(&tcp, sizeof(tcp), skb->head + skb->transport_header) ||
	    probe_read_kernel(&rcv_nxt, sizeof(rcv_nxt), &tp->rcv_nxt) ||
	    probe_read_kernel(&snd_una, sizeof(snd_una), &tp->snd_una) ||
	    ip.version != 4 || ip.ihl != 5 || ip.protocol != IPPROTO_TCP ||
	    (ip.frag_off & bpf_htons(0x3fff)) || !tcp.ack || tcp.syn || tcp.rst ||
	    ip.saddr != child->__sk_common.skc_daddr || ip.daddr != child->__sk_common.skc_rcv_saddr ||
	    tcp.source != child->__sk_common.skc_dport || tcp.dest != bpf_htons(8080) ||
	    bpf_ntohl(tcp.seq) != rcv_nxt || bpf_ntohl(tcp.ack_seq) != snd_una)
		goto error;
	initial.netns_cookie = cookie_probe_namespace;
	initial.client_isn = bpf_ntohl(tcp.seq) - 1;
	initial.server_isn = bpf_ntohl(tcp.ack_seq) - 1;
	initial.local = ip.daddr;
	initial.remote = ip.saddr;
	initial.local_port = 8080;
	initial.remote_port = port;
	initial.family = child->__sk_common.skc_family;
	marker = sk_storage_get(&cookie_child_markers, (void *)child, &initial,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!marker || marker->socket_cookie || marker->netns_cookie != initial.netns_cookie ||
	    marker->client_isn != initial.client_isn || marker->server_isn != initial.server_isn)
		goto error;
	record->marker = *marker;
	__sync_fetch_and_add(&record->created, 1);
	return 0;
error:
	__sync_fetch_and_add(&record->errors, 1);
	return 0;
}

__section("sockops")
int cookie_child_established(struct bpf_sock_ops *ctx)
{
	struct cookie_child_marker *marker;
	struct cookie_child_observation *record;
	struct bpf_sock *sk = ctx->sk;
	__u64 cookie;

	if (ctx->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || !ctx->is_fullsock || !sk ||
	    get_netns_cookie(ctx) != cookie_probe_namespace || ctx->local_port != 8080 ||
	    ctx->local_ip4 != bpf_htonl(0xc633640a))
		return 1;
	record = cookie_observation(bpf_ntohl(ctx->remote_port));
	if (!record)
		return 1;
	marker = sk_storage_get(&cookie_child_markers, sk, 0, 0);
	if (!marker) {
		__sync_fetch_and_add(&record->missing, 1);
		return 1; /* Normal request-based control connection, no probe marker. */
	}
	cookie = get_socket_cookie(ctx);
	if (!cookie || marker->socket_cookie || marker->netns_cookie != cookie_probe_namespace ||
	    marker->local != ctx->local_ip4 || marker->remote != ctx->remote_ip4 ||
	    marker->local_port != ctx->local_port || marker->remote_port != bpf_ntohl(ctx->remote_port) ||
	    marker->family != ctx->family)
		__sync_fetch_and_add(&record->errors, 1);
	else {
		marker->socket_cookie = cookie;
		record->marker = *marker;
		__sync_fetch_and_add(&record->established, 1);
	}
	return 1;
}

BPF_LICENSE("GPL");
