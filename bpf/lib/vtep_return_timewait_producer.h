/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "vtep_return_timewait_owner.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u32);
	__type(value, struct tw_scope);
} tw_reply_scope __section_maps_btf;

/* skb addresses are transient, privileged-only identity keys, not ownership
 * or durable cookies. Creation, release and ACK exit bound the map's lifetime.
 * No buffered-packet tuple lookup or reusable pointer authorizes a later skb.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VTEP_SOCKET_MAX_TICKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u64);
	__type(value, struct tw_reply);
} tw_output_packet __section_maps_btf;

struct tw_packet_stats {
	__u64 scopes, packets, stamps, pressure;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u32);
	__type(value, struct tw_packet_stats);
} tw_packet_stats __section_maps_btf;

static __always_inline struct tw_packet_stats *tw_stats(void)
{
	__u32 zero = 0;

	return map_lookup_elem(&tw_packet_stats, &zero);
}

/* TIME-WAIT callers run with BH disabled on the validated Linux 6.8 path.
 * Only the original socket argument can select an owner. Nested ACK emission
 * invalidates the scope instead of borrowing or restoring another invocation.
 */
__section("fentry/tcp_v4_send_ack")
int tw_ack_enter(__u64 *ctx)
{
	const struct sock *sk = (void *)ctx[0];
	const struct vtep_timewait_owner *record;
	struct vtep_socket_control control;
	struct tw_packet_stats *stats;
	struct tw_scope *scope;
	__u32 zero = 0;
	__u64 cookie;

	scope = map_lookup_elem(&tw_reply_scope, &zero);
	if (!scope)
		return 0;
	scope->valid = 0;
	if (scope->packet)
		map_delete_elem(&tw_output_packet, &scope->packet);
	scope->packet = 0;
	if (scope->depth == ~0U)
		return 0; /* Saturation stays invalid. */
	scope->depth++;
	if (scope->depth != 1 || sk->__sk_common.skc_state != 6)
		return 0;
	cookie = sk->__sk_common.skc_cookie.counter;
	record = map_lookup_elem(&vtep_tw_owners, &cookie);
	if (!cookie || !record || record->owner.socket_cookie != cookie ||
	    !vtep_tw_flow_matches(&record->flow, &sk->__sk_common) ||
	    !vtep_socket_control4(record->owner.netns_cookie, &control) ||
	    control.generation != record->owner.generation)
		return 0;
	scope->reply.record = *record;
	scope->reply.seq = bpf_htonl((__u32)ctx[2]);
	scope->reply.ack = bpf_htonl((__u32)ctx[3]);
	scope->valid = 1;
	stats = tw_stats();
	if (stats)
		__sync_fetch_and_add(&stats->scopes, 1);
	return 0;
}

__section("fexit/tcp_v4_send_ack")
int tw_ack_exit(__maybe_unused __u64 *ctx)
{
	struct tw_scope *scope;
	__u32 zero = 0;

	scope = map_lookup_elem(&tw_reply_scope, &zero);
	if (scope) {
		if (scope->packet)
			map_delete_elem(&tw_output_packet, &scope->packet);
		scope->packet = 0;
		scope->valid = 0;
		if (scope->depth && scope->depth != ~0U)
			scope->depth--;
	}
	return 0;
}

/* The return value identifies the newly constructed skb itself. Unlike a
 * generic output hook, this cannot adopt an older buffered skb by its tuple.
 */
__section("fexit/__ip_make_skb")
int tw_packet_created(__u64 *ctx)
{
	__u64 packet = ctx[4];
	struct tw_scope *scope;
	struct tw_packet_stats *stats;
	__u32 zero = 0;

	scope = map_lookup_elem(&tw_reply_scope, &zero);
	if (!packet || !scope || scope->depth != 1 || !scope->valid)
		return 0;
	if (scope->packet)
		map_delete_elem(&tw_output_packet, &scope->packet);
	scope->packet = packet;
	/* Release must invalidate before address reuse; never overwrite a
	 * surviving entry to make an unexpected pointer collision work.
	 */
	if (!map_update_elem(&tw_output_packet, &packet, &scope->reply, BPF_NOEXIST)) {
		stats = tw_stats();
		if (stats)
			__sync_fetch_and_add(&stats->packets, 1);
	} else {
		/* A collision cannot leave another incarnation eligible for TC. */
		map_delete_elem(&tw_output_packet, &packet);
		scope->packet = 0;
		scope->valid = 0;
	}
	return 0;
}

/* Invalidate before head-state release, including drops before ACK emission returns.
 * Otherwise a freed skb address could be reused before its older call exits.
 * This high-frequency hook requires explicit kernel compatibility validation.
 */
__section("fentry/skb_release_head_state")
int tw_packet_release(__u64 *ctx)
{
	__u64 packet = ctx[0];

	map_delete_elem(&tw_output_packet, &packet);
	return 0;
}

static __always_inline int vtep_timewait_stamp4(struct __sk_buff *ctx, __u64 netns)
{
	__u64 packet = (__u64)ctx; /* Privileged verifier must permit this identity key. */
	const struct tw_reply *reply;
	struct vtep_socket_key key = { .netns_cookie = netns };
	struct vtep_socket_control control;
	struct tw_proof proof = {};
	struct tw_packet_stats *stats = tw_stats();
	__u8 mac[6] __align_stack_8;

	reply = map_lookup_elem(&tw_output_packet, &packet);
	if (!reply)
		return 0; /* Ordinary packets still traverse existing hooks. */
	proof.reply = *reply;
	map_delete_elem(&tw_output_packet, &packet);
	if (proof.reply.record.owner.netns_cookie != key.netns_cookie ||
	    !vtep_socket_control4(key.netns_cookie, &control) ||
	    control.generation != proof.reply.record.owner.generation ||
	    !tw_packet_matches(ctx, &proof.reply))
		return -EPERM;
	key.token = vtep_socket_nonce4(key.netns_cookie);
	if (!key.token)
		return -EPERM;
	proof.expires_ns = ktime_get_ns() + 10000000000ULL;
	if (map_update_elem(&cilium_vtep_tw_proof4, &key, &proof, BPF_NOEXIST)) {
		if (stats)
			__sync_fetch_and_add(&stats->pressure, 1);
		return -EPERM;
	}
	vtep_socket_encode4(key.token, mac);
	if (ctx_store_bytes(ctx, ETH_ALEN, mac, sizeof(mac), 0) < 0) {
		map_delete_elem(&cilium_vtep_tw_proof4, &key);
		return -EPERM;
	}
	if (stats)
		__sync_fetch_and_add(&stats->stamps, 1);
	return 0;
}

static long tw_collect(void *map, const struct vtep_socket_key *key,
		       const struct tw_proof *proof, const __u64 *now)
{
	struct vtep_socket_control control;

	if (proof->expires_ns <= *now || !vtep_socket_control4(key->netns_cookie, &control) ||
	    proof->reply.record.owner.generation != control.generation)
		map_delete_elem(map, key);
	return 0;
}

static __always_inline int vtep_timewait_collect4(void)
{
	__u64 now = ktime_get_ns();

	return for_each_map_elem(&cilium_vtep_tw_proof4, &tw_collect, &now, 0) < 0 ? -EPERM : 0;
}
