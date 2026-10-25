/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "vtep_return_timewait_types.h"

/* CO-RE resolves these partial declarations against the running kernel BTF.
 * No hard-coded socket offsets or kernel object addresses enter map values.
 */
struct vtep_atomic64 {
	long long counter;
} __attribute__((preserve_access_index));

struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	__u16 skc_family;
	__u8 skc_state;
	struct vtep_atomic64 skc_cookie;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct inet_timewait_sock {
	struct sock_common __tw_common;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VTEP_SOCKET_MAX_TICKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u64); /* Globally unique kernel socket cookie. */
	__type(value, struct vtep_timewait_owner);
} vtep_tw_owners __section_maps_btf;

struct vtep_timewait_stats {
	__u64 transferred, rejected, freed;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u32);
	__type(value, struct vtep_timewait_stats);
} vtep_tw_stats __section_maps_btf;

static __always_inline bool
vtep_tw_flow_matches(const struct vtep_socket_flow *flow, const struct sock_common *common)
{
	return flow->pod_addr == common->skc_rcv_saddr &&
	       flow->client_addr == common->skc_daddr &&
	       flow->pod_port == bpf_htons(common->skc_num) &&
	       flow->client_port == common->skc_dport;
}

/* Entry occurs before hashdance publishes the TIME-WAIT object to other CPUs.
 * Both objects are still alive. A cookie, peer or namespace is never guessed.
 */
__section("fentry/inet_twsk_hashdance")
int vtep_tw_transfer(__u64 *ctx)
{
	struct inet_timewait_sock *tw = (void *)ctx[0];
	struct sock *sk = (void *)ctx[1];
	const struct vtep_socket_owner *owner;
	struct vtep_socket_control control;
	struct vtep_timewait_owner initial = {};
	struct vtep_timewait_stats *stats;
	__u32 zero = 0;
	__u64 cookie;

	owner = sk_storage_get(&cilium_vtep_sock4, (void *)sk, 0, 0);
	if (!owner)
		return 0; /* Unselected sockets do not consume experiment capacity. */
	stats = map_lookup_elem(&vtep_tw_stats, &zero);
	cookie = tw->__tw_common.skc_cookie.counter;
	if (!cookie || cookie != owner->socket_cookie ||
	    cookie != (__u64)sk->__sk_common.skc_cookie.counter ||
	    tw->__tw_common.skc_state != 6 ||
	    (tw->__tw_common.skc_family != AF_INET && tw->__tw_common.skc_family != AF_INET6) ||
	    !vtep_socket_origin4(owner->origin, owner->peer) ||
	    !vtep_socket_control4(owner->netns_cookie, &control) ||
	    owner->generation != control.generation)
		goto reject;
	initial.owner = *owner;
	initial.flow.pod_addr = sk->__sk_common.skc_rcv_saddr;
	initial.flow.client_addr = sk->__sk_common.skc_daddr;
	initial.flow.pod_port = bpf_htons(sk->__sk_common.skc_num);
	initial.flow.client_port = sk->__sk_common.skc_dport;
	if (!initial.flow.pod_addr || !initial.flow.client_addr ||
	    !vtep_tw_flow_matches(&initial.flow, &tw->__tw_common) ||
	    map_update_elem(&vtep_tw_owners, &cookie, &initial, BPF_NOEXIST))
		goto reject;
	if (stats)
		__sync_fetch_and_add(&stats->transferred, 1);
	return 0;
reject:
	if (stats)
		__sync_fetch_and_add(&stats->rejected, 1);
	return 0;
}

/* Called with the final reference gone, before the object is deallocated.
 * Unlike a FIN/timeout guess, this is actual incarnation-destruction evidence.
 * Delete only this exact cookie; another connection's record is untouched.
 */
__section("fentry/inet_twsk_free")
int vtep_tw_destroy(__u64 *ctx)
{
	struct inet_timewait_sock *tw = (void *)ctx[0];
	__u64 cookie = tw->__tw_common.skc_cookie.counter;
	const struct vtep_timewait_owner *record;
	struct vtep_timewait_stats *stats;
	__u32 zero = 0;

	if (!cookie)
		return 0;
	record = map_lookup_elem(&vtep_tw_owners, &cookie);
	if (!record || record->owner.socket_cookie != cookie ||
	    !vtep_tw_flow_matches(&record->flow, &tw->__tw_common))
		return 0;
	if (!map_delete_elem(&vtep_tw_owners, &cookie)) {
		stats = map_lookup_elem(&vtep_tw_stats, &zero);
		if (stats)
			__sync_fetch_and_add(&stats->freed, 1);
	}
	return 0;
}
