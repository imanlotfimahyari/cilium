/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "vtep_return_timewait_types.h"

/* Run only after ordinary policy/CT. No proof means the caller may check an
 * ordinary socket; a found but invalid claim must never fall through to it.
 * Atomic deletion elects one consumer, including simultaneous qdisc copies.
 */
static __always_inline int
vtep_timewait_reply4(struct __sk_buff *ctx, __u64 netns, __be32 *peer, bool *claimed)
{
	struct vtep_socket_key key = { .netns_cookie = netns };
	struct vtep_socket_control control;
	const struct tw_proof *found;
	struct tw_proof proof;
	struct ethhdr eth;

	*claimed = false;
	if (ctx_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0)
		return VTEP_SOCKET_DROP;
	key.token = vtep_socket_decode4(eth.h_source);
	if (!key.token)
		return VTEP_SOCKET_DROP;
	found = map_lookup_elem(&cilium_vtep_tw_proof4, &key);
	if (!found)
		return VTEP_SOCKET_DROP;
	*claimed = true;
	proof = *found;
	if (map_delete_elem(&cilium_vtep_tw_proof4, &key) ||
	    !vtep_socket_control4(netns, &control) ||
	    proof.reply.record.owner.netns_cookie != netns ||
	    proof.reply.record.owner.generation != control.generation ||
	    !proof.reply.record.owner.socket_cookie ||
	    proof.expires_ns <= ktime_get_ns() || !tw_packet_matches(ctx, &proof.reply) ||
	    !vtep_socket_origin4(proof.reply.record.owner.origin, proof.reply.record.owner.peer))
		return VTEP_SOCKET_DROP;
	*peer = proof.reply.record.owner.peer;
	return proof.reply.record.owner.origin == VTEP_SOCKET_TUNNEL ?
		VTEP_SOCKET_REDIRECT : VTEP_SOCKET_PASS;
}
