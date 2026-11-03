/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Callers MUST obtain
 * namespace/generation, tuple, both ISNs and peer from trusted, post-policy SYN
 * and actual kernel SYN-ACK evidence. Consuming also requires an independently
 * verified cookie child and trusted post-policy ACK peer. A successful lookup
 * alone is never permission to forward or publish a socket owner.
 *
 * now is kernel jiffies, period is 60 * reviewed kernel HZ. Linux 6.8/6.12
 * accept the current and previous cookie epochs. Neither is configurable by
 * packets. Test adapters supply a virtual jiffies clock to exercise boundaries.
 */
struct cookie_peer_key {
	__u64 netns, generation;
	__be32 local, remote;
	__be16 local_port, remote_port;
	__u32 client_isn, server_isn, reserved;
};

enum cookie_peer_state {
	COOKIE_PEER_ISSUED = 1,
	COOKIE_PEER_CONSUMED,
	COOKIE_PEER_QUARANTINED,
	COOKIE_PEER_COLLECTING,
};

struct cookie_peer_record {
	__u64 epoch, expires;
	__be32 peer;
	__u32 state;
};

#ifndef VTEP_COOKIE_LEDGER_CAPACITY
#define VTEP_COOKIE_LEDGER_CAPACITY 4096
#endif
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VTEP_COOKIE_LEDGER_CAPACITY);
#ifndef VTEP_COOKIE_LEDGER_UNPINNED
	__uint(pinning, LIBBPF_PIN_BY_NAME);
#endif
	__type(key, struct cookie_peer_key);
	__type(value, struct cookie_peer_record);
} cookie_peer_ledger __section_maps_btf;

static __always_inline bool cookie_peer_key_valid(const struct cookie_peer_key *key)
{
	return key->netns && key->generation && key->local && key->remote &&
	       key->local_port && key->remote_port && !key->reserved;
}

/* Never change an existing peer/epoch/expiry and never overwrite a map value.
 * Reissuing the same evidence in another epoch is conservatively refused even
 * for the same peer: identical 32-bit cookies can collide across epochs.
 * A competing peer quarantines an issued record before another issue can be
 * approved. If a valid consumer already won, its socket owner remains intact;
 * the competing SYN-ACK is still denied and cannot gain new authority.
 */
static __always_inline bool
cookie_peer_issue(const struct cookie_peer_key *key, __be32 peer, __u64 now, __u64 period)
{
	struct cookie_peer_record initial = {}, *record;
	__u32 state;

	if (!cookie_peer_key_valid(key) || !peer || !period || period > (~0ULL / 4) ||
	    now > (~0ULL - 2 * period))
		return false;
	initial.epoch = now / period;
	initial.expires = (initial.epoch + 2) * period;
	initial.peer = peer;
	initial.state = COOKIE_PEER_ISSUED;
	map_update_elem(&cookie_peer_ledger, key, &initial, BPF_NOEXIST);
	record = map_lookup_elem(&cookie_peer_ledger, key);
	if (!record || record->expires <= now)
		return false; /* Expired records require the collector, never revival. */
	state = __sync_val_compare_and_swap(&record->state, 0, 0);
	if (state != COOKIE_PEER_ISSUED)
		return false;
	if (record->peer != peer || record->epoch != initial.epoch) {
		__sync_val_compare_and_swap(&record->state, COOKIE_PEER_ISSUED,
					  COOKIE_PEER_QUARANTINED);
		return false;
	}
	return true;
}

/* The caller must publish only on the exact validated child after winning.
 * Allocation/publication failure burns this evidence; it must never reset it.
 * Wrong-peer ACKs do not invalidate another peer's legitimate issued record.
 */
static __always_inline bool
cookie_peer_consume(const struct cookie_peer_key *key, __be32 peer, __u64 now)
{
	struct cookie_peer_record *record;

	if (!cookie_peer_key_valid(key) || !peer)
		return false;
	record = map_lookup_elem(&cookie_peer_ledger, key);
	return record && record->peer == peer && record->expires > now &&
	       __sync_val_compare_and_swap(&record->state, COOKIE_PEER_ISSUED,
					   COOKIE_PEER_CONSUMED) == COOKIE_PEER_ISSUED;
}

/* Claim the exact old map value before deleting it. Only the CAS winner may
 * delete: concurrent collectors holding a stale RCU value cannot delete a
 * newly inserted incarnation of the same key. Issuers/consumers never revive
 * expired or COLLECTING values. No short-TTL GC or eviction of tombstones.
 */
static long
cookie_peer_collect_one(void *map, const struct cookie_peer_key *key,
			struct cookie_peer_record *record, const __u64 *now)
{
	__u32 state;

	if (record->expires > *now)
		return 0;
	state = __sync_val_compare_and_swap(&record->state, 0, 0);
	if (state >= COOKIE_PEER_ISSUED && state <= COOKIE_PEER_QUARANTINED &&
	    __sync_val_compare_and_swap(&record->state, state, COOKIE_PEER_COLLECTING) == state)
		map_delete_elem(map, key);
	return 0;
}

static __always_inline long cookie_peer_collect(__u64 now)
{
	return for_each_map_elem(&cookie_peer_ledger, &cookie_peer_collect_one, &now, 0);
}
