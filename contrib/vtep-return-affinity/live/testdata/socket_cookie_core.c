/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#define ENABLE_VTEP_RETURN_COOKIE_AFFINITY 1
#define ENABLE_VTEP_RETURN_TIMEWAIT_AFFINITY 1
#include "socket_core.c"

/* Read the actual authorization clock; no clock or ledger mutation. */
__section("tc/handoff_cookie_clock")
int handoff_cookie_clock(struct __sk_buff *ctx)
{
	__u64 now = jiffies64();

	return ctx_store_bytes(ctx, 0, &now, sizeof(now), 0) < 0 ? 0 : 1;
}

/* Raw test clients on port 49280 have no kernel TCP socket. Suppress their
 * automatic resets so the two deliberately staged cookie handshakes remain
 * deterministic. This fixture program is never attached by the agent.
 */
__section("tc/handoff_cookie_no_reset")
int handoff_cookie_no_reset(struct __sk_buff *ctx)
{
	struct iphdr ip;
	struct tcphdr tcp;

	if (ctx_load_bytes(ctx, ETH_HLEN, &ip, sizeof(ip)) == 0 &&
	    ip.version == 4 && ip.ihl == 5 && ip.protocol == IPPROTO_TCP &&
	    ctx_load_bytes(ctx, ETH_HLEN + sizeof(ip), &tcp, sizeof(tcp)) == 0 &&
	    tcp.source == bpf_htons(49280) && tcp.rst)
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}
