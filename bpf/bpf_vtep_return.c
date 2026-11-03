/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#define ENABLE_VTEP_RETURN_SOCKET_AFFINITY 1
#define ENABLE_VTEP_RETURN_COOKIE_AFFINITY 1
#ifdef ENABLE_VTEP_RETURN_COOKIE_AFFINITY
#include "lib/vtep_return_cookie_producer.h"
#endif
#include "lib/vtep_return_timewait_producer.h"

volatile const __u64 vtep_queue_cookie;

#ifdef ENABLE_VTEP_RETURN_COOKIE_AFFINITY
__section("tc/vtep_cookie_ingress")
int cil_vtep_cookie_ingress(struct __sk_buff *ctx)
{
	if (vtep_cookie_pod_ingress4(ctx, vtep_queue_cookie) < 0) {
		struct vtep_cookie_stats *stats = vtep_cookie_stats4();

		if (stats)
			__sync_fetch_and_add(&stats->rejected, 1);
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}
#endif

__section("sockops")
int cil_vtep_sockops(struct bpf_sock_ops *ctx)
{
	struct vtep_socket_control control;

	/* Leave callbacks in namespaces outside the selected set untouched. */
	if (!vtep_socket_control4(get_netns_cookie(ctx), &control))
		return 1;
	vtep_socket_sockops4(ctx);
	return 1;
}

__section("tc/vtep_queue")
int cil_vtep_before_queue(struct __sk_buff *ctx)
{
#ifdef ENABLE_VTEP_RETURN_COOKIE_AFFINITY
	int cookie = vtep_cookie_stamp4(ctx, vtep_queue_cookie);

	if (cookie)
		return cookie > 0 ? TC_ACT_OK : TC_ACT_SHOT;
#endif
	return (vtep_timewait_stamp4(ctx, vtep_queue_cookie) < 0 ||
		vtep_socket_before_queue4(ctx, vtep_queue_cookie) < 0) ? TC_ACT_SHOT : TC_ACT_OK;
}

__section("tc/vtep_collect")
int cil_vtep_collect(__maybe_unused struct __sk_buff *ctx)
{
#ifdef ENABLE_VTEP_RETURN_COOKIE_AFFINITY
	if (vtep_cookie_collect4())
		return TC_ACT_SHOT;
#endif
	return (vtep_socket_collect4() || vtep_timewait_collect4()) ? TC_ACT_SHOT : TC_ACT_OK;
}

/* Remains attached independently of normal endpoint links during CNI delete. */
__section("tc/vtep_retired")
int cil_vtep_retired(__maybe_unused struct __sk_buff *ctx)
{
	return TC_ACT_SHOT;
}

BPF_LICENSE("Dual BSD/GPL");
