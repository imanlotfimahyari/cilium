/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Test-only state adapter. Inputs are deliberately synthetic trusted evidence,
 * not network authority. No hooks are attached and no packets are forwarded.
 */
#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "cookie_peer_ledger.h"

struct cookie_peer_command {
	struct cookie_peer_key key;
	__u64 now, period;
	__be32 peer;
	__u32 operation;
};

__section("tc/cookie_peer_test")
int cookie_peer_test(struct __sk_buff *ctx)
{
	struct cookie_peer_command command;

	if (ctx_load_bytes(ctx, 0, &command, sizeof(command)) < 0)
		return 0;
	if (command.operation == 1)
		return cookie_peer_issue(&command.key, command.peer, command.now, command.period);
	if (command.operation == 2)
		return cookie_peer_consume(&command.key, command.peer, command.now);
	if (command.operation == 3)
		return cookie_peer_collect(command.now) >= 0;
	return 0;
}

BPF_LICENSE("GPL");
