/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#define VTEP_SOCKET_MAX_TICKETS 8
#define ENABLE_VTEP_RETURN_SOCKET_AFFINITY 1
#include "lib/vtep_return_timewait_owner.h"

BPF_LICENSE("GPL");
