/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "vtep_return_socket.h"

struct vtep_timewait_owner {
	struct vtep_socket_owner owner;
	struct vtep_socket_flow flow; /* syn_seq is zero; no tuple-keyed ownership. */
};

struct tw_reply {
	struct vtep_timewait_owner record;
	__be32 seq, ack;
};

struct tw_scope {
	__u32 depth, valid;
	__u64 packet;
	struct tw_reply reply;
};

struct tw_proof {
	struct tw_reply reply;
	__u64 expires_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VTEP_SOCKET_MAX_TICKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, struct vtep_socket_key);
	__type(value, struct tw_proof);
} cilium_vtep_tw_proof4 __section_maps_btf;

static __always_inline bool tw_packet_matches(struct __sk_buff *ctx, const struct tw_reply *reply)
{
	struct iphdr ip;
	struct tcphdr tcp;

	return ctx_load_bytes(ctx, sizeof(struct ethhdr), &ip, sizeof(ip)) == 0 &&
	       ip.version == 4 && ip.ihl == 5 && ip.protocol == IPPROTO_TCP &&
	       !(ip.frag_off & bpf_htons(0x3fff)) &&
	       ctx_load_bytes(ctx, sizeof(struct ethhdr) + sizeof(ip), &tcp, sizeof(tcp)) == 0 &&
	       tcp.doff >= 5 && tcp.ack && !tcp.syn && !tcp.fin && !tcp.rst &&
	       !tcp.psh && !tcp.urg && !tcp.ece && !tcp.cwr &&
	       bpf_ntohs(ip.tot_len) == sizeof(ip) + (__u32)tcp.doff * 4 &&
	       ip.saddr == reply->record.flow.pod_addr && ip.daddr == reply->record.flow.client_addr &&
	       tcp.source == reply->record.flow.pod_port && tcp.dest == reply->record.flow.client_port &&
	       tcp.seq == reply->seq && tcp.ack_seq == reply->ack;
}
