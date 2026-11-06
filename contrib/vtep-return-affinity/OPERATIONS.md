<!-- This file was not reviewed by a human before submission -->

# Operations, diagnostics and hook/map review

Use [SUPPORT.md](SUPPORT.md) as the current support/validation matrix. The
read-only diagnostic, controlled pressure handling, external-cookie binding and
agent lifecycle are implemented; historical proposals are not outstanding work.
This document describes the current diagnostic contract and the graph to review.

## Read-only capacity diagnostic

Build with the Go version required by go.mod:

```sh
go build -o /tmp/vtep-capacity ./contrib/vtep-return-affinity/capacity
/tmp/vtep-capacity --maps EXISTING_RUNTIME_MAP_DIRECTORY
```

Supply the existing runtime's `maps` directory. The tool does not discover or
adopt another runtime, create missing maps, fix pins, run collection, or change
configuration. It opens descriptors with kernel read-only flags, validates the
complete v3 map bundle, walks bounded hash maps, and rechecks canonical map IDs
and the schema after sampling. It outputs only map metadata, observed counts,
and aggregate TIME-WAIT/cookie counters. Flow keys, peer addresses and map payloads are
not emitted. Errors do not echo operator paths or raw lookup details.

Exit codes: **0** complete sample with no observed full hash map; **2** complete
sample with a hash map observed at capacity; **1** incomplete/incompatible state,
permissions, cancellation, output failure or usage error. Help exits 0.

`complete` means the diagnostic completed, not that the agent is healthy.
`atomic` is always false. Samples from separate maps are not simultaneous and
churn can change occupancy immediately. Repeated keys or a traversal exceeding
the validated capacity abort that count instead of producing misleading zeroes.
The walk checks a five-second cooperative deadline; kernel calls themselves are
not asynchronously interrupted. Run on demand, not on every packet, readiness
request or GC cycle.

`max_entries=0` on socket-local storage does not mean empty or unlimited resource
availability. The tool deliberately reports its occupancy as unknown. Array and
per-CPU array slots are fixed runtime/control storage, not admission occupancy.
The diagnostic does not validate tracing links or endpoint hooks and cannot
authorize fallback, drain, rollback or deletion.

Counter differences are meaningful only across the same map IDs/boot epoch and
without reset. `timewait_rejected` has multiple causes, not just capacity.
`packet_or_proof_insert_failures` combines insertion failures at two stages;
it is not a precise per-map full-drop metric. Admission/request insertion failures
still lack dedicated production counters. Cookie counters report issued, bound,
rejected and insertion failures; rejected is not synonymous with capacity full.
The diagnostic does not itself add packet-path counters or change schemas.

## Map review

The v3 bundle has eighteen maps. All bounded transient ownership/proof maps are
non-evicting hashes. Full capacity rejects new work; it must not retarget or
evict surviving authority. These entry limits are not total kernel memory bounds.

| Map | Capacity | Role / pressure consequence |
| --- | --- | --- |
| cilium_vtep_sock_ctl4 | 1,024 | Namespace readiness/generation; no new namespace when full |
| cilium_vtep_nonce4 | 1,024 | Never-reused namespace nonce history; saturation refuses admission |
| cilium_vtep_admit4 | 4,096 | Policy-approved SYN tickets; full rejects new tickets |
| cilium_vtep_req4 | 4,096 | Kernel request binding; full prevents new handshake ownership |
| cilium_vtep_sock4 | Per-socket storage | Established immutable ownership; kernel socket lifetime controls reclamation; allocation can fail |
| cilium_vtep_peers4 | 64 | Exact peer configuration; capacity is not a tested scalability claim |
| vtep_tw_owners | 4,096 | Exact TIME-WAIT incarnation; failed transfer leaves replies without authority |
| vtep_tw_stats | One array slot | Transfer/rejection/destruction counters |
| tw_reply_scope | One slot per CPU | Nested ACK scope, not connection capacity |
| tw_output_packet | 4,096 | Exact constructed skb association; failed insertion rejects that handoff |
| cilium_vtep_tw_proof4 | 4,096 | One-time queued ACK proof; full rejects new stamps |
| tw_packet_stats | One array slot | Packet/proof counters and combined insertion pressure |
| cookie_peer_ledger | 4,096 | First-peer cookie authority and consumed/quarantined tombstones; held for the full kernel acceptance window |
| cilium_vtep_ck_ack4 | 4,096 | One-time post-policy ACK evidence; pressure refuses new handoffs |
| vtep_ck_child4 | Per-socket storage | Temporary proof on the exact kernel-created child; allocation failure grants no ownership |
| ck_output_packet | 4,096 | Exact cookie SYN-ACK skb evidence; released at actual skb teardown |
| vtep_ck_stats | One array slot | Issued/bound/rejected and insertion-failure counters |
| cilium_vtep_sock_schema | One array slot | Version/compatibility marker |

Journal admission history is independently bounded to 8,192 memberships/ranges;
input decoding has a separate 64 MiB limit. Neither bounds live socket storage.
Do not clear history or evict ownership to relieve pressure. Transient expiry
aborts pending work; it is not evidence that an established socket has ended.

## Hook review

Eight tracing links remain in the production experiment. Each has a different
incarnation-safety role; this source review establishes no safe removal yet.

| Hook program | Purpose |
| --- | --- |
| vtep_tw_transfer | Transfer the full socket's owner before TIME-WAIT publication |
| vtep_tw_destroy | Remove that exact incarnation at actual destruction |
| tw_ack_enter | Associate ACK construction with the verified TIME-WAIT socket |
| tw_ack_exit | Bound/clear that invocation's scope |
| tw_packet_created | Bind the actual newly constructed skb, not a reusable tuple |
| tw_packet_release | Invalidate TIME-WAIT and cookie associations before skb address reuse, including early drops |
| ck_synack_created | Bind the actual cookie SYN-ACK and original policy-approved SYN |
| ck_child_created | Validate the ACK and attach proof only to the kernel-returned cookie child |

The graph also includes node cgroup sockops, selected-pod ingress/pre-queue TCX and
retirement guards; "eight tracing links" is not the total attachment count.
The global skb-release hook and saved-SYN/socket memory deserve native A/B
measurement. Removing a hook requires an alternative proof for its safety role
and packet/reuse/lifecycle tests. The two reviewed cookie tracing hooks are part of the agent-managed graph.
The separate v18 capability probe remains test-only.

## Remaining operational gates

Last full-agent VM evidence is recorded in `VALIDATION-v29.md`; controlled
real-map and packet-pressure evidence is in v20-v28 reports. The refreshed-main
report records only newly executed checks. Those results do not establish real
Kubernetes policy/identity behavior, sustained legitimate load on every map,
released-version rollback or native performance.

Before production use, exercise the combined target topology, kernel, normal
identities/policy, node reboot and rolling operations. Measure native CPU/memory,
throughput/latency, capacity recovery and loss/offload behavior. Preserve map-ID,
boot and workload context when comparing diagnostics. Do not erase history or
evict occupied ownership to relieve pressure. The remaining gate list and exact
configuration limits are maintained only in [SUPPORT.md](SUPPORT.md).
