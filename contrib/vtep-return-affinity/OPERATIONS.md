# Operational hardening and hook/map review

**v25 validated lifecycle:** schema 3 has 18 maps and eight managed tracing
hooks, plus sockops, pod ingress/pre-queue TCX and retirement guards. Cookie
counters and canonical-map diagnostics are included. See
[v25 executed evidence and limits](VALIDATION-v25.md). Historical validation
notes below remain tied to their named checkpoint.

**v22 update:** the real daemon now passes restart under controlled live admission
pressure on both kernels. This closes v21's separate-fixture restart gap for
that tested map/scenario. It does not establish legitimate sustained load,
full-agent pressure on every transient map, or Kubernetes policy/identity behavior.
See [v22 evidence](VALIDATION-v22.md).

**v21 update:** overlapping producer/GC/reload correctness and controller restart
under pressure now have dedicated tests. The live test uses eight-entry admission
and request maps, invalid synthetic occupancy, actual Cilium policy/CT and established
TCP through both peers. The independent controller test uses production-size maps
and preserves all 13 map IDs and six tracing-link IDs. These do not establish
sustained legitimate-handshake throughput or full-agent restart under live load.
See [v21 validation and remaining gates](VALIDATION-v21.md).

**v20 update:** the reader and pressure behavior now have live-kernel evidence
on Linux 6.8 and 6.12. v20 also fixes missing packet-stage insertion accounting.
See [v20 validation, scope and required drain/disable upgrade](VALIDATION-v20.md).
The v19 validation notes below retain their original historical scope.

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
The v19 diagnostic itself introduced no new packet-path counters or schema.

Correction: through v19 the existing counter actually covered proof insertions
only. v20 adds packet-association insertion failures to that same field, matching
the combined diagnostic label. This changes a tracing program's tag and requires
drain/disable before upgrade; no extra counter map or schema is introduced.

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
and packet/reuse/lifecycle tests. v25 uses the two reviewed cookie tracing hooks in the agent-managed graph.
The separate v18 capability probe remains test-only.

## Validation and remaining gates

v19 is based on published v18 `fe4c069def1018b967c2ecee77ac39b717236bfa`, tree
`637a79a5d59a8d2ed88bcb3e34afc1feacf8cd2b`. Checks executed on 3 November 2026:

- Controller package unit tests and race tests pass; privileged cases are skipped
  without the required environment. This is not a new live-kernel result.
- Capacity tests cover empty/partial/full walks, cyclic and over-capacity churn,
  cancellation, genuine nil initial cursor, error redaction and missing bundles.
- CLI build, help/usage, missing-bundle JSON and exit-code smoke checks pass.
- Go vet and git diff --check pass. Production BPF is unchanged.

Historical admission-map saturation, expiry and nonce-exhaustion tests preserve
established traffic in the existing live fixture. This source review does not
extend those results to every map or establish sustained-load performance.

Next hardening gates, before broadening SYN-cookie forwarding:

1. Run this reader against a real pinned bundle; verify kernel-enforced read-only
   updates, stable IDs, full-map observations and pin-loss/refusal behavior.
2. Independently exhaust the request, TIME-WAIT owner, packet-association and
   proof maps. Verify no eviction/retargeting, existing-flow survival, exact
   fail-closed behavior and new admission after legitimate collection.
3. Repeat pressure with concurrent producers/GC and restart; add precise
   failure diagnostics where justified by the observed gaps.
4. Measure native CPU, memory, throughput and tail latency against flag-off.
   No QEMU/TCG timing may substitute for native performance.

The previous VM tools were removed by workspace maintenance. Native privilege
and a restored disposable VM environment are not available for a new privileged
run in this checkpoint. Kubernetes/normal-identity/NetworkPolicy validation
remains deferred. SYN-cookie peer binding, collision/replay/pressure behavior
and agent lifecycle integration remain unimplemented. Complete authoritative
ownership loss still requires reconnecting.

The VM restoration limitation above applied to v19; v20 restores that environment
and executes the real-map and controlled packet-pressure gates. Sustained
concurrency/restart under exhaustion and native performance remain open.
