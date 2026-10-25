# v14 recovery validation — 25 October 2026

Baseline: `fe561573e0a8adc43bacbcc70bda0c9e01d6676d`.

The restored workspace initially contained v12. The previously cited v14
artifacts were unavailable. This checkpoint rebuilds the missing integration
and records newly executed checks; it does not rely on that earlier completion
claim. No previous test VM/process was running at the initial local check.

## Implemented

- Existing experimental flag, still default-off, enables socket and TIME-WAIT
  return affinity for selected endpoints.
- Thirteen canonical maps, map schema 2, six pinned tracing links.
- Cleanup hooks install before producers and readiness. Compatible restoration
  reuses exact links, with kernel BTF target/attachment, program tag and exact
  map-ID validation. Missing or incompatible state is refused, never recreated.
- Hook-pin loss retires namespace controls and permanently revokes readiness.
- Existing five-second collector includes expired ten-second packet proofs.
- Physical drain required before disable. Producers are removed before cleanup
  hooks, followed by the runtime graph.
- TIME-WAIT proof consumption follows normal Cilium policy/CT; existing
  translated/proxy exclusions remain in front of the reply helper.

## Verified results

| Check | Result |
| --- | --- |
| Strict BPF compilation; conntrack unchanged; sampled flag-off bytecode | PASS |
| Controller unit tests and loader template isolation | PASS |
| Go vet: returnaffinity and live tests | PASS |
| Controller VM: maps/hooks identity restore, every missing hook, missing proof map, old schema, changed code, wrong maps, pin loss, lifecycle/drain | PASS; `VTEP_VM_EXIT=0` |
| Packet VM: actual Cilium socket policy/CT regressions; mapped listeners; TIME-WAIT lifetime, exact packet, synthetic policy/loss, queued tuple reuse, expired proof cleanup; SYN-cookie fail-closed | PASS; `VTEP_VM_EXIT=0` |
| Actual daemon VM: TIME-WAIT forwarding, periodic GC, actual SIGKILL/restart, all map/link IDs, retirement, pod replacement, unsafe disable/recovery, drain/disable, ordinary TCP | PASS; `VTEP_VM_EXIT=0` |
| `git diff --check` and Python compile checks | PASS |

Actual daemon test output:

```text
--- PASS: TestPrivilegedRealAgentProcess (785.79s)
--- PASS: TestPrivilegedRealAgentProcess/periodic_GC_preserves_TIMEWAIT_owner (14.72s)
--- PASS: TestPrivilegedRealAgentProcess/native_owner_bypasses_overlapping_VTEP_prefix (0.05s)
--- PASS: TestPrivilegedRealAgentProcess/SIGKILL_restart_preserves_live_connections (181.28s)
--- PASS: TestPrivilegedRealAgentProcess/retirement_prevents_legacy_fallthrough (0.25s)
--- PASS: TestPrivilegedRealAgentProcess/pod_replacement_with_reused_address_and_interface_name (1.89s)
--- PASS: TestPrivilegedRealAgentProcess/disabled_agent_refuses_live_membership (176.35s)
--- PASS: TestPrivilegedRealAgentProcess/coordinated_drain_then_disabled_agent (224.08s)
VTEP_VM_EXIT=0
```

Only Linux 6.8.0-31 in disconnected QEMU/TCG was tested. The daemon uses the
no-policy allocator; separate actual endpoint tests cover policy/CT. Normal
Kubernetes identity allocation, CNI and full-cluster NetworkPolicy remain
unvalidated. No native performance or broader-kernel claim is made. SYN cookies,
socketless data/resets, services/NAT, encryption, Geneve and IPv6 forwarding remain
outside the supported experiment. Complete ownership-state loss requires reconnect.

Drain and disable the previous live prototype with its old binary before moving
to schema 2. Compatible restart is supported; in-place tracing-code/schema
migration and older-binary rollback are not validated.

## Saved evidence

- `cilium-vtep-v14-recovered-controller-validation.log` — SHA-256 `ef21d7e72d0b0ec2dac46d249535fce37eb096999c5c1115092747e18cf8a5cc`
- `cilium-vtep-v14-recovered-regression-validation.log` — SHA-256 `b53d21f0a64f6d246dfbdbc9694366ab52fa8b08d83a244a01f26f08ac3e5287`
- `cilium-vtep-v14-recovered-agent-validation.log` — SHA-256 `95ebdabb40d903f579c7b35c1e0d0c66e3553d7af77f1f91bfa4cf3a3f11029c`
