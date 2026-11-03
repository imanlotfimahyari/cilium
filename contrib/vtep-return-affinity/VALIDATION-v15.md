# v15 validation — 25 October 2026

Upstream integration baseline: `b28d80469415d4494a1a9d86ae18ee2de8a5146b`.
The original v14 checkpoint is retained as `b0d989ff`.

## Changes

- Verify all thirteen canonical pinned map IDs and the schema marker before
  readiness and periodic collection. Losing/replacing a map pin or changing
  the schema retires selected controls. Repair does not silently reopen them.
- Actual Cilium endpoint tests consume TIME-WAIT proofs after policy/CT;
  no synthetic forwarding hook is attached in the new fixture.
- Cover both IPv4 listener families, both original VXLAN peers and native
  routing, explicit policy denial with queued ACK and CT loss, malformed proofs,
  expiry, generation mismatch, missing cookie, unknown peer and netem duplication.
- Synchronize test close/replay using the client's actual TCP_CLOSE state and
  drain the original capture so old ACKs cannot satisfy new assertions.

Map schema 2 and the six tracing programs are unchanged. The feature stays
experimental and off by default. Initial failed test attempts were retained;
the final focused run uses corrected close/capture synchronization and the
actual explicit-denial reason, DROP_POLICY_DENY (181).

## Focused results

```text
--- PASS: TestPrivilegedBundleDetectsEveryMissingPin (0.62s)
--- PASS: TestPrivilegedRuntimeMapDamageRevokesReadiness (6.33s)
--- PASS: TestPrivilegedTIMEWAITCoreForwarding (7.43s)
--- PASS: TestPrivilegedTIMEWAITCorePolicyOrdering (14.36s)
--- PASS: TestPrivilegedTIMEWAITCoreInvalidProofs (25.57s)
--- PASS: TestPrivilegedTIMEWAITCoreDuplicateProof (4.22s)
VTEP_VM_EXIT=0
```

Strict BPF compilation, conntrack byte equivalence, sampled flag-off executable
section equivalence, controller/loader unit checks, Go vet and Python compile
checks pass. The focused VM includes the controller fault/lifecycle suite and
existing packet regressions, not just the new cases.

## Actual daemon

PASS: the actual agent was freshly built with the current upstream dependency
update and the map-pin readiness checks. The isolated daemon run preserves all
thirteen map and six tracing-link identities across actual SIGKILL/restart,
continues established/TIME-WAIT traffic, validates pod replacement, refuses
unsafe disable, then removes the graph after drain and passes ordinary TCP.

```text
--- PASS: TestPrivilegedRealAgentProcess (682.89s)
--- PASS: TestPrivilegedRealAgentProcess/periodic_GC_preserves_TIMEWAIT_owner (10.57s)
--- PASS: TestPrivilegedRealAgentProcess/native_owner_bypasses_overlapping_VTEP_prefix (0.02s)
--- PASS: TestPrivilegedRealAgentProcess/SIGKILL_restart_preserves_live_connections (166.43s)
--- PASS: TestPrivilegedRealAgentProcess/retirement_prevents_legacy_fallthrough (0.29s)
--- PASS: TestPrivilegedRealAgentProcess/pod_replacement_with_reused_address_and_interface_name (2.11s)
--- PASS: TestPrivilegedRealAgentProcess/disabled_agent_refuses_live_membership (187.10s)
--- PASS: TestPrivilegedRealAgentProcess/coordinated_drain_then_disabled_agent (145.68s)
VTEP_VM_EXIT=0
```

## Evidence

- `cilium-vtep-v15-focused-validation.log` — SHA-256 `0792f509d5b438c433fbe29dd429dc0629826a40fa0e00b260d1af63f3be5e42`

Only the isolated Linux 6.8.0-31/amd64 lab was exercised. Kubernetes normal
identity/CNI/NetworkPolicy validation remains deferred. The full daemon uses
the no-policy identity allocator. Broader kernels, native performance,
older-binary upgrade/rollback and SYN-cookie support remain open gates.

- `cilium-vtep-v15-agent-validation.log` — SHA-256 `794b7c8262c4a85db9cda6a071aeee1774ef3d893d18489a996013f00338fa8e`
