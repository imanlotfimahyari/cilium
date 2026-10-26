# v17 validation — 26 October 2026

## Change and tested source

This milestone extends actual-daemon validation to the v16 runtime on Linux
6.8 and 6.12, and adds explicit prototype upgrade/rollback coverage. It changes
the isolated VM fixture, artifact packaging and evidence checks; no production
agent, datapath, tracing or map-schema implementation changes are included.

- Integration baseline: upstream `b28d80469415d4494a1a9d86ae18ee2de8a5146b`.
- Current agent source: recovered v16 `f4d987348c1d81af78311baad9a805b8f9ff78d5`,
  tree `cf7b93662972439a3da0c0475341eb43b8cf97bc`.
- Previous agent source: published v15 `9ea884789749b1576b48f2f7e534c4f245943d01`,
  tree `7d88d479c8a864643d878c14bbddc61a52453c5c`.
- Harness checkpoint: `aafd68daa0bd247137706c3d8c3d51cee39de26c`, followed
  by readiness-assertion checkpoint `9424b759d4` described below.

Both agents were built separately using Go 1.27.3, `CGO_ENABLED=0` and
`go build -trimpath -o <versioned-output> ./daemon`, from clean source worktrees.
The runner packages each binary with its own BPF source tree. Their production
BPF trees legitimately match: the v16 runtime compatibility change is in Go.
Both executables retain the `cilium-agent` basename. Each version's source is
staged at the same canonical path only after the preceding process has exited;
pins and the recovery journal are never altered to make a transition pass.

## Executed evidence

| Kernel | Result | Actual-daemon test / VM runner | Scope |
| --- | --- | --- | --- |
| Linux 6.8.0-31 | PASS | 854.71s / 881.886s | v15 -> v16 -> v15; full lifecycle |
| Linux 6.12.0-061200 | PASS | 897.48s / 924.616s | v16 restart; v15 rejection; v16 recovery; full lifecycle |

The controller unit package, Go vet for the changed live fixture, all four
Python evidence/preflight tests, strict BPF compilation and `git diff --check`
pass. No production source changed; `conntrack.h` and sampled flag-off
executable sections remain identical to the recovered baseline.

Guests are disconnected QEMU/TCG on amd64 using Ubuntu 6.8.0-31 generic and
Canonical mainline 6.12.0-061200 generic. Durations are execution times under
emulation, not packet-path performance measurements. Required tests were
explicitly selected and must report PASS; zero matches, failures and required
skips fail the evidence report.

The actual agents manage all thirteen maps and six tracing links. The fixture
compares every managed ID and established socket owner, transfers application
data through both VXLAN peers and native routing, and checks actual TIME-WAIT
ACK forwarding while the agent is stopped and after restoration. Subsequent
steps test retirement, reused pod address/interface names, unsafe-disable
refusal/recovery, and drained disable with complete graph removal and working
ordinary TCP afterwards.

Linux 6.8 tests v15 -> v16 -> v15. Linux 6.12 tests v16 SIGKILL/restart and the
known v15 unsupported TIME-WAIT publication-hook rejection, then v16 recovery.
For rejected v15 startup, base-datapath initialization can retry while the process
stays alive. The test requires the specific kernel-hook diagnostic and explicit
failed return-affinity readiness, stops that process, and verifies that the live
graph and traffic survive before restoring v16. Process survival alone is not
acceptance or successful recovery.

The first harness attempt used a noncanonical previous-agent basename and failed
agent initialization; the fixture now enforces the basename. The first Linux
6.12 transition attempt incorrectly required process exit on initialization
rejection and timed out. The corrected assertion checks failed readiness, with
bounded requests and diagnostic output. Those failed reports remain separate
from final evidence; neither counts as a successful test.

## Reproduction

Build the static BPF/live test binaries and objects as described in README.md.
Build the two real agents from the exact source revisions above. Supply QEMU,
BusyBox, kernel/modules, the pinned Cilium compiler and the iptables runtime.
Use the normal privileged_vm.py artifact arguments plus:

```sh
--full-agent /opt/vtep-build/cilium-agent-v16 \
--source-bpf /opt/vtep-v16/bpf \
--previous-full-agent /opt/vtep-build/cilium-agent-v15 \
--previous-source-bpf /opt/vtep-v15/bpf \
--live-test-run '^TestPrivilegedRealAgentProcess$' \
--timewait-packet-object /opt/vtep-build/timewait_packet.o \
--require-test TestPrivilegedRealAgentProcess/periodic_GC_preserves_TIMEWAIT_owner \
--require-test TestPrivilegedRealAgentProcess/disabled_agent_refuses_live_membership \
--require-test TestPrivilegedRealAgentProcess/coordinated_drain_then_disabled_agent
```

Use `--previous-agent-mode compatible` on Linux 6.8 and require both
`TestPrivilegedRealAgentProcess/upgrade_previous_to_current_preserves_live_connections`
and
`TestPrivilegedRealAgentProcess/rollback_current_to_previous_preserves_live_connections`.
On Linux 6.12 use `--previous-agent-mode missing-hashdance` and require
`TestPrivilegedRealAgentProcess/SIGKILL_restart_preserves_live_connections` and
`TestPrivilegedRealAgentProcess/unsupported_previous_agent_refuses_without_replacing_live_graph`.
The sequential matrix accepts these mode and required-test fields per kernel.

Keep each JSON report and log. A rerun uses a separate output directory, preserving
failed evidence. Identical agent binaries and incomplete previous-agent artifact
declarations are rejected before guest allocation.

## Remaining gates

This validates two specific prototype checkpoints, not arbitrary released Cilium
upgrades, schema migrations or older binaries without these protections.

- Real Kubernetes/CNI, normal identity allocation and combined NetworkPolicy
  enforcement remain deferred. The real-agent fixture uses the no-policy
  allocator and policy `never`; earlier separate policy/CT tests remain relevant
  but do not replace that cluster checkpoint.
- Full-agent node reboot with workloads and multi-node rolling upgrades remain
  untested. v16's two-boot result exercises the controller, not a full node.
- Native A/B CPU, memory, throughput and tail-latency measurements, sustained
  churn, hardware NIC/GRO combinations and wider kernel coverage remain open.
  `/dev/kvm` is unavailable in this environment.
- SYN-cookie forwarding remains unsupported; the earlier forced-cookie tests
  prove safe rejection. TFO payloads and unauthoritative socketless replies also
  remain unsupported. Full-agent listeners in this milestone are AF_INET;
  mapped AF_INET6 listeners retain v16 packet/controller evidence only.
- Architectural review of the six hooks/metadata handoff and shared maintenance
  agreement remain necessary. The experiment is default off and not production
  ready. Existing README scope exclusions and complete-state-loss reconnect
  requirement still apply.

## Evidence fingerprints

Only SHA-256 fingerprints are committed; raw logs and binaries stay outside the source tree.

Both supplied production BPF trees have digest
`82cf7227c3617eefc7c225ae7d94da32a9ab38964bfa2959b214cff4c115fd5b`
using the runner's canonical tree-hash procedure. The static Clang 21.1.8 binary
has SHA-256 `cfa1fb10c78ba8f5a99c1d2ab3cfa8f4f7a4d2316175d5c563d5fa40260150a9`.

- `v17-agents/agent68.json` — `ab42ef201d27191084f4c4b7c22cd826310f4f0b5f6be47b8edb3f362eb274f8`
- `v17-agents/agent68.log` — `24ccd3550bec792ecc5b4b79123fd9bc2e91b3f90f5113eed45d44ac6108e7e1`
- `v17-agent612-final/agent612.json` — `21aea583e402b3eec7baa29e69257263e05088bc3a0d94b69de6b9c1367fc2c2`
- `v17-agent612-final/agent612.log` — `741179def4653006a6b026f1b6a6dae86fe3be69ae2a542d6c842f8ea9e22457`
- `build-v17/cilium-agent-v16` — `a8094191d3944d6486eb48521a88d412ce5b6e2a75b0869e01abb756340366dd`
- `build-v17/cilium-agent-v15` — `e39aa05eff0ff99f9a2219c840eb3e213d2feb36bbb7cd36e2789eada882d86f`
- `build-v17/livetest` — `3510262bb7799817494b169757147bff81d1ab30576810c5d8ee48bb10dcd170`

Linux 6.8 used the original harness binary SHA-256
`456579bd1fdb73419604e1cedb61f230033e2aa336c899282b074a89767442aa`.
The final Linux 6.12 fixture differs only in the rejected-startup check and
timeout diagnostics; the compatible 6.8 transition path is unchanged.

