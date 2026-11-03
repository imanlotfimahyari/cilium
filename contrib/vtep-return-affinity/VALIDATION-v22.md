# v22 full-agent restart under live pressure — 3 November 2026

Implementation: local `44eaa342a741ed74184b4e69519e4784d0058257`, published
`a44cf0bf821ee72d76823cd8659b7d67c50402c5`, matching source tree
`4956e1196b09b5d45a3a8d63289f1c062c871885`. Baseline is v21; production Go/BPF
behavior is unchanged. v20's older-binary drain/disable requirement remains.

## Executed evidence

| Final full-agent evidence | Linux 6.8.0-31 | Linux 6.12.0-061200 |
| --- | --- | --- |
| Real daemon test | PASS, 542.44s | PASS, 511.56s |
| Complete VM runner, including conntrack/core BPF regressions | PASS, 566.438s | PASS, 535.824s |
| Occupancy-producer rounds during restart | 7,044 | 6,645 |
| Completed two-peer TCP payload rounds during restart | 17,526 | 16,527 |
| Required failures / skips | 0 / 0 | 0 / 0 |

Both guests finish with `VTEP_VM_EXIT=0`. These are disconnected amd64
QEMU/TCG guests with two vCPUs and 2,048 MiB, not native performance benchmarks.
The agent was built with Go 1.27.3, `CGO_ENABLED=0`, `GOMAXPROCS=2`,
`go build -p 2 -trimpath -o <output>/cilium-agent ./daemon`.
The runner fingerprints the exact executable, BPF source tree and Clang.
Official Ubuntu iptables/runtime libraries were extracted without host installation.

## What changed and what passed

The new focused `TestPrivilegedRealAgentPressureProcess` shares the established
actual-agent lifecycle fixture. It starts the actual daemon, creates the pod
endpoint synchronously through the API, waits for pod and host datapaths, and
establishes real TCP flows through both VXLAN peers. The agent installs all
hooks/maps, selects namespace readiness and manages collection. The test also
checks actual TIME-WAIT ownership, periodic proof GC and native routing before
its focused restart. Unrelated replacement/disable/rollback phases remain in
the original lifecycle fixture rather than being repeated here.

After SIGKILL, the fixture fills the production 4,096-entry admission map with
invalid synthetic occupancy. It verifies rejection of an extra insertion, a
new real handshake timeout, and byte-identical preservation of occupied entries.
Invalid records never represent valid forwarding authority.

Independent producer and two-peer traffic workers retain their own descriptors
while the real daemon restarts and regenerates the normal host/pod datapaths.
Every transferred payload must match its peer. The worker does not invoke any
collector or delete occupancy. Once restoration is ready, workers stop and join;
the daemon's real periodic GC must empty the stopped admission pressure within
20 seconds. A new connection through the second peer must transfer application
payload successfully. Both original socket owners and all thirteen map IDs and
six tracing-link IDs remain identical. TIME-WAIT ACK forwarding also survives
agent downtime/restoration; real FIN replay keeps the kernel lifetime alive.

The producer continues during startup/periodic GC; occupancy is not claimed to
remain full at every instant. Exhaustion is asserted deterministically while
the agent is down. This is finite controlled pressure with synthetic occupancy,
not sustained legitimate SYN-flood availability, fairness or capacity sizing.

Go vet for the modified fixture, host evidence/preflight tests and
`git diff --check` pass. No production behavior, map schema, hook count or
configuration API was changed.

## Reproduce

Build the static agent/live-test executables and use the existing trusted
kernel/module, QEMU, BusyBox, bpftest, Clang and extracted iptables arguments.
Add to `privileged_vm.py`, or pass through `kernel_matrix.py`:

```sh
--full-agent /opt/vtep-build/cilium-agent \
--source-bpf /opt/vtep-source/bpf \
--clang /opt/vtep-tools/clang \
--netfilter-root /opt/vtep-tools/netfilter-root \
--live-tests /opt/vtep-build/livetest \
--live-test-run '^TestPrivilegedRealAgentPressureProcess$' \
--timewait-packet-object /opt/vtep-build/timewait_packet.o \
--memory 2048M --timeout 1500
```

Require the exact root plus children `periodic_GC_preserves_TIMEWAIT_owner`,
`native_owner_bypasses_overlapping_VTEP_prefix` and
`SIGKILL_restart_under_live_pressure`, each prefixed with
`TestPrivilegedRealAgentPressureProcess/`, using repeated `--require-test`.
No previous-version binary is supplied; this is same-version restart coverage.

## Remaining gates

The full-agent fixture uses the supported no-policy identity allocator because
there is no Kubernetes/kvstore backend. It is not real Kubernetes/CNI, normal
identity allocation or NetworkPolicy validation. Actual policy/CT ordering has
separate packet-fixture coverage, which does not close this deployment gate.

Full-agent request/TIME-WAIT-map exhaustion, legitimate sustained connection
churn, native CPU/memory/latency measurements, multi-node rollout and v20-era
older-binary transitions under live pressure remain open. SYN-cookie forwarding
remains unsupported; subsequent candidate binding work must not change that
claim until trusted packet/child evidence and lifecycle support are complete.

## Evidence fingerprints

Raw logs and binaries are not committed. Fingerprints identify local evidence.

- `v22-agent-pressure-initial/linux68.log` — `32f5c2bf632c55ed89dc0c527ace80f86757f75357b8d46f4dfed0d7602edea9`
- `v22-agent-pressure-initial/linux68.json` — `9bb7c3a24ebdb87d0cd9c1fa97848e28d3bc8fed46e62aef6b4d0ce12e01e3a5`
- `v22-agent-pressure-initial/linux612.log` — `2a223727780e140ac30c46cc44666873a460654ef0fdbd6563a89661b9be4ecd`
- `v22-agent-pressure-initial/linux612.json` — `05c6029b9ca8c5b470b7afd36baf7c701f5b0d99038be42451f2fe513c4e8911`
- `v22-agent-pressure-initial/matrix.json` — `c003a148620dcae3516de52f522bd16daca473452baf4b3c3b809d6166207c35`
- `build-v22/cilium-agent` — `92bbf95495104f95c2fc245637b59b38c811baeb106694c675965a2fbdf524f8`
- `build-v22/livetest` — `71ba57339e14201d0b1f42fb10b8a1f54984185575da56e92f19b386afd05bc5`
