# v20 live pressure validation — 3 November 2026

## Change and upgrade requirement

Implementation checkpoint: `97b41df1b9`, based on local v19 `a20a22830d`.
Published v19 is `68df4b5971aeb548a0b2c2f715d3b5cb97ee0774`, with the same source
tree `8320b1abb75b8a573f143b8833ac724a66e1f26e` as that local baseline.
The upstream integration baseline remains `b28d8046`.

The new tests found that packet-association insertion failures were absent from
the existing `tw_packet_stats.pressure` counter. Through v19 only proof insertion
failures incremented it, despite the diagnostic's combined label. v20 increments
the same counter when `tw_output_packet` insertion fails as well. It counts
insertion errors, including collisions, not exclusively full-map drops.

**Drain selected pods and disable with the running older binary before upgrading
to v20.** Then upgrade, enable and recreate eligible pods. Use the corresponding
drain/disable sequence before rolling back. The counter fix changes tracing
program bytecode/tag; existing compatibility checks must refuse an in-place
replacement of older live hooks. Do not bypass tag checks or manually delete
pins/journal state. No new maps, hooks, map schema or routing authority are added.

## Final executed evidence

All guests are disconnected amd64 QEMU/TCG, 1,536 MiB and one vCPU. Packages were
downloaded/extracted without installing a kernel or QEMU on the host. The 6.8
packages came from Ubuntu's signed package indexes; the Canonical mainline 6.12
kernel/modules were checked against the publisher's SHA-256 list. The Cilium
Clang layer was checked against its pinned image-layer digest. Go is 1.27.3.

| Suite | Linux 6.8.0-31 | Linux 6.12.0-061200 |
| --- | --- | --- |
| Real pinned-map diagnostics and pressure | PASS, 2.06s | PASS, 1.70s |
| Controller restore preserves 13 maps / 6 tracing links | PASS, 3.40s | PASS, 3.14s |
| Partial/changed state refusal | PASS, 33.88s | PASS, 32.40s |
| Actual Cilium handshake-map pressure | PASS, 13.55s | PASS, 14.09s |
| Actual Cilium TIME-WAIT map pressure | PASS, 25.42s | PASS, 23.84s |
| Complete VM runner | PASS, 96.721s | PASS, 93.352s |

Both reports have no failed or skipped tests and finish with `VTEP_VM_EXIT=0`.
Conntrack/core BPF regressions pass in both guests. Durations are emulated test
execution times, not native packet-performance measurements.

The real-map test fills each of the five transient hashes to the production
capacity of 4,096 entries. Extra insertion fails, every old record remains,
the capacity reader reports full occupancy with unchanged IDs, and the kernel
refuses update/delete through read-only descriptors. Freeing one disposable test
slot lowers the observed occupancy and permits another insertion. It also checks
aggregate counters, unknown socket-local occupancy, missing-pin refusal and
replacement-pin detection against held canonical descriptors. The latter does
not claim the standalone reader knows an agent's historical IDs before startup.

The packet tests use eight-entry maps with invalid synthetic occupancy records
to trigger each real failure branch cheaply. They use actual bpf_lxc.c policy/CT
fixtures and real TCP sockets, for both AF_INET and mapped AF_INET6 listeners:

- Full admission/request maps reject new handshakes without changing an
  established socket's owner or application delivery. The real collector removes
  invalid/expired fixture records; new admission and the old flow work afterward.
- Full TIME-WAIT owner storage rejects a new transfer without evicting records
  or retargeting the established flow. After test slots are freed, a future
  connection transfers successfully. A previously lost TIME-WAIT owner is not
  reconstructed.
- Full packet/proof maps increment the corrected pressure counter, and a real
  replayed FIN produces no forwarded TIME-WAIT ACK. Existing application traffic
  and ownership survive. After capacity is available, replay produces the exact
  ACK through the original peer again. Expired proof fixtures are removed by the
  real collector. Packet-association fixtures have no real skb lifetime and are
  explicitly removed only by the disposable test; no automatic recovery or GC
  guarantee is inferred for those fake addresses.

The initial packet run failed waiting for the missing packet-stage counter.
That failed report remains separate. Final evidence below uses the corrected
object on both kernels. No failures are relabelled as passes.

Host unit/race tests, Go vet and strict BPF compilation pass. `conntrack.h` and
sampled flag-off executable sections remain byte-identical to baseline.

## Reproduce

Build objects with run_spike.py and static test binaries as described in README.
Supply kernel/module, QEMU, BusyBox and bpftest artifact arguments to the existing
VM runner. Add:

```sh
--agent-tests /opt/vtep-build/agenttests \
--agent-test-run '^TestPrivileged(CapacityReadOnlyAndPressure|TracingRestartPreservesCompleteGraph|TracingRejectsPartialOrChangedState)$' \
--runtime-object /opt/vtep-build/bpf_vtep_return.o \
--live-tests /opt/vtep-build/livetest \
--live-test-run '^TestPrivileged(HandshakeMapPressure|TIMEWAITMapPressure)$' \
--core-object /opt/vtep-build/socket_core.o \
--timewait-core-object /opt/vtep-build/socket_timewait_core.o \
--timewait-packet-object /opt/vtep-build/timewait_packet.o
```

Require all five exact roots in the evidence report. Also require every pressure
child: capacity's five map names, empty/counter and pin-refusal cases; each of
the two handshake-map names and three TIME-WAIT-map names under both
`mapped=false` and `mapped=true`; and changed-code/map/schema refusal children.
Use --require-test repeatedly and keep both JSON/log files. The sequential
kernel_matrix.py runner retains per-kernel outcomes. Missing or skipped required
tests must fail validation.

## Remaining gates

These are controlled correctness tests, not sustained legitimate-handshake load
or SYN-flood capacity measurements. Concurrent producer/GC pressure, prolonged
churn and restart while exhausted still need dedicated tests. Admission/request
failures still lack precise per-map production counters. Native A/B CPU, memory,
throughput and tail-latency measurements remain blocked by lack of KVM/native
test infrastructure here. No emulation-to-native extrapolation is made.

No full-agent v19-to-v20 transition, full-node reboot with workloads, multi-node
rollout or real Kubernetes/normal-identity/NetworkPolicy deployment was executed.
The controller tests are not substitutes for these gates. Kubernetes remains
deferred. SYN-cookie peer binding, collision/replay/pressure handling and agent
integration remain unimplemented; SYN-cookie forwarding is still unsupported.

## Evidence fingerprints

Only SHA-256 fingerprints are committed. Raw logs and artifacts remain outside
the source tree.

- `v20-pressure-final/linux68.log` — `f7bb1feb84b9d256e78188c0974100e3fad949b7fdb7c26c69d2d306ef5fe9a5`
- `v20-pressure-final/linux68.json` — `1eef0cbb4e62c1e20d597af8547340f7a220cd4ca9a37abf2118db339c3f0c5f`
- `v20-pressure-final/linux612.log` — `35e655303423899bd5bcdf5fec8034441cbeb165170694d05be928d662ff26f6`
- `v20-pressure-final/linux612.json` — `ef5d3a881fc074f5003346fafcb350db88a71332e0cc648d7a028b9efe4a02ac`
- `v20-pressure-final/matrix.json` — `2239322f05ce7f532871f08027f3dbfa337b98941f1eee97a217bd9596b7a5a6`
- `build-v20/bpf_vtep_return.o` — `1675170d5d19196be8ff25cd6785a9e1e8f43ece2d0085359755faf951f0d8b5`
- `build-v20/socket_core.o` — `444f7021f9cd85252aaf5f1d525f302ceb18dbeac7dc194e8426f8a172020b98`
- `build-v20/socket_timewait_core.o` — `fe6ae8ba39d81c22dcb2bea6aacf0739f5669bc6fe44b944b7a3fba51d7b97a7`
- `build-v20/timewait_packet.o` — `da137ff9fbb938c454673ee4736a7aa351a691b2e20b97af0ca3dcef28c0a745`
- `agenttests-v20` — `4e797ab83ccbb4cb44a9e1028f24d9cb6bed18090f5880aa9c4c81abed57c623`
- `livetest-v20` — `a391864de196816ff1cf81c92504d488f95b780d1a7f0f1b8901161f9023b10f`
