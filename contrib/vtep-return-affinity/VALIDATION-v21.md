# v21 concurrent pressure validation — 3 November 2026

Implementation checkpoint: `6e0669026b`.

## Scope and compatibility

Based on published v20 `dbefdca81a50366d5a9b985c0d40dc7b18c8dfef`, matching
local `9ed0b56fb7c9914aed4e640422db300bdf2dedb1`, tree
`e17a43f85ebd9a72680f6eed06e7fa1cee43ea86`. The upstream integration baseline
remains `b28d8046`.

This checkpoint adds two test files and documentation. There is no production
program, map, schema, flag or forwarding behavior change. It reuses the exact
v20 BPF objects; their fingerprints are recorded below. v20's drain/disable
requirement when upgrading older live tracing programs remains in force.

## What the tests establish

`TestPrivilegedConcurrentPressureReload` runs four independent cases: admission
or request-map pressure, each with AF_INET or IPv4-mapped AF_INET6 listeners.
The eight-entry packet fixtures use actual Cilium policy/CT and real TCP.

1. Establish separate sockets through both external peers and retain their exact
   socket owners. Fill the target map with invalid synthetic occupancy records.
2. Verify a new real handshake times out on the specific admission/request
   rejection path, without modifying any occupied test record.
3. Run three workers together: refill invalid occupancy, execute real BPF GC,
   and continuously transfer peer-specific payloads on both established flows.
   Workers hold independent descriptors and return errors to the test goroutine.
4. Perform two compatible warm program reloads through Cilium's collection
   loader with canonical map replacements and link updates. Workers continue
   running; map identity and both socket owners must remain unchanged.
5. Stop and join workers, let pending tickets expire, then use real BPF collection
   to empty admission/request storage. Verify new admission through the other
   peer, exact ownership and application traffic on both original connections.

The producer writes deliberately invalid synthetic entries, never forwarding
authority. This is controlled contention and recovery, not legitimate SYN-flood
or throughput evidence. Full-map rejection is asserted before concurrent GC;
it is not assumed that every instant of the concurrent phase is full.

`TestPrivilegedControllerRestartUnderPressure` exercises the production controller
and complete production-capacity map bundle independently of the live fixture.
It fills the owner and packet hashes to 4,096 entries with invalid synthetic
records, while a worker inserts collectible invalid admission/request/proof
records and repeatedly checks that extra owner/packet inserts are rejected.
The worker keeps its descriptors open across controller downtime.

Across two close/start/initialize cycles, all thirteen map IDs and six tracing-link
IDs must remain unchanged. Startup and explicit production collector runs execute
while the worker continues. Readiness succeeds without deleting the full owner or
packet hashes. After joining the worker, real GC removes invalid collectible records;
every occupied owner/packet record remains byte-identical. The test deliberately
does not invent expiry evidence to reclaim those lifetime-owned maps.

These are complementary tests, not one full-agent test combining real sockets
and a daemon SIGKILL under pressure. No new forwarding authority is fabricated
or injected into a running deployment.

## Final executed evidence

All guests use the trusted amd64 Linux 6.8.0-31 and 6.12.0-061200 kernels,
QEMU/TCG, 1,536 MiB and one vCPU. Go is 1.27.3. These emulated durations are
not native packet-performance measurements.

| Final suite | Linux 6.8 | Linux 6.12 |
| --- | --- | --- |
| Controller restart with production-size occupied maps | PASS, 12.42s | PASS, 8.92s |
| Two-peer traffic with concurrent pressure/GC/reload, both listener families | PASS, 42.33s | PASS, 47.97s |
| Conntrack and Cilium core BPF regressions | PASS | PASS |
| Complete final VM runner | PASS, 79.255s | PASS, 77.983s |

Both final reports have no failed/skipped tests or errors, and both guests finish
with `VTEP_VM_EXIT=0`. Every required root and child executed. The controller
producer completed 603 and 660 rounds respectively. Live workers completed
1,761–2,291 two-peer payload rounds per case on 6.8, and 2,235–2,616 on 6.12.
These are finite correctness assertions, not workload-size or fairness guarantees.

The host controller package unit/race invocation and Go vet for controller/live
packages pass. Privileged cases execute in the guests using static, non-race
binaries; the host race invocation does not exercise privileged kernel paths.
`git diff --check` passes. No production source changed from v20.

A preliminary broader run used a one-peer version of the live workload. Final
results above use the strengthened two-peer source. Its evidence is not
silently substituted for the final test.

## Reproduce

Use the trusted kernels, modules, QEMU/TCG, BusyBox and unchanged v20 BPF objects
described in [v20 validation](VALIDATION-v20.md). Build static test binaries from
this checkpoint with Go 1.27.3:

```sh
CGO_ENABLED=0 go test -c -o /opt/vtep-build/agenttests ./pkg/datapath/vtep/returnaffinity
CGO_ENABLED=0 go test -c -o /opt/vtep-build/livetest ./contrib/vtep-return-affinity/live
```

Add these selectors to the existing VM/kernel-matrix runner:

```sh
--agent-tests /opt/vtep-build/agenttests \
--agent-test-run '^TestPrivilegedControllerRestartUnderPressure$' \
--runtime-object /opt/vtep-build/bpf_vtep_return.o \
--live-tests /opt/vtep-build/livetest \
--live-test-run '^TestPrivilegedConcurrentPressureReload$' \
--core-object /opt/vtep-build/socket_core.o
```

Require both exact roots and all four live children with repeated `--require-test`:
`TestPrivilegedConcurrentPressureReload/mapped={false,true}/{cilium_vtep_admit4,cilium_vtep_req4}`,
expanding both sets into four separate arguments. A missing or skipped required
test must fail the evidence report. Retain independent JSON/log files for each
kernel. The final runs retain conntrack/core BPF regression suites as well.

## Remaining gates

- Full-agent SIGKILL/restore under live concurrent pressure; these tests exercise
  controller restart and packet-program reload in separate fixtures.
- Sustained legitimate connection churn, load fairness and concurrent pressure
  across TIME-WAIT owner/packet/proof producers. v20's TIME-WAIT pressure evidence
  remains sequential, not concurrent workload validation.
- Native CPU/memory, throughput and tail-latency A/B measurement. TCG results are
  correctness evidence only. No native test or KVM device was available here.
- Real Kubernetes/CNI with normal identities, NetworkPolicy and rollout/drain.
- SYN-cookie trusted peer binding and collision/replay/pressure tests. Production
  SYN-cookie forwarding remains unsupported; the test-only v18 probe is unchanged.

## Evidence fingerprints

Only fingerprints are committed; raw logs, test binaries and build artifacts
remain outside the source tree.

- `v21-concurrent-final/linux68.log` — `0e3a8b42e356c87cca8b2154174987b19ef3b876f67a2b0364a4b9249f000933`
- `v21-concurrent-final/linux68.json` — `ce9857ac992e020276d4327c953692dd98183ff17d25fba1fcaeee7796dd083c`
- `v21-concurrent-final/linux612.log` — `0afd370cedada49898c488afe3582b0f67131236048ec763aa77c0d492e59cbf`
- `v21-concurrent-final/linux612.json` — `a5e5ce9e6ca8634296ae0f26bec4b46670575b5fac3e001c9c17779b42cb9177`
- `v21-concurrent-final/matrix.json` — `89a8c2195f9c4e45a9bf22c90cff599c0807b53661f24ddf852e5768523e41b6`
- `agenttests-v21` — `7ab16e99ed079e7072346ed0a0f2d820c1841508e830c5105c9cf07cd8f7e404`
- `livetest-v21-final` — `0ebfa4db564bb1f74f50738c35c46edf9c992f00b6000a0148c638af05c27255`
- `build-v20/bpf_vtep_return.o` — `1675170d5d19196be8ff25cd6785a9e1e8f43ece2d0085359755faf951f0d8b5`
- `build-v20/socket_core.o` — `444f7021f9cd85252aaf5f1d525f302ceb18dbeac7dc194e8426f8a172020b98`
