# v25 agent-managed trusted SYN-cookie handoff — 3 November 2026

Implementation `89fe4373da`, fixture sequencing `8f9a451e37`, actual-loader pruning fix `a8badddd9d`, following the
[v24 trusted packet-path checkpoint](VALIDATION-v24.md). The existing global
experimental option remains **off by default**. This is a scoped lab prototype,
not production readiness or upstream acceptance.

## Implementation

The real agent enables the cookie packet path only for selected endpoints,
using the existing configuration API. It manages the complete schema-3 bundle:
18 maps, eight tracing hooks, node sockops and both pod-side TCX directions.
The newly managed cookie maps are `cookie_peer_ledger`, `cilium_vtep_ck_ack4`,
`vtep_ck_child4`, `ck_output_packet` and `vtep_ck_stats`.

Cleanup/child hooks are installed before cookie issuance. CNI preparation
installs the pod-ingress guard and pre-queue stamper before namespace readiness
or application listeners. Restoration requires the original maps and tracing
links, exact kernel targets, relocated program tags and canonical map IDs.
Pod-side hooks additionally require the verified namespace/veth, correct
attachment direction, frozen namespace constant, canonical map bindings and
reviewed program tag. Compatible TCX updates preserve link IDs. Missing or
changed guards are refused; readiness/periodic collection detects subsequent
loss or replacement and retires namespace controls permanently.

The periodic agent collector expires ACK tickets and full-window cookie
records/tombstones. Expiring those records never deletes established socket
ownership. Cookie issued/bound/rejected/insertion-failure counters are included
in the existing operator-invoked read-only capacity diagnostic. Socket-local
storage occupancy remains explicitly unknown. Rejected does not mean map-full.

The map schema changes from 2 to **3**; journal format remains 2. There is no
live migration or arbitrary older-binary rollback. Drain selected pods and
disable with the previous binary before upgrading. Incompatible restoration
must preserve surviving state and fail readiness.

## Executed controller evidence

| Frozen-artifact VM suite | Linux 6.8.0-31 | Linux 6.12.0-061200 |
| --- | --- | --- |
| All 45 controller root/child test entries | PASS | PASS |
| Complete 18-map/eight-tracing-link restart | PASS | PASS |
| Missing tracing hooks, each new cookie map and schema v1/v2 | Refused | Refused |
| Changed tracing code or unrelated map binding | Refused | Refused |
| Missing/wrong-map/wrong-namespace/empty/changed-code cookie guard | Refused | Refused |
| Guard pin loss, map pin loss/replacement and schema damage | Readiness revoked | Readiness revoked |
| Real-map capacity and read-only diagnostic, including cookie counters/maps | PASS | PASS |
| Complete runner including conntrack/core regressions | PASS, 203.207s | PASS, 178.110s |

No skipped/failed required test, report error or unsuccessful VM exit is present
in these two final controller reports. These disconnected amd64 QEMU/TCG guests
validate correctness, not native performance.

Strict compilation of all 13 BPF objects with the daemon's integer/enum/fallthrough
warnings passes. `conntrack.h` remains byte-identical to baseline; sampled flag-off
executable sections remain identical. The actual daemon compiler exposed an
implicit collector return-width conversion; the helper now preserves `long`.
The isolated probe's explicit port narrowing was also made visible to the same
strict warnings. Go unit/race tests, loader template isolation, Go vet, four
Python evidence/preflight tests and `git diff --check` pass. Host race tests
skip privileged cases; guest test binaries are static and non-race.

## Executed full-agent evidence

Both final actual-daemon runs pass all 12 selected live root/child entries,
with no skipped/failed tests, report errors or unsuccessful VM exits.

| Actual-daemon scenario | Linux 6.8 | Linux 6.12 |
| --- | --- | --- |
| Forced-cookie children have exact peer/socket ownership | PASS | PASS |
| TIME-WAIT replies and active periodic proof GC | PASS, 10.70s | PASS, 10.79s |
| Ordinary native handshakes bypass an overlapping VTEP prefix | PASS | PASS |
| SIGKILL, forwarding/handshakes while down, same-version restoration | PASS, 211.13s | PASS, 208.92s |
| Older schema-2 agent refuses; current agent recovers live state | PASS, 244.73s | PASS, 320.73s |
| Expired cookie tombstones absent after recovery; owners survive | PASS | PASS |
| Retirement prevents ordinary-routing fallthrough | PASS | PASS |
| Pod replacement reuses address/interface name with fresh ownership | PASS, 68.35s | PASS, 3.06s |
| Unsafe disable refused; recovery preserves live traffic | PASS, 256.87s | PASS, 248.30s |
| Coordinated drain, full hook/pin removal, ordinary TCP with feature off | PASS, 343.17s | PASS, 332.22s |
| Actual-loader pruning/replacement regression | PASS, 0.07s | PASS, 0.05s |
| Complete daemon test | PASS, 1482.46s | PASS, 1466.50s |
| Complete runner including conntrack/core regressions | PASS, 1516.595s | PASS, 1500.537s |

Restoration preserves all **18 canonical map IDs**, **eight tracing-link IDs**
and **both pod-side TCX link IDs**. Existing cookie connections and TIME-WAIT
replies continue while the process is dead. Fresh kernel-cookie children bind
to the correct peer both while the agent is down and after it restarts.
The older executable is a distinct v22/schema-2 prototype, not a released binary.
It reports the expected schema refusal and failed readiness without replacing
surviving state; the current agent recovers the same graph and owners.

The expiry assertion runs after a long recovery, when cookie records have
already expired and been collected. It verifies post-recovery collection and
owner survival; its near-zero duration is **not** a fresh-record, steady-state
expiry measurement. Periodic daemon invocation is independently exercised by
TIME-WAIT proof GC. v24 separately times genuine cookie-window expiry and
collection with eight real established bindings. No clock or valid expiry field
is edited to make these tests pass.

Initial failed runs remain failed evidence. The actual daemon compiler first
exposed the collector conversion warning described above. Later cold emulated
base/endpoint compilations overlapped the endpoint API's generation budget;
the fixture now waits for independent base/host readiness before timed endpoint
creation, retaining the production deadline. The next endpoint load exposed
Cilium's map-pruning interaction: runtime-only cookie maps were removed from the
collection while their replacement entries remained, making ebpf-go reject it.
The loader now removes replacements only for originally declared maps proven
unused. The dedicated actual-loader regression verifies preserved used map IDs,
an unchanged caller descriptor set, and continued rejection of unknown names.
Both final runs include that fix. No failed report was relabelled as success.

The two disconnected amd64 guests ran concurrently, each with two vCPUs and
2,048 MiB under QEMU/TCG. These durations include repeated cold daemon/compiler
starts and are correctness-test durations, not performance evidence.

## Scope and remaining gates

[v24](VALIDATION-v24.md) records real forced-cookie forwarding through both peers,
both AF_INET and IPv4-mapped AF_INET6 listeners, ingress-policy denial, exact
kernel child ownership, collision/replay/pressure cases and real-window expiry.
The cookie handoff does not infer ownership from a reusable tuple or accept a
nonce without the corresponding original packet/kernel-child evidence.

Supported cookie timing is restricted to the reviewed Linux **6.8.0-31-generic**
and **6.12.0-061200-generic**, exactly `CONFIG_HZ=1000`. The matching trusted kernel
configuration must be readable at `/proc/config.gz` or `/boot/config-<release>`.
An estimated timer rate or a missing/unreviewed configuration is refused.

- External configured VXLAN peers, direct IPv4/TCP, veth/TCX, BPF host routing,
  kube-proxy replacement and newly selected namespaces remain the contract.
- Forced native/ordinary-cluster SYN-cookie handshakes remain unsupported;
  ordinary native handshakes remain covered separately.
- No tenant isolation or simultaneous identical established tuples per peer;
  separate policy identities per peer remain unresolved.
- Services/NAT, proxies/ztunnel, encryption, IPv6, Geneve, netkit, TFO/SYN data,
  fragments/IP options and general socketless data/reset replies remain outside scope.
- Missing/expired authority or insertion/allocation failure grants no forwarding
  authority. Some failure paths can leave a kernel-created child without an
  owner; this does not promise pre-stack rejection in every allocation/state-loss race.
- Complete authoritative ownership loss requires affected connections to reconnect.
- Kubernetes/CNI with normal identity allocation and NetworkPolicy remains deferred.
  The actual-daemon fixture uses Cilium's no-policy allocator and policy `never`;
  v24's actual policy/CT fixture is separate evidence.
- Native CPU/memory/latency/throughput, sustained legitimate load, broader kernel
  coverage and production rollout/rollback validation remain outstanding.

## Frozen artifacts and reproduction

The final controller binaries/objects were frozen before their two-kernel runs.
The later fixture sequencing and generic collection-loader fix do not change
the controller package or BPF code. Agent runs use a separate frozen artifact
directory containing the rebuilt agent and live test.

| Artifact | SHA-256 |
| --- | --- |
| Current `cilium-agent` | `4e315b3974abcd7547d01658169881f546c170516ec617ebe6d275f28d4c2359` |
| Live test with explicit startup ordering | `43e7e34948cc2da74a86acb44005642d3bc133671cf727754c4fafda7442171f` |
| Runtime BPF object | `c0062f016c24244fd0bb10b73467689ba4ba29fda0bc429bb22d4e660e4c0983` |
| Controller test binary | `acfb056769c5cfd371383180522781437b169b11a5a35952037fac910c354d5b` |
| Previous schema-2 agent (v22) | `92bbf95495104f95c2fc245637b59b38c811baeb106694c675965a2fbdf524f8` |
| Linux 6.8 kernel | `529a76e832d2b92041ab3f7355b70b096263aa971dbace1ffca7bf23d0497f4d` |
| Linux 6.12 kernel | `144439e925a02129b01c74a37a73466494cac3876d65bc3850e3b9f1b260d44c` |

Build with the Go version required by `go.mod` and Cilium's supported Clang:

```sh
python3 contrib/vtep-return-affinity/run_spike.py --clang "$CLANG" --output "$BUILD"
CGO_ENABLED=0 go build -trimpath -o "$BUILD/cilium-agent" ./daemon
CGO_ENABLED=0 go test -c -o "$BUILD/livetest" ./contrib/vtep-return-affinity/live
CGO_ENABLED=0 go test -c -o "$BUILD/agenttest" ./pkg/datapath/vtep/returnaffinity
```

Use `privileged_vm.py` with the explicit trusted kernel/modules/config,
BusyBox, BPF runner, compiled objects, Clang, source tree and iptables runtime.
For the actual-daemon case select `^TestPrivilegedRealAgentCookieProcess$`, pass
`--full-agent`, `--source-bpf`, `--timewait-packet-object`, `--cpus 2`,
`--memory 2048M`, and an adequate outer correctness-test timeout. Require the
root and all lifecycle subtests with `--require-test`; a skipped or absent test
must not count as success.

For incompatible rollback supply the **distinct** previous v22 executable and
its own BPF source from v23 `c98727e31d`, using
`--previous-agent-mode incompatible-schema`. The previous program does not
support v3: the expected result is failed readiness, preserved state and safe
recovery with the current agent. Do not substitute current sources for the
older binary or call this compatible live rollback.

For controller tests provide `--agent-tests`, `--runtime-object` and require the
socket lifecycle, tracing restore/partial-state, cookie guard damage/readiness,
capacity and runtime-map-damage suites. The runner also executes existing
conntrack/core BPF regressions and records exact kernel/artifact provenance.
Do not replace these correctness results with a performance claim from TCG.
