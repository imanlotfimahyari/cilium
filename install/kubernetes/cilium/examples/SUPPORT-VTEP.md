<!-- This file was not reviewed by a human before submission -->

# Current VTEP return-affinity support and validation

Canonical source: `contrib/vtep-return-affinity/SUPPORT.md`. The chart's
`examples/SUPPORT-VTEP.md` is a byte-for-byte generated copy; edit this source
and copy it when packaging. Other design/runbook documents describe mechanisms,
not a separate support contract. Historical `VALIDATION-v*.md` reports record
only their named checkpoints.

Integration snapshot: upstream `7d0c8c64dbdba8e101b35cd502371ea762590183`,
6 November 2026, on `experimental/vtep-return-affinity-lab-v29`.
This remains an experimental, default-off personal-fork feature.

## Implementation and evidence

| Capability | Implementation | Validation boundary |
| --- | --- | --- |
| External-peer connection-specific IPv4/TCP return path | Present; immutable socket-owned peer, normal Cilium policy/CT ordering | Two-kernel isolated packet/agent evidence at v29; refreshed-main checks recorded separately |
| AF_INET and AF_INET6 listeners accepting IPv4 | Present; both mapped addresses checked against kernel IPv4 fields | Tested in isolated fixtures; IPv6 forwarding is outside scope |
| TIME-WAIT pure IPv4 ACK replies | Present; exact socket-incarnation transfer and one-time packet proof | Tested with queued ACKs, tuple reuse, policy/CT, duplicates and GC under the reviewed buffering contract |
| Trusted external VXLAN SYN cookies | Present; SYN/SYN-ACK/ACK evidence binds the exact kernel-created child | Forced-cookie, replay/collision, expiry/pressure and agent lifecycle evidence at v24-v29 |
| Agent initialization/restoration/cleanup | Present; canonical pins, readiness, periodic GC, endpoint retirement and drain/disable | Current-agent SIGKILL/restart and replacement passed in v29 disconnected VMs; standalone allocator is no-policy |
| Bounded maps/history and diagnostics | Present; no eviction of established ownership; read-only map/stage/headroom report | Controlled pressure tests and unit/race checks; sustained legitimate native throughput remains unmeasured |
| Helm chart, full defaults and EKS/VTEP example | Present; `vtep.experimentalReturnAffinity.enabled=false` | Render/lint/package tests; images have not been built/run on EKS here |
| Actual Kubernetes CNI, normal identities and NetworkPolicy together | Harness present | Not executed; separate packet-policy fixtures do not establish combined cluster behavior |
| External peers on multi-host EKS | Forwarding implementation present | EKS peer provisioning/execution adapter and real-cluster validation remain required; existing Docker adapter is kind-only |
| Rolling node operations and arbitrary older-binary rollback | Strict restore refusal/drain procedures present | Only named prototype transitions have historical evidence; real node operations and released-version compatibility remain pending |

See `contrib/vtep-return-affinity/VALIDATION-main-20261106.md` for refreshed-main
checks. Last full-daemon live evidence is `VALIDATION-v29.md`; merging main does
not rerun or extend that result automatically.

## Supported experimental configuration

| Area | Current contract |
| --- | --- |
| Kernel/architecture | Exact reviewed Ubuntu builds `6.8.0-31-generic` and `6.12.0-061200-generic`; amd64 lab coverage, cgroup v2, BTF/fentry/fexit and required BPF helpers |
| SYN-cookie timing | Exactly CONFIG_HZ=1000 and validated kernel function signatures; config readable through `/proc/config.gz` or matching `/boot/config-<release>` |
| AL2023 | Unsupported by the current exact-build guard; needs reviewed timing/ABI support and live validation, not an allowlist-only bypass |
| Datapath | IPv4 TCP, VXLAN over IPv4, veth/TCX, BPF host routing, kube-proxy replacement, direct pod connections |
| Selection | Newly created eligible synchronous CNI endpoints; recreate existing pods to opt in; install hooks before listening |
| Peers | Exact configured outer IP/VXLAN MAC pairs; client ranges separate from node/pod/Service ranges; underlay must enforce trusted origins |
| Configuration lifecycle | Startup-only flag; explicit agent rollout; peers frozen while active; physically drain selected pods before disable/reconfiguration/rollback |
| State compatibility | Canonical map schema 3 and journal format 2; restore requires compatible map IDs/program tags/hooks/boot/history; incomplete state refuses readiness |

Exact peer matching is not cryptographic authentication. Return affinity does
not provide tenant isolation or separate policy identities per external peer.

## Unsupported paths and fundamental limits

| Area | Limit |
| --- | --- |
| Network integrations | Services/NAT translations, Geneve, netkit, endpoint routes, IPv6, IPsec/WireGuard, proxies/ztunnel and peer failover |
| TCP paths | Native/ordinary-cluster SYN-cookie handshakes, SYN payload/TFO and general socketless data/reset replies |
| Packet forms/buffering | IP options/fragments and arbitrary neighbor buffering/cloning/offload combinations outside the reviewed proof path |
| Tuple isolation | Simultaneous identical TCP tuples in one network namespace cannot receive independent peer ownership; demonstrations use distinguishable tuples |
| Unknown ownership | Drop without prefix/tuple-based fallback; unsupported paths or lost proof can fail connections |
| Complete authoritative ownership loss | Affected connections must reconnect; the original peer cannot be reconstructed from absent information |

TIME-WAIT and external-cookie support are implemented within the narrower
contracts above; old statements that either is wholly unimplemented describe
historical checkpoints only.

## Capacity and operational costs

- Existing agent configuration admits eight peers; the exact-peer map has 64
  slots. Namespace controls/nonce histories have 1,024 entries. Transient maps
  and the TIME-WAIT owner map have 4,096 entries each.
- Established ownership and temporary child evidence use socket-local storage;
  transient map counts are not a total kernel memory bound. Failed allocation
  grants no authority. Pressure can reject new handshakes/handoffs/proofs while
  existing owners remain intact. Agent outages pause collection.
- The complete graph has 18 maps and eight tracing hooks, plus sockops,
  selected-pod ingress/pre-queue TCX hooks and endpoint retirement guards.
  No safe tracing-hook removal has been established.
- Journal admissions plus exact retired-cookie ranges are capped at 8,192;
  input/output recovery data are capped at 64 MiB. Sparse churn can exhaust
  history capacity; never erase history to bypass admission or restore checks.
- Saved SYNs, socket storage and common-path hooks add unmeasured CPU/memory
  overhead. Read-only occupancy samples are not health verdicts, per-map
  insertion-failure counters or reserved capacity guarantees.

These bounds are runtime contracts, not additional configurable Helm fields.

## Remaining production gates

1. Port and validate the actual target kernel, initially the intended AL2023
   build; retain strict ABI/timing checks and both existing kernel regressions.
2. Build/run the matching full agent/operator images. Execute real CNI, normal
   identities/policy, cross-node/external-peer traffic, restart and replacement.
3. Exercise node reboot, rolling upgrades, interrupted upgrades and explicitly
   supported older-binary recovery with documented operational procedures.
4. Measure native throughput, latency, handshake rate, CPU/memory and pressure
   behavior with controlled resources, loss/reordering and offload settings.
5. Obtain independent architectural/security review, actionable diagnostics and
   an agreed maintenance/support scope. Optional protocols are separate extensions.
