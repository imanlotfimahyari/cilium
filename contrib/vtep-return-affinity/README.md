# Experimental IPv4/TCP VXLAN return affinity

**v16:** strict recovery decoding rejects ambiguous/future JSON and oversized
inputs without rewriting history. Reviewed BTF signatures select the TIME-WAIT
publication point on Linux 6.8 and 6.12 without adding hooks or changing maps.
The lab now includes offload modes, loss/retransmission and real two-boot
controller recovery. See [v16 validation and remaining gates](VALIDATION-v16.md).
SYN-cookie forwarding and native performance remain open.

**v15:** the default-off experiment detects loss or replacement of every
canonical map pin, as well as tracing-hook pin damage. It retires selected
namespace controls and refuses readiness instead of continuing with an
unrestorable graph. TIME-WAIT tests now exercise the actual Cilium policy/CT
consumer, including denial, malformed proofs and one-time duplicate rejection.
See [TIME-WAIT behavior](TIMEWAIT.md) and [v15 validation](VALIDATION-v15.md).
Kubernetes remains deferred to the final real-cluster checkpoint.

Original baseline: Cilium `fe561573e0a8adc43bacbcc70bda0c9e01d6676d`.
Current integration baseline: upstream `b28d80469415d4494a1a9d86ae18ee2de8a5146b`.
Use case: [cilium/cilium#46159](https://github.com/cilium/cilium/issues/46159).
No public PR or maintainer message has been created. This is not production
ready or accepted upstream. See [design review](REVIEW.md) and
[Kubernetes lab instructions](k8s/README.md).

## Supported lab contract

Enable `--enable-experimental-vtep-return-affinity=true` together with the
existing `--enable-vtep` and exact VTEP endpoint/MAC configuration on a dedicated
lab node. New synchronous CNI endpoints are selected when IPv4-only, with a
namespace cookie/path and veth interface. Existing restored endpoints without
the persisted selection property keep their previous behavior. Recreate pods to
opt in. Clients cannot set the server-owned property through the endpoint API.

Require IPv4-only VXLAN over IPv4, veth, TCX, BPF host routing and kube-proxy
replacement. Disable L7 proxies, endpoint routes, IPsec and WireGuard. The
controller rejects unsupported node settings. Supported listeners include
AF_INET and IPv4-mapped children of AF_INET6 listeners, with both mapped
addresses checked against kernel IPv4 fields. IPv6 forwarding is not enabled.

External client ranges must not collide with Kubernetes node, pod or service
address space. Exact peer configuration is not cryptographic authentication;
the underlay must enforce trusted traffic origins.

Services/NAT, proxies/ztunnel, SYN cookies, SYN payload/TFO, IP options/fragments,
socketless data/resets remain unsupported. TIME-WAIT supports pure IPv4 ACKs
under the tested kernel/buffering contract. Unknown
ownership drops instead of selecting a peer by client prefix. Native traffic
must use a known Cilium route; arbitrary host-stack fallback stays forbidden.
Geneve, netkit, IPv6 and peer failover are outside this experiment.

Return affinity is not tenant isolation. Simultaneous identical TCP tuples in
the same namespace and separate policy identities per external peer are not
provided. The demonstrations use distinguishable connections, including shared
client addresses with different client ports. Complete loss of authoritative
peer ownership still requires affected connections to reconnect.

## Structure and packet path

- `bpf/lib/vtep_return_socket.h`: policy-approved SYN tickets, kernel request
  binding, immutable socket storage, IPv4/mapped-IPv4 callbacks and transient GC.
- `bpf/lib/vtep_return_core.h` / `bpf_lxc.c`: admission after normal ingress
  policy and reply selection after ordinary egress policy/connection tracking.
- `bpf/bpf_vtep_return.c`: node cgroup sockops, selected pod pre-queue TCX,
  transient collection, TIME-WAIT producers and independent retirement drop guard.
- `bpf/lib/vtep_return_timewait*.h`: kernel-incarnation transfer/destruction,
  exact-skb handoff, one-time proof consumption after normal policy/CT and proof GC.
- `pkg/datapath/vtep/returnaffinity`: shared agent/loader controller, pinned map
  bundle, readiness, durable journal, lease and endpoint lifecycle.
- `contrib/vtep-return-affinity/live`: real-socket, actual endpoint and real-agent
  fixtures. `k8s/` contains the separate executable Kubernetes checkpoint.

Trusted ingress records the exact external peer or explicit native origin.
A never-reused 46-bit nonce in the final internal SYN source MAC carries an
opaque admission token. `TCP_SAVE_SYN=2` and sockops callbacks validate the saved
SYN, namespace/generation, tuple, ISN and actual kernel request cookie, then
publish the owner on the accepted full socket before reclaiming request state.
The nonce alone grants no forwarding authority.

A pre-queue pod hook stamps exact TIME-WAIT ACK proofs and approved request
SYN-ACKs so host TC can verify them even when a qdisc orphans the request skb. ARP, active SYNs and application
data continue to normal processing. Data replies require the actual socket
owner; the handshake fallback never authorizes application data. FIN, CT loss
and inactivity are not used as evidence to delete a live owner. Kernel socket
lifetime reclaims established storage.

The older CT-bit and tuple-guard experiments and their unused controller/tests
have been removed. `bpf/lib/conntrack.h` is byte-identical to baseline; sampled
flag-off executable BPF sections remain identical. Earlier experiments remain
available in the separate v8 patch, not in this implementation.

## Agent lifecycle and bounded history

Startup takes a process lease and validates boot ID, exact peers and the durable
journal. It restores the complete canonical map bundle/schema and pinned links;
missing or incompatible members are never silently recreated. Hooks, peers and
initial GC are initialized before readiness; collection runs every five seconds.
Normal agent exit closes descriptors and preserves pinned forwarding state.
Tracing links are reused without a detach gap only when the kernel BTF target,
attachment type, program tag and exact map IDs agree. Cleanup hooks precede
producers on fresh install. A missing/replaced map or hook pin, or changed schema marker, permanently revokes readiness
and retires selected controls. Drain/disable stops producers before cleanup hooks
and then removes the graph. This is not a live tracing-code upgrade mechanism.

The map schema is now **2**, separate from journal format 2. Before upgrading
an older live prototype, drain its selected pods and disable with the old binary;
then upgrade and recreate selected pods. In-place schema migration is refused.

Synchronous CNI preparation verifies the actual namespace cookie, host/peer veth
indices and absence of pre-existing TCP listeners/sockets. PREPARING is durable
before installing a fresh namespace's nonce counter and pre-queue hook. After
normal endpoint programs, routes and pins commit, a second census precedes READY
and CNI completion. Partial installation requires pod replacement. Warm reload
preserves socket maps and nonce history, rather than retrofitting listeners.

Deletion records RETIRING and installs an independent host-veth ingress drop
guard before ordinary endpoint links are removed. It retires control and reclaims
bounded kernel entries. Once the old veth and namespace binding are physically
drained, collection removes their auxiliary links and compacts the full
membership into exact retired-cookie ranges. Gaps remain usable by unrelated
namespaces; an old selected cookie is never reopened through native routing.

New registrations are bounded by **8,192 combined full memberships and retired ranges**.
Adjacent cookies compress, so 100,000 contiguous retired cookies need one range.
Sparse churn may reach the bound: new registrations then fail explicitly while
existing history remains intact. Clear history through coordinated drain,
disable and verified reboot; never erase the journal to bypass recovery checks.
Recovery input and output are independently capped at 64 MiB. Non-regular
files, duplicate/case-aliased fields, noncanonical namespace keys, unknown
fields and trailing JSON are refused; original history is preserved.
This bounds normal journal growth without assuming every earlier cookie belonged
to the experiment. Old oversized journals are preserved and block new admissions.

Journal version 1 migrates to version 2 on durable publication. Older v1-only
binaries reject v2. The independent canonical map schema is now 2. Existing listeners
created before the AF_INET6 extension need pod recreation to obtain the new
listen callback behavior.

Map capacities are 1,024 namespace controls, 64 exact-peer slots and 4,096
records in each transient map and the TIME-WAIT owner map. Existing VTEP agent configuration allows eight
peers. Established ownership is separate kernel socket storage. Non-evicting
map pressure rejects new admissions or TIME-WAIT handoffs/proofs, depending on
the exhausted map. Agent outages pause collection and can fill
pending maps; existing owners are not evicted.

## Disable, recovery and rollback

Drain selected pods through CNI deletion, stop their traffic, remove their old
veths/namespace bindings, then restart the feature-aware agent with the flag off.
It verifies physical drain before removing custom pins. Frozen peers can be
changed after this coordinated disable. Missing state, changed boot or changed
peers while active fail restoration. Never remove the journal or replace owner
maps with empty maps to force startup.

Same-boot retired history survives disable and forbids CNI retries that would
reuse an old selected namespace under ordinary routing. A new namespace cookie
is eligible. Older-binary rollback has not been validated. Drain/disable is a
prerequisite,
and a v1-only binary rejects a v2 journal. The [offline exporter](DOWNGRADE.md)
preserves cookie history in v1 format after a successful coordinated disable.
Actual older-daemon rollout remains untested. Do not simply remove the journal.
Total peer-state loss cannot transparently recover old connections.

## Validation status

The current privileged runner uses disconnected QEMU/TCG, Linux 6.8.0-31,
cgroup v2/BTF, veth/TCX/VXLAN and explicit trusted test artifacts. It exposes no
host filesystem or external network. Historical v14/v15 results cover one kernel/topology. The v16 controller/packet
matrix adds Linux 6.12; it is not full-agent/Kubernetes coverage on that kernel
or a native performance measurement.

The v14 recovery validation passes in three freshly executed VM runs, each
ending with `VTEP_VM_EXIT=0`: controller lifecycle/faults, packet regressions,
and the actual daemon lifecycle. The full daemon test takes 785.79 seconds under
TCG and includes actual TIME-WAIT ACK forwarding, periodic proof GC, SIGKILL and
restart preserving all thirteen map and six tracing-link identities, retirement,
pod replacement, unsafe-disable refusal/recovery, and coordinated drain/disable.
It verifies complete hook removal and ordinary TCP after disable.

Unit tests, loader template isolation, focused strict BPF compilation, sampled
flag-off bytecode equivalence, Go vet and `git diff --check` also pass.
See [v14's exact validation scope](VALIDATION-v14.md) and the subsequent
[v15 checkpoint](VALIDATION-v15.md), whose latest-main controller/packet and
actual-daemon VM runs both pass with `VTEP_VM_EXIT=0`.

The actual daemon fixture uses the no-policy identity allocator and policy
`never`. Separate actual endpoint regressions exercise Cilium policy/CT; this
is not full-cluster identity/NetworkPolicy validation. Kubernetes remains deferred,
as do broader kernel, performance, rollout and SYN-cookie work.

## Reproduce focused checks

Use Go matching `go.mod` and Cilium's Clang. With tools on PATH:

```sh
go test ./pkg/datapath/vtep/returnaffinity ./pkg/datapath/loader \
  ./pkg/datapath/vtep ./pkg/endpoint ./pkg/status
go test -race ./pkg/datapath/vtep/returnaffinity
go vet ./pkg/datapath/vtep/returnaffinity \
  ./contrib/vtep-return-affinity/live ./contrib/vtep-return-affinity/k8s/probe
python3 -m unittest discover -s contrib/vtep-return-affinity/k8s -p 'test_*.py'
python3 contrib/vtep-return-affinity/run_spike.py --clang clang --output /tmp/vtep-build
```

Build static test binaries for the isolated VM:

```sh
CGO_ENABLED=0 go test -c -o /tmp/vtep-build/bpftest ./bpf/tests/bpftest
CGO_ENABLED=0 go test -c -o /tmp/vtep-build/agenttests ./pkg/datapath/vtep/returnaffinity
CGO_ENABLED=0 go test -c -o /tmp/vtep-build/livetest ./contrib/vtep-return-affinity/live
```

Run `privileged_vm.py --help` for trusted kernel, BusyBox, QEMU/module paths,
object inputs and log output. Supply `--runtime-object`, `--agent-tests`,
`--live-tests`, `--handoff-object`, `--core-object` and optionally
`--socket-object`. The runner's final `VTEP_VM_EXIT=0` is required for success.
`--full-agent` additionally needs `--clang`, `--source-bpf` and an appropriate
iptables runtime through `--netfilter-root`; it executes actual daemon restart
and regeneration, not just controller reconstruction.

Do not run these root-cgroup/TC tests on a shared node. They require both
`PRIVILEGED_TESTS=1` and `VTEP_RETURN_ISOLATED_VM=1` inside the disposable guest.
For actual cluster validation follow [k8s/README.md](k8s/README.md). Missing tools,
skipped tests and unimplemented TCP paths are recorded as such.

For the complete real-daemon lifecycle sequence, supply `--full-agent`,
`--clang`, `--source-bpf`, `--netfilter-root`, and
`--timewait-packet-object`, then select
`--live-test-run '^TestPrivilegedRealAgentProcess$'`. The packet object supplies
only a receiver sink in that test; the agent installs every forwarding hook.
The netfilter directory must contain the required iptables runtime and shared
libraries. The daemon retains its required `--install-iptables-rules=true`.

Validated milestones are retained as local Git commits. See
[checkpoint and backup workflow](CHECKPOINTS.md).

## Actual-agent prototype transitions

The VM runner can package a current agent and a distinct previous agent, each
with its own BPF source tree. Both are executed with the `cilium-agent` basename
because Cilium uses the executable name to select agent initialization. Before
each start, the fixture stages that version's BPF tree at the same canonical
path. This models source replacement without path-dependent compilation tags;
it never changes the journal or pins to make an incompatible version fit.

Additional artifact arguments:

```sh
--full-agent /tmp/vtep-build/cilium-agent-v16 \
--source-bpf /tmp/vtep-v16/bpf \
--previous-full-agent /tmp/vtep-build/cilium-agent-v15 \
--previous-source-bpf /tmp/vtep-v15/bpf
```

Use `--previous-agent-mode compatible` for the reviewed v15 -> v16 -> v15
prototype transition on Linux 6.8. Require both exact subtests:

- `TestPrivilegedRealAgentProcess/upgrade_previous_to_current_preserves_live_connections`
- `TestPrivilegedRealAgentProcess/rollback_current_to_previous_preserves_live_connections`

Use `--previous-agent-mode missing-hashdance` on Linux 6.12 to test the known
v15 unsupported-hook refusal, preservation of the live graph and recovery with
v16. Require
`TestPrivilegedRealAgentProcess/unsupported_previous_agent_refuses_without_replacing_live_graph`.
A failure for an unrelated reason does not satisfy that test. The compatible
mode is not a promise that arbitrary Cilium versions can reuse this experiment.

Both modes must also pass the root lifecycle test, real packet/TIME-WAIT checks,
unsafe-disable refusal and coordinated drain/disable. Reports fingerprint both
agent binaries, both supplied production BPF trees and the compiler. Identical
agent binaries are refused before boot; the two production trees can legitimately
match when only the agent's Go implementation changed.

For a mixed-kernel run, kernel_matrix.py accepts per-case `previous_agent_mode`
and `required_tests` fields in addition to `name`, `kernel` and `modules`.
Supply all shared artifact arguments after `--`, plus
`--live-test-run '^TestPrivilegedRealAgentProcess$'`. All selected transitions
must produce explicit PASS evidence; skipped/missing required tests fail.
