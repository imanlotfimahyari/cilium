# v24 trusted cookie packet-to-child handoff — 3 November 2026

Implementation checkpoint: `da987349f1`. Parent is v23 local `c98727e31d`,
published `a150e459f00eb6bd3a0294e422f212556b3ec7f7`, matching tree
`ae81c364e0dacbd4b362007a0c20fc1777a1c1b4`.

**This checkpoint proves the live packet path, not agent installation.** Test
objects explicitly define `ENABLE_VTEP_RETURN_COOKIE_AFFINITY`; the agent's
current runtime/configuration does not turn it on yet. Agent lifecycle and
schema integration are the next milestone. The existing flag remains off by
default. No new operator configuration API is introduced.

## Executed final evidence

| Isolated real-kernel test | Linux 6.8.0-31 | Linux 6.12.0-061200 |
| --- | --- | --- |
| Forced cookie VXLAN forwarding, both listener families | PASS, 11.66s | PASS, 10.58s |
| Actual ingress-policy denial precedes issuance | PASS, 5.68s | PASS, 6.05s |
| Same-cookie cross-peer collision quarantine | PASS, 10.81s | PASS, 9.77s |
| ACK-ticket pressure and ACK-with-data recovery | PASS, 10.43s | PASS, 9.49s |
| Consumed replay after reset, live duplicates still allowed | PASS, 10.21s | PASS, 10.47s |
| Eight legitimate bindings, exhaustion and real window expiry | PASS, 69.42s | PASS, 71.82s |
| Packet-association pressure | PASS, 5.39s | PASS, 6.26s |
| Another issued cookie cannot borrow an existing tuple's peer | PASS, 10.97s | PASS, 10.57s |
| Shared eleven-case ledger regression suite | PASS, 1.40s | PASS, 1.34s |
| Complete runner, including conntrack/core BPF regressions | PASS, 153.810s | PASS, 154.585s |

Both final guests pass all 30 selected root/child tests, with no failed or skipped
tests, no report errors and `VTEP_VM_EXIT=0`. The final objects/binary were frozen
in a separate build directory before execution. The two disconnected amd64
QEMU/TCG guests ran concurrently, each with two vCPUs and 1,536 MiB. Timings are
correctness-test execution durations, not native performance measurements.

Strict BPF compilation, sampled flag-off executable comparisons, unchanged
conntrack.h, Go unit/race tests, Go vet, four Python evidence/preflight tests
and `git diff --check` pass. The host race suite skips privileged cases; guest
BPF tests use static non-race binaries.

Earlier compile/verifier/fixture failures remain separate. They exposed nullable
socket-pointer reuse, an inappropriate internal-rodata replacement and a TC
helper unavailable on these kernels. The final code checks one socket pointer,
shares canonical named maps only, and binds the pod-ingress hook to the verified
namespace/veth instead of calling the unsupported TC helper. Earlier exploratory
runs were not reused as final same-object evidence.

## Implemented trust chain

1. Existing Cilium ingress policy and exact configured VXLAN peer/VNI validation
   mint the original never-reused SYN token after the final Ethernet rewrite.
2. A checked `fexit/tcp_make_synack` reads that exact original SYN and the actual
   newly constructed cookie SYN-ACK. It verifies the ticket, tuple and ISNs,
   records the original peer in the bounded ledger, and associates only that skb.
3. Pod pre-queue TC checks the exact skb association and stamps the SYN token.
   Normal host egress policy/CT then validates the live SYN ticket and issued
   cookie evidence before routing to the original peer. Atomic ticket deletion
   allows one queued SYN-ACK consumer. A retransmitted SYN gets a fresh token.
4. A cookie-shaped ACK is classified at the same final post-policy point. Its
   trusted outer peer must match the issued record. A fresh opaque ACK ticket,
   not packet-supplied identity, is carried in its Ethernet source bytes.
5. Pod ingress validates the ticket before Linux TCP. For consumed evidence it
   requires the exact existing socket and that socket's immutable owner; a
   listener, request or TIME-WAIT socket cannot authorize a replacement child.
   An issued cookie also cannot borrow a full socket owned by another peer.
6. Checked `fexit/tcp_get_cookie_sock` verifies the kernel-returned child, namespace,
   family, tuple, receive-next/send-unacknowledged values and exact ACK ticket.
   It consumes the ledger once and puts the peer proof on that exact child.
7. The passive-established callback obtains the child's actual socket cookie,
   publishes the immutable owner before app replies, then removes the temporary
   socket-local proof. Application replies use ordinary Cilium egress policy/CT
   and that socket's owner, including after CT loss.

New logical state is the ledger, ACK tickets, transient skb associations, pending
child socket storage and aggregate cookie counters. The next agent schema will
manage these five additions: an eighteen-map bundle and eight tracing links,
plus node sockops, selected-pod pre-queue, new pod-ingress and retirement hooks.
The existing skb-release hook invalidates cookie associations before address
reuse. There is no tuple-only forwarding fallback or latest-peer overwrite.

## Safety and lifetime checks

The ledger uses the v23 atomic collision/consumption/GC rules. Timing is based on
actual kernel jiffies and a sixty-thousand-tick epoch. The loader requires the
exact reviewed builds `6.8.0-31-generic` or `6.12.0-061200-generic`, checked ABIs
and enum values, and exactly `CONFIG_HZ=1000` from the running kernel configuration.
It does not use Cilium's estimated HZ probe for this authorization boundary.
Missing, ambiguous, oversized or unreviewed timing refuses loading.

The real-expiry test fills the eight-entry test ledger using eight actual kernel
cookie handshakes. The ninth is rejected. It runs real GC through the actual
acceptance window without editing clocks/timestamps or deleting those records;
no still-valid tombstone disappears and all eight socket owners keep transferring
data. Once the kernel window ends, GC frees capacity and a new peer-B handshake
succeeds while the original owners remain intact.

ACK/packet-map pressure uses explicitly invalid synthetic occupancy. Real ACK GC
permits a delayed ACK with application data to bind the right child before that
payload is delivered. Fake skb-address occupancy is removed only by the fixture;
actual skb lifetime cleanup is performed by the kernel release hook. The raw
MSS-distinct-cookie test suppresses automatic resets from its socketless test
clients on one dedicated port; that fixture program is never agent-installed.

## Reproduce

Build with run_spike.py and static Go binaries. Supply the usual trusted kernel,
modules, QEMU, BusyBox and bpftest arguments, plus:

```sh
--live-tests /opt/vtep-build/livetest \
--cookie-runtime-object /opt/vtep-build/cookie_runtime.o \
--cookie-core-object /opt/vtep-build/socket_cookie_core.o \
--cookie-peer-object /opt/vtep-build/cookie_peer_ledger.o \
--live-test-run '^TestPrivileged(Cookie.*|SYNcookiePeerLedger)$' \
--cpus 2 --memory 1536M --timeout 600
```

Use the running kernel's trusted configuration beside vmlinuz, or pass it with
`--kernel-config`. Require every root/child listed in cookie_forwarding_test.go
and all eleven ledger children using repeated `--require-test`. Missing or
skipped required cases must fail the report. The final test's actual selector,
artifact arguments and individual reports are retained outside source control.

## Limits and next milestone

- The current agent still does not install this cookie path. Integrate all new
  maps, eight tracing hooks and the pod-ingress hook, strict v3 restoration,
  readiness, retirement, drain/disable and older-binary refusal next. Upgrading
  live v2 state will require draining/disabling with the older binary first.
- Proven forwarding scope is direct IPv4/TCP through configured external VXLAN
  peers, on veth/TCX, for AF_INET and IPv4-mapped AF_INET6 listeners. Forced-cookie
  native/ordinary-cluster traffic remains unsupported. Services/NAT, proxies,
  encryption, Geneve, IPv6 forwarding, netkit, TFO and fragments remain excluded.
- This does not provide tenant isolation or simultaneous identical TCP tuples
  per peer; peer-specific policy identities remain unresolved. The extra tuple
  guard protects the demonstrated cookie handoff, not arbitrary established data.
- Lost/unavailable proof or child-storage allocation failure cannot grant an
  owner. Forwarding fails closed; this is not a promise that Linux cannot create
  an unowned child under every allocation/state-loss race. Complete authority
  loss still requires reconnect, not reconstruction from tuples.
- Retained tombstones reduce admission availability under sustained SYN pressure.
  Native overhead, memory, sustained legitimate churn, actual Kubernetes/CNI with
  normal identities/NetworkPolicy, broader kernels and rollout remain unvalidated.

## Evidence fingerprints

Only hashes are committed. Raw logs, binaries and trusted-kernel packages stay
outside the source tree.

- `v24-packet-final/linux68.log` — `d7f635cab96ce2d663c5ea6c3034213c79f0bbc8398dad74096d397f47e4fdd3`
- `v24-packet-final/linux68.json` — `ef98348a80cc9460e213cc95d4b09cab00f11a67a22a99d471070da10a95289c`
- `v24-packet-final/linux612.log` — `279db1030e3701fab873aec0a0702496e3f03140ef9278f1cd779d6bf71c71c4`
- `v24-packet-final/linux612.json` — `8f993806e2bb62a3283ec9fedd13944d4344f364723e6e9499fcc0ba37ec70db`
- `v24-packet-final/matrix.json` — `9071f7747813f6a001a3d523f8452e2dae2ac7ace838156e76f1fff8602bfc1c`
- `build-v24-final/livetest` — `c02f11d0a276c294269a7fd381dddc5f494fc718f302e5f20f272aa36248c300`
- `build-v24-final/cookie_runtime.o` — `4f6149d52a2a9a7e625816c54b1a42aa9a6ec145793d062a5f75b26a6f2955b4`
- `build-v24-final/socket_cookie_core.o` — `69f81bc13ea6d987cca5e1b127207c565fb51bda458208367b0aa91f2352b17b`
- `build-v24-final/cookie_peer_ledger.o` — `3fd5d9af9819394f1ab3311268451be28718f4773cdd84b26038f09e4c3877cd`
