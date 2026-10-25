# Design review and remaining implementation gates

This is experimental source, not an upstream-approved feature. No public PR,
maintainer message, acceptance or maintenance commitment is implied.

## Changes in this pass

1. Remove the abandoned CT-bit/tuple-guard design and its controller, map,
   native adapters and old packet tests. `bpf/lib/conntrack.h` is restored
   byte-for-byte to the baseline. Keep one socket-owned implementation.
2. Compact physically drained retired memberships into exact cookie ranges.
   Never use a high-water mark that would reject unrelated namespaces in gaps.
   Bound registrations plus ranges to 8,192 for new admissions; pressure never
   deletes ownership history. Version 1 journals migrate to version 2. A binary
   that only understands version 1 fails closed on version 2, even after
   drain/disable. v10 provides a bounded offline compatibility export; an
   actual older-binary rollout still needs validation (see DOWNGRADE.md).
3. Enable saving a SYN on AF_INET6 listeners, then validate both IPv4-mapped
   child addresses against the kernel's IPv4 fields before assigning ownership.
   No IPv6 packet forwarding or address-based ownership fallback is introduced.
4. Distinguish external WORLD/VNI-2 peers from ordinary Cilium VXLAN traffic.
   Native cluster admission requires agreement between source IP-cache entry,
   source identity, tunnel identity and exact node tunnel address. The explicit
   external-peer list still takes precedence and requires WORLD/VNI 2.
5. Preserve ordinary local-stack delivery for socket-owned native TCP whose exact
   destination is a host address in Cilium's endpoint map. Do not allow arbitrary
   TCP destinations to fall through to an ownership-unaware host prefix route.
6. Add a disposable-cluster harness for actual CNI, ordinary identities,
   NetworkPolicy, persistent connections across agent pod replacement, workload
   replacement and node drain. Its local result is BLOCKED, not PASS.

## TIME-WAIT: why a tuple cache is insufficient

The shared TIME-WAIT runtime implements both requirements below: exact
full-socket to TIME-WAIT transfer/destruction cleanup, and binding a newly
constructed ACK before qdisc buffering. A queued ACK keeps its original peer
across actual TIME-WAIT destruction and exact tuple reuse through another peer.
v14 consumes proofs after ordinary Cilium policy/CT and manages the complete
map/hook lifecycle in the agent. The synthetic fixtures remain independent
regressions; Kubernetes validation is deferred.
See [TIMEWAIT.md](TIMEWAIT.md) for evidence and the six-hook maintenance cost.

The v9 default-path regression still enters kernel TIME-WAIT and replays a
checksummed client FIN to demonstrate fail-closed behavior without the extension.
The separate v12 fixture implements successful forwarding under its lab contract.

Linux 6.8 `inet_twsk_alloc()` copies the original socket cookie to the TIME-WAIT
object. However, `tcp_v4_send_ack()` emits the reply using a per-CPU control
socket, not the TIME-WAIT object. Thus retaining a cookie-to-owner map alone
would not identify the output packet's original connection.

A candidate extension must establish both:

- An authoritative handoff of the full socket owner to the exact TIME-WAIT
  incarnation while the original owner is still available.
- A packet-specific handoff from that verified TIME-WAIT incarnation to the
  emitted ACK, surviving queues and tuple reuse, followed by the existing
  policy/CT and generation checks.

A pod-side kernel socket lookup with cookie verification is worth evaluating;
it needs compatible BPF access to the TIME-WAIT cookie and careful namespace
handling. No timeout, FIN observation, tuple-only lookup, guessed peer or new
SYN may retarget a surviving connection. Cleanup must have reliable incarnation
absence evidence, with bounded memory and explicit handling of lookup failure.
Any additional kernel/CO-RE hooks require architecture and support-matrix review.

Sources used for this reasoning:
- https://github.com/torvalds/linux/blob/v6.8/net/ipv4/inet_timewait_sock.c
- https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp_ipv4.c

## SYN cookies: retaining the admission is only half the problem

The forced-cookie regression checks the kernel's `SyncookiesSent` counter,
observes ownership enforcement rejecting the SYN-ACK, and verifies an already
established connection remains usable. This is an availability limitation under
backlog pressure, not completed SYN-cookie support.

Linux exposes the just-received SYN through `TCP_BPF_SYN_MAC` while generating
its SYN-ACK, including in cookie mode. The later accepted socket does not have
that saved SYN. A safe extension must connect the kernel-validated cookie ACK
and accepted socket to the original policy-approved peer and namespace
incarnation. A tuple or latest-SYN record alone cannot do that safely.

A design based on kernel-generated SYN-ACK sequence evidence and initial child
sequence state needs collision, retransmission, ACK-with-data, expiry and
cross-peer adversarial tests. It would also retain bounded state while the
kernel uses cookies to avoid retaining requests. The resulting SYN-flood
capacity and admission behavior must be measured and documented.

Source:
- https://github.com/torvalds/linux/blob/v6.8/net/core/filter.c
- `bpf/include/linux/bpf.h`, documentation for `TCP_BPF_SYN_MAC`

## Required next gates

| Gate | Exit evidence |
| --- | --- |
| Kubernetes native path | Execute `k8s/validate.py` on an actual patched disposable cluster; preserve the report and verify cleanup |
| Kubernetes external path | Add real external VXLAN peers to that cluster and repeat policy/lifecycle checks with overlapping external client prefixes |
| TIME-WAIT | Agent lifecycle and policy/CT consumption implemented; v15 adds actual policy/CT, invalid-proof and duplicate regressions; broader buffering/kernel coverage and overhead review remain |
| SYN cookies | Kernel-validated child binding, forced/overflow-cookie tests and measured admission-pressure behavior |
| Operations | Reboot, partial pins/journal loss, rolling upgrade and older-binary downgrade tests |
| Maintainability | Maintainer review of hooks/handoff, agreement on scope and shared long-term ownership |

The current prototype is return affinity for distinguishable TCP connections.
It does not provide network tenancy, separate policy identities per external
peer, or support for two simultaneous identical TCP tuples in the same network
namespace. Losing every authoritative owner still requires reconnecting.

## v10 recovery checkpoint

An offline converter now preserves exact retired-cookie history while publishing
v1-format tombstones for the v8 feature-aware prototype. It requires disabled,
uninitialized, same-boot state and no pins; it refuses active leases, unknown
fields and expansions above 8,192 cookies. It checks only by default and writes
atomically with `--apply`. This does not establish arbitrary older-Cilium or
Kubernetes downgrade support. Startup also reads journal contents under the
lease, eliminating the pre-lease snapshot race. No packet-path code changed.
