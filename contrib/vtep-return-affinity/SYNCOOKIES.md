<!-- This file was not reviewed by a human before submission -->

# Agent-managed external VXLAN SYN-cookie ownership

External-cookie forwarding and its lifecycle are implemented. Use
[SUPPORT.md](SUPPORT.md) for exact kernel requirements, scope and evidence.
The early v18 capability probe and v23 synthetic ledger are historical steps,
not the current forwarding/agent status.

## Trusted handoff

1. Record the exact policy-approved external SYN origin and namespace generation.
2. The checked kernel SYN-ACK producer records both initial sequence numbers and
   exact constructed skb. A bounded first-peer ledger retains authority and
   consumed/quarantined entries for the full reviewed kernel acceptance window.
3. Verify the incoming ACK's exact peer and handshake evidence after normal
   ingress policy. A pre-stack guard rejects stale consumption and cross-peer
   borrowing before the kernel TCP path can reuse it.
4. The checked `tcp_get_cookie_sock` return binds evidence to the exact live
   kernel-created child, validating family/namespace/tuple/state/sequences.
   No released request object is dereferenced after return.
5. The passive-established callback publishes the actual child's socket cookie
   and immutable ownership. Application data uses this socket owner; handshake
   evidence is not an alternative application-data authorization path.

The nonce/tuple alone grants no authority. Conflicting peer evidence cannot
replace an occupied owner. Expiry collection removes pending records only after
its acceptance window; established ownership is independent of ledger expiry.
Runtime installation, pin reuse, collection, readiness and drain/disable are
managed by the agent's canonical bundle.

## Evidence and remaining boundary

The v24 packet fixtures exercise real forced-cookie VXLAN handshakes through
normal Cilium policy/CT, both listener families, exact child publication,
replay/collision, expiry and pressure. v25-v29 add managed runtime lifecycle and
real agent periodic collection on the reviewed kernels. These reports do not
establish AL2023 support, ordinary native SYN-cookie forwarding or EKS execution.
The authoritative distinction is in [SUPPORT.md](SUPPORT.md).

The kernel uses cookies to avoid retaining request state while this feature
retains bounded peer evidence. SYN-flood availability, memory and native
handshake throughput therefore require measurement. The common skb-release hook
must invalidate temporary associations before address reuse, including drops.

## Implementation references

- `bpf/lib/vtep_return_cookie*.h`
- `pkg/datapath/vtep/returnaffinity/cookie_targets.go`
- `contrib/vtep-return-affinity/live/testdata/socket_cookie_core.c`
- `contrib/vtep-return-affinity/live/testdata/cookie_runtime.c`
- Recorded `VALIDATION-v24.md` through `VALIDATION-v29.md`
