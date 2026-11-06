<!-- This file was not reviewed by a human before submission -->

# Current design review

Use [SUPPORT.md](SUPPORT.md) for the current matrix and remaining deployment
scope. This document records the invariants that the existing implementation
must preserve. Historical speculative TIME-WAIT/cookie proposals are retained
in Git history and checkpoint reports, rather than repeated as unfinished work.

## Ownership and policy invariants

- Return authority belongs to an exact kernel socket incarnation and selected
  namespace/generation, bound to policy-approved ingress and the exact peer.
  The opaque MAC nonce, tuple, latest SYN or client prefix alone grants nothing.
- Ingress admission follows normal policy. Reply selection follows normal
  egress policy/CT, retaining Cilium's established-reply semantics.
- FIN observation, conntrack loss, inactivity and tuple reuse do not prove an
  established socket ended. Kernel socket lifetime reclaims socket-local state.
- Native origin is explicit; a known Cilium route or exact local host destination
  is required. Unknown ownership cannot fall into legacy external prefix routing.
- The underlay must constrain trusted peer origins. This is return affinity,
  with no peer-specific identity/tenant isolation or duplicate-tuple namespace.

## Completed design elements

The single socket-owned design replaces the abandoned CT-bit/tuple guard.
AF_INET6 listeners accepting IPv4 validate both mapped addresses. The controller
bounds and strictly decodes journal history, compacts exact retired ranges,
checks canonical maps/hooks and refuses ambiguous or incomplete restoration.

[TIME-WAIT](TIMEWAIT.md) transfers ownership before publication and binds the
new ACK skb to that incarnation before handing off a one-time queued proof.
[SYN cookies](SYNCOOKIES.md) bind the original policy-approved SYN and real
kernel SYN-ACK/validated ACK to the exact returned child before publishing
socket ownership. Both are agent-managed in the current source. Their limits
and last live evidence are centralized in [SUPPORT.md](SUPPORT.md).

## Review still required

1. Independently review kernel ABI/timing checks, policy ordering and metadata
   handoff, especially global skb-release instrumentation and saved-SYN memory.
2. Establish whether every hook/map is necessary; no safe removal has yet been
   proved. Any simplification needs equivalent lifetime/reuse/pressure evidence.
3. Validate normal Kubernetes identities, NetworkPolicy and actual CNI lifecycle
   together with external peers. The standalone daemon's no-policy allocator
   and separate policy fixture are insufficient for this gate.
4. Measure legitimate sustained load, exact exhaustion behavior and native
   CPU/memory/latency; emulator timing is not performance evidence.
5. Define supported target kernels and upgrade/reboot/recovery transitions,
   document disruption and agree on maintenance ownership and implementation home.

Losing all authoritative records of a peer cannot be repaired transparently;
affected connections must reconnect. A broader feature scope is a separate
proposal, not an implied consequence of completing the current lab tests.
