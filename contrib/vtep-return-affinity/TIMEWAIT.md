<!-- This file was not reviewed by a human before submission -->

# Agent-managed TIME-WAIT return affinity

TIME-WAIT pure IPv4 ACK forwarding, policy/CT consumption, complete map/hook
restoration, proof collection and drain/disable are implemented. Use
[SUPPORT.md](SUPPORT.md) for the current kernel, buffering, capacity and evidence
matrix. The old schema-2/six-hook and one-kernel descriptions were historical;
the current shared bundle also includes the external-cookie runtime.

## Ownership and packet handoff

`bpf/lib/vtep_return_timewait_owner.h` implements two CO-RE hooks:

1. `inet_twsk_hashdance` (6.8) or reviewed `inet_twsk_hashdance_schedule`
   (6.12), selected after BTF ABI checks: before publication, transfer the full socket's immutable
   owner to the exact kernel TIME-WAIT cookie. Check cookies, IPv4 endpoints,
   ports, origin and namespace generation. The non-evicting map is keyed by the
   globally unique socket cookie, never a tuple.
2. `inet_twsk_free`: at actual final-reference destruction, remove only that
   cookie's matching record. Application FD closure, FIN observation, inactivity
   and tuple reuse are not cleanup evidence.

`bpf/lib/vtep_return_timewait_producer.h` adds the packet-specific handoff:

3. Entry/exit of `tcp_v4_send_ack` identify the original TIME-WAIT object and the
   kernel's ACK sequence values. A per-CPU scope is valid only for a single
   non-nested emission. The validated Linux 6.8 TIME-WAIT call path has bottom
   halves disabled. Nested emission invalidates the scope and outstanding
   packet association instead of borrowing another invocation's owner.
4. Exit of `__ip_make_skb` identifies the newly constructed packet itself.
   Retain its exact live skb address as a temporary, privileged-only identity
   key. This is construction evidence, not a lookup of a buffered packet's
   tuple. `skb_release_head_state` invalidates the association before freeing
   head state; ACK exit removes any remaining association. Unexpected identity
   collisions invalidate the association rather than adopting an existing one.
5. Selected pod TC egress verifies that exact packet, namespace/generation and
   pure ACK headers, then issues a one-time proof containing the original owner
   and expected headers. A never-reused namespace nonce in the internal Ethernet
   source MAC carries the proof through qdisc buffering and orphaning. No IP,
   TCP address, sequence or checksum is rewritten.
6. The actual endpoint reply path consumes the one-time proof after normal
   Cilium egress policy/CT. It verifies namespace/generation, exact headers,
   expiry and origin, atomically deletes the proof, restores the source MAC and
   uses the original external peer or ordinary native routing. Invalid claims
   drop; they cannot borrow the current tuple's owner. Synthetic fixtures still
   exercise the same producer with their independent test route.

The construction point matters: the initial `ip_local_out` probe did not observe
this kernel's control-reply path. A generic output hook could also encounter an
older reinjected skb. The constructor return binds the newly created object.

## Evidence and failure boundary

Recorded fixtures cover both listener families and original external peers plus
native routing: retransmitted-FIN ACKs, a queued ACK across TIME-WAIT destruction
and exact tuple reuse, missing authority, proof expiry, actual policy/CT denial,
malformed/expired/wrong-generation claims and duplicate proof consumption.
The v29 current-agent fixture covers preservation and collection across actual
agent restart on both reviewed kernels. Kubernetes remains a separate gate.

CT_REPLY retains normal Cilium established-reply semantics. The egress-denial
fixture removes CT after queueing so an actual DROP_POLICY_DENY verifies the
new-policy case; it does not redefine ordinary reply allowance.

A packet held before the pod hook, for example by unresolved neighbor discovery,
can outlive its construction scope and drop. Known-neighbor/qdisc tests do not
prove arbitrary neighbor buffering, clones or all offload combinations.
Temporary live skb identity stays in privileged kernel maps/scopes and is not
durable ownership or client-visible data. Its verifier/ABI dependency and
common-path cost still require independent review and native measurement.

See [OPERATIONS.md](OPERATIONS.md) for the shared hook graph and diagnostics,
[SUPPORT.md](SUPPORT.md) for remaining limits, and checkpoint reproduction
reports for exact object/VM arguments. Synthetic and actual-endpoint fixtures
have different routes; results must retain that distinction.
