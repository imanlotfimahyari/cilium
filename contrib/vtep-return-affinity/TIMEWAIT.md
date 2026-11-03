# Agent-managed TIME-WAIT return affinity (v16)

The existing default-off experimental agent flag now manages this extension.
The source includes proof consumption after ordinary Cilium policy/CT, complete
map/hook restoration, periodic proof collection and drain-before-disable.
Kubernetes remains deferred. The v16 controller/packet matrix passes on Linux
6.8 and 6.12; full-daemon lifecycle evidence remains the historical Linux 6.8
v15 result. See [v16 validation](VALIDATION-v16.md) for exact scope and gaps.

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

## Validated evidence

The disconnected Linux 6.8.0-31 guest tests actual kernel TCP with two external
VXLAN peers sharing an inner client address, plus a native client:

- IPv4 and IPv4-mapped AF_INET6 listeners: actual retransmitted-FIN ACKs arrive
  on each original external peer and on the native client.
- An ACK is demonstrably held in netem before host forwarding. The original
  TIME-WAIT object is then destroyed by an in-window RST, and the exact TCP tuple
  is reused through the other peer. The replacement handshake overtakes the old
  ACK. On release, that ACK still goes to its original peer, and the replacement
  retains its own immutable owner and passes application data.
- Synthetic egress denial consumes and rejects a valid proof. Removing the
  authoritative TIME-WAIT owner rejects later ACKs without guessing a peer.
- A packet lost by netem leaves an outstanding proof. After its ten-second
  expiry, the explicit collector reclaims it while preserving the surviving
  kernel TIME-WAIT owner.
- v11's real-destruction cleanup, non-evicting owner-map exhaustion, exact tuple
  reuse and pinned descriptor-reopen tests still pass for both listener families.
- Existing mapped-listener data tests and default fail-closed TIME-WAIT and
  SYN-cookie tests still pass. The flag-off agent path remains unchanged.

Peer-side packet taps observe ACK delivery before a test receiver sink prevents
an already-closed old client from generating an unrelated RST against the
replacement's shared TCP tuple. This verifies return routing, not tenant
isolation. Identical tuples still share one kernel TCP namespace.

## Actual endpoint proof validation (v15)

The additional `socket_timewait_core.c` fixture enables the production proof
consumer in the real `bpf_lxc.c` entrypoints. It attaches the shared producers,
never the synthetic `tw_route` hook. Tests cover both listener families and
both original VXLAN peers plus native routing; policy denial after queued-packet
CT loss; malformed, expired and wrong-generation claims; missing socket cookies,
unknown peers, and actual netem duplicates consuming a proof only once.

CT_REPLY remains subject to Cilium's normal established-reply semantics. To test
new egress denial rather than that legitimate reply allowance, the test queues
the stamped ACK and removes CT after the incoming FIN has recreated it. It
requires the actual `DROP_POLICY_DENY` metric and an unconsumed proof, then
checks expiry collection without deleting the TIME-WAIT owner.

The close/replay harness waits for the original client's kernel TCP_CLOSE and
drains its initial capture before injecting a new packet. This prevents an old
close ACK from satisfying a later assertion and avoids spurious retransmissions.
This is test synchronization, not production ownership/cleanup evidence.

## Bounds, failures and remaining limits

The agent uses 4,096-entry non-evicting owner, packet-identity and proof
hashes. Standalone fixtures use eight entries to exercise exhaustion. Pressure refuses new work; it does not evict another connection's
owner or retarget a delayed packet. Queued proofs expire after ten seconds.
The agent's existing five-second collector reclaims expired proofs without
removing a surviving kernel TIME-WAIT owner.

Live skb addresses are used only in transient kernel maps and per-CPU scope,
not as durable connection ownership or values exposed to clients. The tested
privileged verifier permits the TC context identity key. This adds a privilege
and compatibility dependency that needs review before integration. No kernel
object addresses are logged or copied into durable state.

A packet deferred before pod TC, for example by unresolved neighbor discovery,
can outlive the ACK scope and lose its association. It then drops. This does not
implement arbitrary neighbor buffering, packet cloning, offload combinations,
SYN cookies, socketless data/resets, services/NAT or IPv6 forwarding. Tests use
known neighbors and the existing direct-veth VXLAN contract. Complete loss of
all authoritative peer records still requires reconnecting.

## Integration and maintenance costs

There are now **six internal-function tracing attachments**, plus the pod/host
TC proof path. Kernel BTF, fentry/fexit support, the TC identity-key verifier
behavior and these function signatures are dependencies. Only Linux 6.8.0-31 is
validated. The packet-release hook runs on a common kernel path; its cost and
that of the other hooks are unmeasured. This approach needs architectural review
and performance evidence before it is a reasonable core proposal.

The tracing link API cannot update these programs in place. The controller
reuses compatible pinned links, comparing exact kernel BTF function/attachment,
program tag and map bindings. Schema 2 contains thirteen canonical maps and six
tracing links. Missing or changed state refuses restoration; no link/map is
silently recreated. Fresh installation attaches cleanup before producers. Drain
and disable removes producers first, then cleanup, then the whole graph.

Upgrading the previous live prototype requires drain and disable with its old
binary before schema 2 installation. The journal remains version 2. Older-binary
rollout, broader kernels, CPU/memory benchmarks, unresolved-neighbor buffering,
SYN cookies and Kubernetes remain open validation or implementation gates.

The full-agent test loads only a peer receiver sink outside the daemon. Its
ownership, tracing, stamping, GC and forwarding programs are agent-managed.
The standalone daemon uses the no-policy identity allocator; it cannot establish
normal Kubernetes identities or full-cluster NetworkPolicy conformance.

## Reproduce

Compile `timewait_owner.o` and `timewait_packet.o` using `run_spike.py`, and build
its static live-test binary as described in README.md. Add to the isolated VM
runner, together with its trusted kernel, BusyBox, QEMU and module arguments:

```sh
--live-tests /tmp/vtep-build/livetest \
--handoff-object /tmp/vtep-build/socket_handoff.o \
--core-object /tmp/vtep-build/socket_core.o \
--timewait-object /tmp/vtep-build/timewait_owner.o \
--timewait-packet-object /tmp/vtep-build/timewait_packet.o \
--live-test-run '^TestPrivileged(TIMEWAIT.*|MappedIPv4Handoff|SYNcookiesFailClosed)$'
```

Require `VTEP_VM_EXIT=0` and all supplied tests to pass. These root-cgroup and
tracing tests are only for the explicitly marked isolated guest; no external
network or host filesystem is exposed.

Kernel implementation references:

- https://github.com/torvalds/linux/blob/v6.8/net/ipv4/inet_timewait_sock.c
- https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp_ipv4.c
- https://github.com/torvalds/linux/blob/v6.8/net/ipv4/ip_output.c
- https://github.com/torvalds/linux/blob/v6.8/net/core/skbuff.c
