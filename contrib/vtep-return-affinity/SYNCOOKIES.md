# SYN-cookie child handoff: isolated capability checkpoint

## What v18 establishes

Linux 6.8 and 6.12 can attach socket-local evidence to a successfully created
cookie child before `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`. The isolated probe
uses one temporary `fexit/tcp_get_cookie_sock` hook and a temporary sockops
program. It does not select peers, permit packets, change routing, modify the
production map schema or add a managed agent hook. The production experiment
continues to reject SYN-cookie handshakes.

The loader checks the exact four-argument kernel BTF prototype and `sock *`
return type before reading context slot four. The fexit probe filters the
selected namespace inode, checks the child's namespace, tuple and SYN-RECV
state, and compares the ACK's sequence numbers to the new TCP child's initial
receive-next and send-unacknowledged values. It creates evidence on that exact
socket with BPF socket storage. The passive-established callback then requires
that marker, agrees on namespace/tuple/family, and records the kernel socket
cookie. Userspace reads the marker through the accepted socket FD and verifies
its cookie with `SO_COOKIE`.

The probe never dereferences `request_sock` after return: the kernel may already
have released it. CO-RE locates the selected fields. TCP-specific fields beyond
the verifier's `sock` return type are read through checked kernel probe reads.
No kernel object address is retained as a map key or value.

## Executed checks

Both AF_INET listeners and AF_INET6 listeners accepting IPv4 pass all five cases
on each kernel:

| Case | Required evidence |
| --- | --- |
| Normal handshake, cookies disabled | Passive callback occurs without cookie-child evidence |
| Forced kernel SYN cookies | `SyncookiesRecv` increases; marker creation precedes callback; FD cookie, namespace, tuple and family match; application data works |
| Invalid raw ACK | Kernel `SyncookiesFailed` increases; no child evidence is created; the existing socket marker and application transfer survive |
| Another namespace with the identical tuple | Its forced-cookie handshake works without acquiring or modifying selected-namespace evidence |
| Exact tuple reuse after client reset | New cookie and independent evidence; old server FD retains its original marker; replacement transfers data |

The same VM runs also retain the existing forced-cookie fail-closed tests for
both listener families, through the synthetic handoff and actual Cilium
policy/CT fixtures. Required subtests must explicitly PASS; no tests were skipped.
See [v18 validation](VALIDATION-v18.md) for source and artifact fingerprints.

These are direct-veth capability tests with trusted, isolated kernel hooks.
They do not demonstrate VXLAN peer binding, tenant isolation, cookie forwarding,
admission-pressure behavior or production kernel support.

## Next implementation gate

A successful cookie ACK proves the kernel accepted a TCP handshake; it does
not identify the original outer VXLAN peer. Before enabling cookie forwarding:

1. Bind the original policy-approved SYN ticket to the kernel-generated
   SYN-ACK sequence evidence, namespace and generation. Require exact trusted
   peer agreement on the incoming cookie ACK, with ordinary policy ordering.
2. Make cross-peer collisions and retransmissions explicit. Never overwrite an
   ambiguous proof with the latest SYN or infer ownership from a tuple/prefix.
   Retention and any quarantine must cover the kernel's cookie acceptance
   window; arbitrary short expiry must not permit an older ACK to acquire a
   replacement peer.
3. Bound every admission/proof structure without evicting surviving authority.
   Define exhaustion, invalidation, duplicate use and late-callback behavior.
   Cookies avoid keeping kernel request state; this feature would add state
   back and must quantify its SYN-flood availability and memory cost.
4. Publish the verified peer on the exact validated child before application
   replies. Exercise cross-peer replay/collision, ACK-with-data, retransmission,
   expiry and pressure. Then integrate managed installation, compatibility,
   restart and drain/disable with the agent.

The temporary probe hook is not automatically an acceptable production hook.
Its compatibility and maintenance cost need review alongside the existing six
TIME-WAIT hooks. No new production configuration API is introduced here.

## Reviewed kernel sources

- https://github.com/torvalds/linux/blob/v6.8/net/ipv4/syncookies.c
- https://github.com/torvalds/linux/blob/v6.12/net/ipv4/syncookies.c
- https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp_ipv4.c
- https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp_input.c
- https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp_minisocks.c

The cookie checker calls `tcp_get_cookie_sock` after cookie validation. The
IPv4 receive path subsequently invokes `tcp_child_process`, which advances the
child through the passive-established callback. The live tests validate this
ordering on the supplied 6.8 and 6.12 builds rather than extrapolating it to
other kernels.
