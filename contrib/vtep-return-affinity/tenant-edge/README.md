<!-- This file was not reviewed by a human before submission -->

# Isolate overlapping tenants at the TCP ingress edge

The same IPv4/TCP tuple can be accepted concurrently if the two listeners are
in different Linux network namespaces. Each tenant frontend accepts its own
TCP connection, then opens a new connection from a unique address to that
tenant's distinct backend. A shared application installation can serve both
through separate, tenant-authorized endpoints. This does not demultiplex
duplicate tuples inside a single Cilium pod namespace.

| Where | Tenant A | Tenant B |
| --- | --- | --- |
| Ingress | Tenant A's private network | Tenant B's private network |
| Client → listener | `198.18.0.2:49000 → 198.18.0.1:8080` | Same tuple |
| TCP frontend | HAProxy in tenant A's network namespace | HAProxy in tenant B's network namespace |
| New backend connection | `192.0.2.5 → 192.0.2.6:18080` | `192.0.2.9 → 192.0.2.10:18080` |

Place the frontends at the VTEP/gateway edge, **before** separate tenant
networks enter a shared Cilium datapath. If traffic arrives encapsulated, each
tenant tunnel must terminate on its own trusted ingress interface in the
corresponding namespace. Do not bridge the tenant ingress networks, infer a
tenant from a client address or payload, or use Cilium's shared VTEP world
identity as a tenant identity. Configure routing so the shared backend network
does not have access to the overlapping frontend addresses. No transparent
source spoofing or cross-tenant fallback is needed.

The generator validates addresses and renders one ordinary HAProxy TCP config
per tenant. It deliberately permits duplicate listener tuples; it rejects
shared egress/backend addresses or uplink addresses inside any ingress range.
It **does not** provision namespaces, VTEPs, routes or access controls. Deploy
exactly one frontend per tenant namespace (or on distinct gateways), give it
only its own ingress attachment and a restricted egress path to its backend.
Backends must enforce tenant authorization and deny other gateways and direct
client access. Use an authenticated connection where the network is not itself
trusted. Generated config alone does not enforce those boundaries.

```sh
cd contrib/vtep-return-affinity/tenant-edge
python3 render.py tenants.example.json ./rendered
haproxy -c -f ./rendered/tenant-a.cfg
haproxy -c -f ./rendered/tenant-b.cfg

# Only after provisioning the dedicated interfaces, addresses and routes:
sudo ip netns exec tenant-a haproxy -db -f "$PWD/rendered/tenant-a.cfg"
# Run the second frontend independently, in tenant-b.
```

The backend sees the gateway source, not the original client address. TCP is
split into two independent connections; TLS bytes can pass through unchanged.
A frontend restart takes down its connections unless the proxy rollout drains
them. Configure proxy timeouts/limits and backend authorization for the workload.
The existing Cilium affinity feature and its kernel requirements are unchanged.
The proxy boundary can be exercised with affinity switched off.

To test a disposable Linux host, with Python 3, HAProxy, iproute2 and veth support:

```sh
python3 -m unittest discover -s . -p 'test_*.py' -v
sudo unshare --mount --net --propagation private -- \
  python3 "$PWD/lab.py" --isolated-lab
```

The lab uses private veth pairs to represent traffic **after** tenant ingress
separation. It holds two identical TCP tuples concurrently, checks the two
different backend responses, then stops one backend and verifies the other
tenant retains its original TCP connection. It is not a VXLAN demultiplexing,
Cilium, Kubernetes or AL2023 deployment test.

For a smaller check, Linux with unprivileged network/user namespaces can run
`python3 loopback_lab.py` as a regular user. It starts real HAProxy processes
and overlapping TCP sockets in two private loopback namespaces. This test,
validation of both generated configs with HAProxy 3.0.11, and the four
renderer tests passed. The veth test was blocked by unavailable netlink access;
it and deployment over separate VXLAN ingress links still need a lab host.
