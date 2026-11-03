<!-- This file was not reviewed by a human before submission -->

# Disposable Kubernetes validation

This harness is implemented but has **not been executed against Kubernetes** in
this workspace. The local preflight reports `blocked`: kubectl and a container /
Kubernetes runtime are unavailable, and the host has no network/BPF capabilities.
The disconnected QEMU guest can validate Linux packet paths, not substitute for
an actual Kubernetes control plane, kubelet, runtime and CNI execution.

## What it tests

On a preconfigured disposable cluster running this patched agent:

- Real pod scheduling and CNI ADD, ordinary allocated identities (not the
  standalone no-policy allocator), and the selected endpoint compile define.
- Native cross-node IPv4 TCP with an allow/deny Kubernetes NetworkPolicy.
- Optional replacement of the actual Cilium agent pod, while a persistent TCP
  session continues with the same server-side connection ID and no reconnect.
- Workload replacement, fresh endpoint creation and retained policy enforcement.
- Optional node drain, workload rescheduling and policy enforcement afterwards.

The server has a TCP readiness probe, so local-node-to-pod TCP is exercised too.
The default run tests the native CNI/identity/policy checkpoint only. Optional
external peer containers add real VNI-2 VXLAN traffic, shared client addresses,
allow/deny policy and persistent TCP across agent replacement. This extension
has offline tests but has **not run against a cluster**. Neither mode measures
native performance or provides tenant isolation for identical TCP tuples.

## Required lab

Use Linux with cgroup v2, TCX and the required BPF features; Linux 6.8 is the
currently tested kernel. Use at least two schedulable untainted nodes and an
explicit context named `kind-vtep-affinity-lab` (or a suffix of that name).
Every node, including control-plane nodes, must carry the label
`vtep-return-affinity.cilium.io/lab=true`. The harness never reads a default
context and never patches Cilium configuration or installs Cilium itself.

Create/install the cluster through Cilium's existing development workflow
(`Makefile.kind` / `contrib/scripts/kind.sh`) or your equivalent disposable setup.
Build and install the **patched** agent. Use IPv4-only, VXLAN/IPv4 underlay,
veth, TCX, BPF host routing and kube-proxy replacement. Disable L7 proxies,
endpoint routes, IPsec/WireGuard and unsupported translations for this test.
Supply reachable Kubernetes API host/port when using kube-proxy replacement.
Keep normal identity allocation and Kubernetes NetworkPolicy enabled.

Enable the feature through the existing `extraConfig` Helm map:

```yaml
extraConfig:
  enable-experimental-vtep-return-affinity: "true"
```

Also enable/configure the existing `vtep` values with exact peer addresses, MACs,
CIDRs and mask appropriate to the isolated lab. They must not overlap Kubernetes
node/pod/service ranges for this native-path checkpoint. The feature rejects an
empty peer set even though this harness does not send external-peer traffic.
Do not reuse production peer definitions or cluster credentials in this lab.

After selecting that explicit lab context, label its nodes:

```sh
kubectl --context kind-vtep-affinity-lab label nodes --all \
  vtep-return-affinity.cilium.io/lab=true
```

## Build and run

From the repository root, with the Go version required by `go.mod`:

```sh
mkdir -p /tmp/vtep-affinity-probe
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
  -o /tmp/vtep-affinity-probe/affinity-probe \
  ./contrib/vtep-return-affinity/k8s/probe

docker build -f contrib/vtep-return-affinity/k8s/Dockerfile \
  -t vtep-affinity-probe:local /tmp/vtep-affinity-probe
kind load docker-image --name vtep-affinity-lab vtep-affinity-probe:local

python3 contrib/vtep-return-affinity/k8s/validate.py \
  --context kind-vtep-affinity-lab --image vtep-affinity-probe:local \
  --restart-agent --drain-node --report /tmp/vtep-kubernetes-report.json
```

The two explicit lifecycle switches replace the server node's agent pod and
cordon/drain a lab node. Without them, those checks are not run. The report lists
only checks actually completed; it contains no kubeconfig, raw API errors,
addresses or secrets. Missing tools generate a `blocked` report and perform no
cluster operations. An exec/API failure is never counted as a policy denial.

Each run creates a unique namespace. Cleanup requests its deletion and restores
any node cordoned by the harness, including on failure. Cleanup failure makes
the report fail. Inspect any remaining namespace or cordoned node before reuse.
The harness does not delete the cluster. Normal production rollback limitations
still apply to the patched agent itself; see the parent README.

## Optional external peers for kind

Prepare two dedicated containers **before installing/enabling the patched
agent**, so both exact peer IP/MAC pairs can be frozen in its VTEP configuration.
They must share the nodes' local Docker bridge, have separate network namespaces,
and contain `ip`, `rm` and `/affinity-probe`. The runner refuses remote Docker,
unlabelled containers, shared/host networking and existing `akvtep` links. It
changes only its newly created links/routes/neighbours inside these containers.
No host/node routes or Cilium configuration are patched.

After building the static probe above:

```sh
docker build -f contrib/vtep-return-affinity/k8s/Dockerfile.peer \
  -t vtep-affinity-peer:local /tmp/vtep-affinity-probe
for peer in affinity-peer-a affinity-peer-b; do
  docker run -d --name "$peer" --network kind --cap-add NET_ADMIN \
    --label vtep-return-affinity.cilium.io/peer=true vtep-affinity-peer:local
done
docker inspect affinity-peer-a affinity-peer-b
```

Use the bridge endpoint IP/MAC pairs from that **local** inspection in the
existing `vtep` configuration. Both peers send from `198.18.0.9/32` with different
TCP ports; the client range must be separate from node/pod/service ranges.
The legacy prefix map can represent only one peer for an overlapping prefix;
the experiment must nevertheless have both exact endpoint/MAC pairs configured.
The test must succeed through both peers simultaneously without prefix fallback.
Do not change peer configuration while the experiment is active.

```sh
python3 contrib/vtep-return-affinity/k8s/validate.py \
  --context kind-vtep-affinity-lab --image vtep-affinity-probe:local \
  --external-peer affinity-peer-a --external-peer affinity-peer-b \
  --external-network kind --external-client 198.18.0.9/32 \
  --restart-agent --drain-node --report /tmp/vtep-external-kubernetes.json
```

The peer VXLAN interfaces use VNI 2/UDP 8472, the target node's real VXLAN MAC,
and a direct pod /32 route. Actual Linux TCP sockets bind the shared client
address. Every short probe uses a fresh port; local bind/exec failures cannot
count as policy denial. Existing sessions must retain the same server-side
connection identifiers across agent replacement. Workload replacement and drain
test fresh connections after retargeting; they do not promise that a connection
to a deleted pod survives.

Cleanup deletes the runner-created peer links and state files, deletes its
namespace and uncordons its drained node. A failed cleanup fails the report.
The two operator-created containers remain for inspection; remove them manually
afterwards with `docker rm -f affinity-peer-a affinity-peer-b`. Peer addresses,
MACs and connection identifiers are not included in the JSON report. A test
failure can leave fixtures requiring inspection; never run this on production.
