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
The harness does **not** yet provision external VTEP peers inside Kubernetes.
A passing report here would complete the native CNI/identity/policy checkpoint;
it would not demonstrate Kubernetes-plus-external-VTEP return affinity. The
isolated VM separately exercises actual VXLAN peers and actual endpoint code.

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
