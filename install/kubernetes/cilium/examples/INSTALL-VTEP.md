<!-- This file was not reviewed by a human before submission -->
# Build and install the fork's VTEP chart

This chart keeps the upstream Cilium values structure. The added switch is
`vtep.experimentalReturnAffinity.enabled`, default `false`. Peer configuration
uses the existing `vtep.enabled`, `endpoint`, `mac`, `cidr` and `mask` fields.
Images use the standard `image.override` and `operator.image.override` fields.
The example selects IPv4 VXLAN, cluster-pool IPAM, exclusive Cilium CNI and full
kube-proxy replacement. It disables proxy/encryption/endpoint-route paths that
the experiment does not support. It does not remove EKS add-ons or migrate nodes.

## 1. Check out one source version

Use Git, GNU make, the Go version in `go.mod`, Docker with Buildx and Helm 3.
The commands build Linux amd64 images, the architecture covered by the lab tests.
Use a clean checkout and authenticate to your chosen registry locally.

```sh
git clone --single-branch --branch experimental/vtep-return-affinity-lab-v29 \
  https://github.com/imanlotfimahyari/cilium.git cilium-vtep
cd cilium-vtep
git rev-parse HEAD
git status --short
```

For reproducing a downloaded package, check out the exact commit in its
`SOURCE.txt` before building. Do not mix an upstream image or another source
version with this fork chart. The package retains chart/appVersion
`1.21.0-dev`; its file name alone does not identify this fork's source commit.

## 2. Build locally, then push

Set a registry namespace you own, without `https://` or a trailing slash.
No registry credentials are stored in the chart. The namespace below is an
example; replace it with your own before building.

```sh
export IMAGE_PREFIX="registry.example.com/your-namespace"
export IMAGE_TAG="vtep-$(git rev-parse --short=12 HEAD)"
export CILIUM_IMAGE="$IMAGE_PREFIX/cilium:$IMAGE_TAG"
export OPERATOR_IMAGE="$IMAGE_PREFIX/operator-generic:$IMAGE_TAG"

make docker-cilium-image docker-operator-generic-image \
  ARCH= CI_BUILD= \
  DOCKER_DEV_ACCOUNT="$IMAGE_PREFIX" DOCKER_IMAGE_TAG="$IMAGE_TAG" \
  DOCKER_FLAGS="--platform linux/amd64 --load"

docker push "$CILIUM_IMAGE"
docker push "$OPERATOR_IMAGE"
```

These targets build the full agent image, including BPF sources/runtime tools,
and the generic operator required by cluster-pool IPAM. They use the pinned
builder/runtime dependencies in this checkout. No separate custom Envoy or
Hubble image is needed for this example. A static agent binary alone is not
the deployment image. Builds still require downloading the pinned base images.
If the nodes cannot pull your registry anonymously, configure a pull Secret in
`kube-system` and the standard `imagePullSecrets` chart value.

Optional: inspect the pushed digests and use `repository@sha256:...` references
instead of the source-specific tags above:

```sh
docker buildx imagetools inspect "$CILIUM_IMAGE"
docker buildx imagetools inspect "$OPERATOR_IMAGE"
```

## 3. Package the chart and fill the values

```sh
mkdir -p dist
helm package ./install/kubernetes/cilium --destination ./dist
helm show values ./dist/cilium-1.21.0-dev.tgz > ./dist/values-full.yaml
cp ./install/kubernetes/cilium/examples/values-eks-vtep-affinity.yaml \
  ./dist/values-eks-vtep-affinity.yaml
```

Edit `dist/values-eks-vtep-affinity.yaml` locally:

| Input | Value to supply |
| --- | --- |
| `k8sServiceHost` | Direct EKS API hostname without `https://`; port is 443 |
| `ipam.operator.clusterPoolIPv4PodCIDRList` | Pod CIDR that overlaps none of the VPC/connected networks, Service or external client ranges |
| `image.override` | Patched agent image; alternatively supplied by the CLI below |
| `operator.image.override` | Matching operator-generic image; alternatively supplied by the CLI below |
| `operator.replicas` | 2 for a lab with at least two workers; use 1 for a single-worker lab |
| `vtep.endpoint`, `mac`, `cidr`, `mask` | Exact peer pairs, client CIDRs and common mask when VTEP is enabled |
| `vtep.enabled` | Enable the existing VTEP integration when its peer inputs are ready |
| `vtep.experimentalReturnAffinity.enabled` | Enable the experiment only after the running-kernel checks pass |

The two image placeholders can remain in the file only when overridden by the
explicit CLI arguments below. Replace the API/CIDR placeholders before using it.
Use either the new experimental value or its legacy `extraConfig` key, never both.
The dedicated false default does not override a legacy enabled `extraConfig` key.
All standard upstream values are still available through `values-full.yaml`.
Map capacities, peer-freeze rules and journal/pin locations are runtime contracts,
not additional configurable Helm inputs; this chart does not invent new knobs.

## 4. Render, then install

Run against the intended disposable cluster context. AWS VPC CNI and kube-proxy
must be retired through your existing cluster provisioning/migration process.
For EKS overlay mode, ensure API-server-reachable endpoints for webhooks and
similar services; the managed control plane cannot directly route to overlay
pod IPs. Permit node/peer VXLAN traffic on UDP 8472 according to your topology.

```sh
helm lint ./dist/cilium-1.21.0-dev.tgz --kube-version 1.35.0 \
  -f ./dist/values-eks-vtep-affinity.yaml \
  --set-string image.override="$CILIUM_IMAGE" \
  --set-string operator.image.override="$OPERATOR_IMAGE"

helm template cilium ./dist/cilium-1.21.0-dev.tgz \
  --namespace kube-system --kube-version 1.35.0 \
  -f ./dist/values-eks-vtep-affinity.yaml \
  --set-string image.override="$CILIUM_IMAGE" \
  --set-string operator.image.override="$OPERATOR_IMAGE" \
  > ./dist/rendered.yaml

helm upgrade --install cilium ./dist/cilium-1.21.0-dev.tgz \
  --namespace kube-system --create-namespace \
  -f ./dist/values-eks-vtep-affinity.yaml \
  --set-string image.override="$CILIUM_IMAGE" \
  --set-string operator.image.override="$OPERATOR_IMAGE" \
  --wait --timeout 15m

kubectl -n kube-system rollout status daemonset/cilium --timeout=10m
kubectl -n kube-system rollout status deployment/cilium-operator --timeout=10m
kubectl -n kube-system exec daemonset/cilium -- cilium-dbg status --verbose
```

For the downloadable kit, the archive's `chart/` contains the complete chart
directory. Run `helm package ./chart --destination ./dist` to produce the same
chart from those source files, or use the supplied `.tgz` directly and copy the
example values into `dist/` before running the commands above.

## Runtime boundary

Current code accepts only reviewed Ubuntu builds `6.8.0-31-generic` and
`6.12.0-061200-generic`, with verified CONFIG_HZ=1000 and the expected BTF tracing
targets for SYN-cookie ownership. AL2023 still needs a kernel port and live
validation. Merely adding an Amazon kernel to the allowlist is not sufficient.
Keep the experimental flag off on AL2023 until that work is completed.

If required after validation, the standard optional mount is:

```yaml
extraHostPathMounts:
  - name: running-kernel-config
    mountPath: /boot
    hostPath: /boot
    hostPathType: Directory
    readOnly: true
```

This only makes `/boot/config-<running-release>` readable; it does not make an
unsupported kernel compatible. ConfigMap-only changes do not activate the
startup-only flag. Plan an explicit agent rollout; recreate existing pods to
opt in. Drain selected pods before disabling, changing peers or rolling back.
Do not erase pinned maps or history, or use cleanState/cleanBpfState as recovery.
A Helm rollback does not establish older-binary state compatibility.

This is a personal-fork experiment. Real EKS/CNI/normal-identity/policy validation,
image execution on EKS and native performance measurements remain pending.
