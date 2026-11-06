<!-- This file was not reviewed by a human before submission -->

# Experimental IPv4/TCP VXLAN return affinity

The forwarding and agent lifecycle implementation is present behind the
startup-only, default-off `vtep.experimentalReturnAffinity.enabled` Helm value.
The agent preserves the original external peer on the kernel socket and keeps
return selection after normal Cilium policy/connection-tracking checks.

**[SUPPORT.md](SUPPORT.md) is the authoritative current capability, compatibility,
capacity and validation matrix.** It distinguishes implemented behavior from
historical live evidence and unexecuted deployment gates. The Helm package
includes a generated copy at `examples/SUPPORT-VTEP.md`.

Upstream integration snapshot: `7d0c8c64dbdba8e101b35cd502371ea762590183`,
6 November 2026. The previous fork checkpoint `308356ca6c05` is preserved in
Git history. [Refreshed-main checks](VALIDATION-main-20261106.md) document this
integration. Last full-daemon VM evidence is [v29](VALIDATION-v29.md), not a new
Kubernetes or native performance result. This is a personal-fork lab experiment.

## Install and configure

Use the fork's standard chart under `install/kubernetes/cilium`, with full
`values.yaml`, schema and templates. The only added enablement value is
`vtep.experimentalReturnAffinity.enabled`; exact peers use the existing VTEP
fields. See [the packaged EKS/VTEP example](../../install/kubernetes/cilium/examples/values-eks-vtep-affinity.yaml)
and [source image/chart build commands](../../install/kubernetes/cilium/examples/INSTALL-VTEP.md).

Use the exact target-kernel requirements and remaining AL2023 blocker in
[SUPPORT.md](SUPPORT.md). A chart render cannot establish kernel compatibility.
Newly created eligible endpoints opt in; existing pods need recreation.
The value is startup-only and the chart retains `rollOutCiliumPods=false`.
Physically drain selected pods before disabling, changing peers or rolling back.
Do not clear pins/history to force startup. A false dedicated value does not
remove an enabled legacy `extraConfig` key.

## Structure and packet path

| Component | Responsibility |
| --- | --- |
| `bpf/lib/vtep_return_socket.h` | Policy-approved SYN admission, exact request binding, immutable socket ownership and lifetime-safe cleanup |
| `bpf/lib/vtep_return_core.h`, `bpf_lxc.c` | Admission after ingress policy and return selection after ordinary egress policy/CT |
| `bpf/lib/vtep_return_cookie*.h` | Trusted cookie handshake ledger, exact child/packet proofs, replay/collision guard and expiry |
| `bpf/lib/vtep_return_timewait*.h` | Exact TIME-WAIT incarnation transfer/destruction, queued ACK proof and GC |
| `bpf/bpf_vtep_return.c` | Sockops, tracing, selected-pod TCX and retirement programs |
| `pkg/datapath/vtep/returnaffinity` | Agent/loader controller, canonical pins, durable journal, readiness and endpoint lifecycle |
| `live/`, `k8s/`, `capacity/` | Isolated packet/agent fixtures, disposable-cluster harness and read-only diagnostics |

Trusted ingress records the external peer or explicit native origin. An opaque,
never-reused nonce in an internal SYN MAC connects policy-approved admission to
the saved SYN and exact kernel request. It grants no authority by itself.
Namespace/generation, tuple, ISN, request and actual socket identity must agree.
TIME-WAIT and cookie paths use their own exact incarnation/packet evidence;
application data always requires the actual immutable socket owner.

## Lifecycle and recovery

Startup leases the runtime and validates boot, peers, durable history, the entire
canonical map bundle and pinned hooks. Compatible links are reused without a
detach gap; missing/incompatible state is not silently replaced. Hooks, peers
and initial collection are installed before readiness.

Synchronous CNI preparation verifies namespace/veth identity and absence of
pre-existing listeners/sockets. Durable PREPARING precedes hook installation;
a second socket census precedes READY/CNI completion. Partial installation needs
pod replacement. Retirement installs an independent drop guard before endpoint
links disappear; reclamation requires physical drain, not FIN/timeout guesses.
Retired cookies are compacted into exact ranges without rejecting gaps belonging
to unrelated namespaces. [OPERATIONS.md](OPERATIONS.md) describes diagnostics,
[DOWNGRADE.md](DOWNGRADE.md) the bounded historical compatibility export.

The abandoned CT-bit/tuple-guard experiments were already removed. The focused
compiler check requires `conntrack.h` to match the merged upstream snapshot and
compares sampled feature-off executable sections against that same snapshot.

## Design and evidence

- [Design invariants and review gates](REVIEW.md)
- [TIME-WAIT mechanism](TIMEWAIT.md) and [cookie mechanism](SYNCOOKIES.md)
- [Operational diagnostic and hook/map review](OPERATIONS.md)
- [Disposable Kubernetes harness and its current execution boundary](k8s/README.md)
- [Checkpoint index](CHECKPOINTS.md) and individual `VALIDATION-v*.md` reports

Checkpoint reports are historical records. Their former "next step" or
"unsupported" statements do not override [SUPPORT.md](SUPPORT.md).

## Reproduce focused checks

Use Go matching `go.mod`, Cilium's Clang and Helm. These commands do not replace
privileged live tests or a real-cluster deployment:

```sh
go test ./pkg/datapath/vtep/returnaffinity ./pkg/datapath/vtep \
  ./pkg/datapath/linux/config ./pkg/datapath/loader ./pkg/endpoint ./pkg/status
go test -race ./pkg/datapath/vtep/returnaffinity
go vet ./pkg/datapath/vtep/returnaffinity \
  ./contrib/vtep-return-affinity/live ./contrib/vtep-return-affinity/k8s/probe
python3 contrib/vtep-return-affinity/test_helm.py
python3 -m unittest discover -s contrib/vtep-return-affinity/k8s -p 'test_*.py'
python3 contrib/vtep-return-affinity/run_spike.py --clang clang --output /tmp/vtep-build
```

`privileged_vm.py`, `kernel_matrix.py` and the checkpoint reproduction reports
specify the trusted kernel/object arguments and explicit isolated-guest safety
markers. Privileged cases skip outside that environment; never report those
skips as fresh packet/verifier/lifecycle passes. Real EKS and native measurements
remain separate gates in [SUPPORT.md](SUPPORT.md).
