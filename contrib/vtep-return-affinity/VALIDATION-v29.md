<!-- This file was not reviewed by a human before submission -->

# v29: refreshed daemon lifecycle and experimental Helm lab integration

3 November 2026. **Fresh current-agent lifecycle checks PASS on both reviewed
kernels. Helm render/lint, generation checks and offline tests PASS.**
Real Kubernetes/image execution and native operational/performance gates are
**blocked** in this environment. This remains a personal-fork lab experiment,
not a production-ready or upstream-approved contribution.

## Implementation scope

- Base: published v28 `14a657076f`. Local Helm checkpoint `c52f712284`, legacy
  precedence clarification `11c948a142`, journal caveat `bedd412620`.
- New chart value: `vtep.experimentalReturnAffinity.enabled`, boolean, **false**
  by default. It forwards the existing agent flag only when enabled. No agent/BPF
  runtime, pinned-map schema, tracing-hook or forwarding change occurs.
- Chart guards reject known unsupported settings, missing explicit peers,
  ownership-erasing cleanup flags and duplicate dedicated/extraConfig controls.
- The default false value preserves existing legacy extraConfig behavior;
  retiring that path requires disabling/removing its key explicitly.
- Generated values/schema/docs and the lab instructions describe patched-image,
  new-pod, frozen-peer, drain and journal-format requirements. Helm cannot prove
  that selected pods have drained or that an older binary can read the journal.

## Fresh current-agent execution

A new static Cilium agent was built with Go 1.27.3, `CGO_ENABLED=0`, `-trimpath`
and `-ldflags='-s -w'`. Its runtime sources are v28 `14a657076f`, byte-identical
in v29. Existing static live/BPF test artifacts were verified byte-for-byte
against the published v28 hashes before reuse. No unavailable original binary
or historical PASS was substituted for the fresh execution.

Each disconnected QEMU 8.2.2/TCG guest has two vCPUs and 3,072 MiB, trusted
matching vendor kernel/config/modules, Clang 21.1.8 and the required iptables
runtime. The 11 required root/subtest entries all pass on each kernel:

- Actual-loader pruned-map replacement regression and real-agent root test.
- Periodic GC preserves TIME-WAIT ownership.
- Kernel cookie children have exact peer owners; native ownership bypasses an
  overlapping legacy VTEP prefix.
- Actual agent SIGKILL/restart preserves live flows, exact ownership and all
  18 map/eight tracing-link/two pod-hook identities. Fresh cookie children bind
  while the process is down and after restoration.
- Fresh cookie records expire through the running agent's periodic collector
  while established owners/flows survive.
- Endpoint retirement prevents legacy fallback; workload replacement reuses
  the address/interface safely.
- Disabled startup refuses live membership; coordinated drain removes the
  runtime and ordinary TCP works with the feature disabled.

| Fresh required execution | Linux 6.8.0-31-generic | Linux 6.12.0-061200-generic |
| --- | --- | --- |
| Conntrack entries | 8 PASS | 8 PASS |
| Core forwarding/policy entries | 17 PASS | 17 PASS |
| Required actual-agent/loader entries | 11 PASS | 11 PASS |
| Runner elapsed time | 769.316s | 710.24s |

Both VM exits are zero with no failed/skipped entries or report errors. These
are **emulated correctness** results. The standalone daemon still uses the
explicit no-policy allocator; normal Kubernetes identities/CNI and policy were
not validated together. The separate core packet fixture remains policy/CT
evidence. Cross-version upgrade/rollback was not rerun: v27's rebuilt-prototype
transition report remains the evidence for that narrower historical contract.

## Helm and offline validation

- Helm 3.16.3 lint: PASS.
- Five chart render tests: PASS, including 19 incompatible-setting subcases,
  enabled string-valued flag uniqueness, string-boolean schema rejection,
  duplicate configuration refusal and retained legacy behavior.
- Default ConfigMap bytes and all deterministic default resources match v28;
  only upstream-labelled non-idempotent resources are excluded from the latter
  comparison. No cluster deployment was performed.
- Generated values match the existing Makefile recipe with yq 4.45.1.
- helm-schema 0.9.0 (the pinned toolbox version) produces an identical schema
  apart from the retained review-only root `$comment`.
- helm-docs 1.11.0 (the pinned toolbox version) reproduces the committed README.
- Root tooling/render Python suite: 9 tests PASS; Kubernetes/external harness
  offline suite: 13 tests PASS. Total: 22 root tests; no skipped tests in these
  selected invocations. Python/PyYAML and an explicit Helm binary are required
  for the chart render tests.
- `git diff --check`: PASS.

The first render regression encountered nullable metadata annotations in the
upstream chart; the test reader was corrected to accept absent annotations.
The production templates did not require a fix for that test setup issue.

## Artifact identities

| Artifact | SHA-256 |
| --- | --- |
| Current static agent | `0228927967661a03a86d87960b8d9cfe4ee41c1d19a4eadfcedf6229bf0cdb66` |
| Reused live tests | `326dc7bbb2e309c422a3a8e1b5b4c701f0ca2127405d1c363bfcf0cd1b4c1ad5` |
| Reused BPF runner | `0036882890b843bdec975689f2f99f5150e3986b8585b9be315b9297817d8c02` |
| Kernel linux68 | `cee36e261749483e951c8229eb1aeeb768af6c28f493421a52b3916885ce913f` |
| Kernel linux612 | `144439e925a02129b01c74a37a73466494cac3876d65bc3850e3b9f1b260d44c` |

## Blocked requested gates and remaining scope

The actual external Kubernetes invocation freshly reports `blocked`:
`kubectl` and Docker are unavailable and no cluster operation was performed.
There is no Docker socket, kubeconfig, KVM device, writable host cgroup tree or
NET_ADMIN/BPF capability. No connected disposable native lab is available.
Therefore peer-image build/run, real CNI/normal identities/policy/external-peer
execution, rolling node operations and credible native measurements did **not**
run. The Helm candidate is render-tested only.

No cloud machines, GitHub runners or paid resources were provisioned. An
accessible privileged Linux/Docker host can execute the documented kind lab;
credible multi-node hardware measurements additionally require a controlled
native topology and appropriate reachable external peers. The current Docker
peer adapter assumes a shared local kind bridge and is not a multi-host adapter.

Existing restrictions remain: direct-pod IPv4/TCP VXLAN/veth-TCX only; Services/
NAT, encryption/proxies, IPv6/Geneve/netkit and unsupported TCP paths remain out
of scope. Unknown ownership drops, peer configuration is frozen, disable needs
drain, and complete loss of authoritative ownership requires reconnecting.
Independent human architectural/security review, maintenance agreement and an
honest AI disclosure remain separate upstream gates. This work is AIL:4;
passing tests and disclosure do not themselves satisfy Cilium's AI policy.

See [the lab guide](k8s/README.md) and [reproduction commands](REPRODUCE-v29.md).
