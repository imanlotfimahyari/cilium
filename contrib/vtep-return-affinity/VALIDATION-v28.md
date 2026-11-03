<!-- This file was not reviewed by a human before submission -->

# v28: external Kubernetes harness and read-only pressure context

3 November 2026. **Focused host and two-kernel regression checks PASS.**
The external Kubernetes fixture is implemented and offline-tested; cluster
execution and native performance remain pending. This is an experimental lab
checkpoint, not production readiness or an upstream submission.

## Changes and source

- Based on published v27 plus main refresh `7f9316a60f` (upstream `26d69186dd`).
- Local implementation checkpoints: `a8d07d1fb7`, `9f2f79b1a1`, `0e77f5cd27`,
  `11dc9cce1b`. Branch: `experimental/vtep-return-affinity-hardening-v28`.
- Two explicitly labelled local Docker peers can send real VNI-2 VXLAN traffic
  from the same client address using distinct ports. The Kubernetes runner adds
  allow/deny checks, simultaneous held sessions across agent replacement,
  workload replacement and optional node drain. Images/peers must be provisioned
  by the operator before enabling the frozen peer configuration.
- Local bind/exec errors cannot count as policy denial. Restart success requires
  unchanged connection IDs and fresh progress after restored readiness. Invalid
  invocations invalidate stale PASS reports before preflight. Cleanup waits for
  namespace deletion and still attempts uncordon after other cleanup failures.
- Capacity output adds map stage, observed headroom and explicit uncertainty.
  Dedicated admission/request insertion-failure counters are still absent.
- BPF source is byte-identical to the v27 main-refresh parent. No map/schema,
  tracing-hook, forwarding behavior, configuration API or Helm change occurs.
  The abandoned CT/guard implementation was already removed in earlier work.
- Design notes now distinguish historical gates from current executed evidence.

## Fresh host checks

- Go 1.27.3 and Clang 21.1.8.
- Controller and TCP probe unit tests: PASS.
- Controller and probe race tests: PASS; focused Go vet: PASS.
- Five selected loader/template/cache tests: PASS with restored Clang on PATH.
- Kubernetes/external-harness offline suite: 13 tests PASS, including stale
  restart progress, reconnect rejection, local setup/exec failures, fixture
  isolation, cleanup continuation and stale-report invalidation.
- Evidence/preflight Python suite: 4 tests PASS.
- All 13 selected BPF objects compile with strict warnings; conntrack.h remains
  identical to baseline and both sampled flag-off executable comparisons pass.
- Static controller/live/BPF test binaries build; static probe/capacity tools
  build without an ELF dynamic interpreter. Missing-map capacity CLI exits 1
  with incomplete evidence and explicit limitations.
- `git diff --check`: PASS.

An initial extra loader invocation lacked Clang on PATH and was corrected before
its passing rerun. An initial BPF-runner build used the wrong package path;
final commands use `./bpf/tests/bpftest`. Neither required production changes.

## Fresh disconnected QEMU/TCG execution

Each guest has two vCPUs and 1,536 MiB. Counts include root and subtest entries.
The report suite named `agent` contains controller/map tests here, not an
actual full-daemon lifecycle run.

| Suite | Linux 6.8.0-31-generic | Linux 6.12.0-061200-generic |
| --- | --- | --- |
| Conntrack | 8 PASS | 8 PASS |
| Core forwarding/policy | 17 PASS | 17 PASS |
| Controller/maps, including new pressure assertions | 49 PASS | 49 PASS |
| Cookie forwarding/adversarial ledger | 30 PASS | 30 PASS |
| Runner duration | 334.473s | 334.285s |

Both VM exits are zero, with no failed/skipped entries or report errors.
Read-only pressure checks fill eight production-size transient maps, preserve
all entries, verify full/headroom classification, reject writes/deletes through
read-only descriptors, and reject incomplete/replaced pins. Other checks cover
restore, damaged state, both IPv4 listener forms, exact cookie child ownership,
policy denial, collision/replay, exhaustion, concurrency and real expiry.

These are emulated correctness results, not performance measurements. The v27
actual-agent lifecycle evidence is retained; the full-daemon transition suite
was not rerun for this harness/read-only diagnostic change.

## Artifact identities

| Artifact | SHA-256 |
| --- | --- |
| agenttest | `7ba6ae23084f1f2c07463cee9dbba66b99d291949dc929322a22fd67ed432133` |
| livetest | `326dc7bbb2e309c422a3a8e1b5b4c701f0ca2127405d1c363bfcf0cd1b4c1ad5` |
| bpftest | `0036882890b843bdec975689f2f99f5150e3986b8585b9be315b9297817d8c02` |
| affinity-probe | `fd6bd7cac159e7b747f7859c0acff86a0df327496e3499d527f03cf0532abada` |
| vtep-capacity | `78ee108ed7dd48842ecba03ab048559bd5ac18cd0a9559d0ff2d97506344cf03` |
| Kernel linux68 | `cee36e261749483e951c8229eb1aeeb768af6c28f493421a52b3916885ce913f` |
| Kernel linux612 | `144439e925a02129b01c74a37a73466494cac3876d65bc3850e3b9f1b260d44c` |

## Explicit remaining gates

The live Kubernetes preflight reports **blocked** because kubectl and Docker
are unavailable; no cluster operations were performed. Peer-image assembly and
the external fixture have not run against Docker/Kubernetes. Offline fixtures
are not CNI, policy or rolling-node evidence.

Real cluster execution with normal identities and external peers, native load
and overhead, node reboot/rolling deployment, broader kernel/version coverage
and independent human architecture/security review remain. Existing restricted
TCP/VXLAN scope, trusted-underlay assumptions, frozen peers, drain-required
disable and reconnect after complete authoritative-state loss still apply.
Helm integration remains deferred until the configuration contract is stable.
Human review and an honest AIL score (this work: AIL:4) are required before
upstream submission. See [reproduction commands](REPRODUCE-v28.md).
