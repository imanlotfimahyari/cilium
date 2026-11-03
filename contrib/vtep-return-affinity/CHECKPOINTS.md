<!-- This file was not reviewed by a human before submission -->

# Checkpoint workflow

v28 extends the external Kubernetes fixture and read-only pressure diagnostics,
then fixes stale restart/progress and report evidence. Host unit/race, offline
harness and both kernel matrices pass. No BPF runtime or hook/map change occurs;
real Kubernetes and native performance remain pending. See VALIDATION-v28.md.

Recovered v27 source `691819609b` matches the previous production tree exactly.
Fixture `bd5f35ae81` restores distinct cookie probe tuples per version transition.
All 119 files are published with an identical tree on the separate main-v27
branch. Fresh unit/build/race checks and both packet/controller matrices pass;
actual-agent upgrade/rollback between the rebuilt versions, fresh-record GC,
replacement and drain/disable pass on both kernels. See VALIDATION-v27.md.

v26 `efccb8e9c7` closes the fresh-record periodic agent GC evidence gap on both
reviewed kernels. Two real records are observed live, preserved until expiry
and collected while four socket owners/flows survive; new admission then passes.
Only tests/documentation change. See VALIDATION-v26.md for exact scope.

v25 implementation `89fe4373da`, fixture sequencing `8f9a451e37` and actual-loader
pruning fix `a8badddd9d` integrate trusted cookie forwarding into the default-off
agent. Both kernels pass the 18-map/eight-tracing-hook controller checks and
actual-daemon SIGKILL/restoration, incompatible rollback refusal/recovery, pod
replacement and drain/disable. VALIDATION-v25.md records the exact evidence
and remaining Kubernetes, performance and compatibility limits.

v24 implementation `da987349f1` proves the trusted live cookie packet-to-child
handoff on both kernels. It is still build-time gated off in the agent.
VALIDATION-v24.md records frozen-artifact final evidence and the v3 lifecycle
work needed before agent-managed enablement.

v23 implementation `47fdea7b11` adds only an isolated candidate SYN-cookie
peer-binding ledger and explicit two-vCPU test support. Both kernels pass all
eleven required cases; production objects are unchanged and cookie forwarding
is still unsupported. See VALIDATION-v23.md for trusted-handoff/lifecycle gates.

v22 implementation `44eaa342a7` adds actual-daemon restart under live admission
pressure. Both kernels pass with no failed/skipped required tests. The source
backup `a44cf0bf82` matches tree `4956e1196b09b5d45a3a8d63289f1c062c871885`.
See VALIDATION-v22.md for the exact scope and remaining gates.

v21 implementation `6e0669026b` adds concurrent producer/GC/compatible-reload live tests and a separate
production-size controller restart-under-pressure test. Production programs,
map schemas and compatibility rules are unchanged from v20. VALIDATION-v21.md
records exact executed coverage and distinguishes these two fixtures from a
full-agent workload/rollout test.

v20 implementation `97b41df1b9` validates real pinned-map capacity and actual
Cilium pressure paths, and fixes packet-association insertion accounting in the
existing counter. It requires drain/disable before replacing older live tracing
code. VALIDATION-v20.md records the successful two-kernel runs and remaining gates.

The v19 read-only diagnostic and focused hook/map review build on published v18
`fe4c069def`. See OPERATIONS.md for the unit/CLI evidence and the live-kernel
pressure and native-performance gates that remain open. No new privileged
validation is implied by this checkpoint.

- Keep the integration branch separate from upstream `main`.
- Commit each completed, validated milestone before starting the next one.
- Record the upstream commit and exact validation scope. Keep historical reports
  tied to their tested checkpoint; do not silently relabel old results.
- Preserve a known-good checkpoint when incorporating newer upstream changes,
  and rerun checks appropriate to the changed dependencies and behavior.
- Publish checkpoints to the authorized personal fork. Verify its commit/tree
  before calling the backup complete. A fork's existence alone is not a code backup.
- If remote write authorization is unavailable, retain a verified Git bundle
  and report the blocker. Never overwrite unrelated remote history.

## Historical source checkpoint references

| Commit | Scope |
| --- | --- |
| `b0d989ff1ba2825521daa895cba594e385d27fa9` | v14 source and original Linux 6.8 lifecycle evidence |
| `cb3c9277` | Incorporate upstream `b28d8046` while preserving v14 history |
| `67656647` | Fail readiness on canonical map-pin damage |
| `8a8a6d4c` | Actual TIME-WAIT policy/CT proof tests and deterministic close/replay capture |

The integration branch is `experimental/vtep-return-affinity`.

A bundle that excludes upstream `b28d8046` requires that commit and its ancestor
`fe561573` to be present in the destination clone. Verify with `git bundle verify`,
then fetch the bundle's `experimental/vtep-return-affinity` ref into a new local
branch. Pushing that branch still requires authorized write access to the fork.

## Recoverable published baseline and v16

Browser publication reconstructed the source tree under different commit IDs.
Published `9ea884789749b1576b48f2f7e534c4f245943d01` has tree
`7d88d479c8a864643d878c14bbddc61a52453c5c`, exactly matching the originally
tested local `b3231c22779126531730da42ec85cedecb6df668`. Cloning the fork
recovers that source; the older local hashes above are historical references,
not a promise that their original objects are reachable on the browser branch.

The v16 local commits start from that recoverable published baseline:

- `cf05815e`: strict, bounded recovery journals, with original input preserved
  on refusal; shared decoding for the agent and offline exporter.
- `5f2cc31b`: reviewed TIME-WAIT kernel variants and tracing ABI validation.
- `b76ab98f`: loss/offload/unsupported-TCP coverage, explicit validation
  evidence checks, a sequential kernel matrix and real two-boot recovery.

See VALIDATION-v16.md for executed tests and the gates still open. Compare
source trees after any browser backup; commit hashes alone will differ.

## v17 actual-agent validation

The recovered v16 baseline is published `f4d987348c1d81af78311baad9a805b8f9ff78d5`,
tree `cf7b93662972439a3da0c0475341eb43b8cf97bc`, matching the original local
v16 checkpoint `f08a3944`.

Local `aafd68daa0bd247137706c3d8c3d51cee39de26c` adds the two-version agent
fixture, isolated artifact packaging, binary/source fingerprints and required
transition evidence. Its source tree `83606c29e8a578cedbd6587aaf347e92391e0548`
was verified byte-for-byte against published
`d4f349cba28bf3c370cea33653e34c0754bde149` before further work.

The subsequent rejected-startup assertion requires the old agent's specific
unsupported-hook diagnostic and failed readiness, since base-datapath retries
do not necessarily terminate the process. See VALIDATION-v17.md for the final
executed evidence and its limits. Historical v16 reports retain their original
scope; v17 adds actual-agent evidence rather than relabeling older tests.

## v18 SYN-cookie capability checkpoint

Local `de831993a7` adds one isolated cookie-child fexit probe, socket-local
evidence and real-kernel regression tests. Both supplied kernels pass the new
cases and retain the production forced-cookie fail-closed regressions. The
probe does not modify the agent or production BPF. See SYNCOOKIES.md and
VALIDATION-v18.md for the exact scope, evidence and next peer-binding gate.
