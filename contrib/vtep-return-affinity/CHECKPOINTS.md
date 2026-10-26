# Checkpoint workflow

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
