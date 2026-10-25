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

## Retained source checkpoints

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
