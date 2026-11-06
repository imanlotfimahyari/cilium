<!-- This file was not reviewed by a human before submission -->
# Chart and upstream-main checkpoint — 6 November 2026

Upstream snapshot: `7d0c8c64dbdba8e101b35cd502371ea762590183` on
`experimental/vtep-return-affinity-lab-v29`. The download's `SOURCE.txt` identifies
the exact published fork commit. Chart/appVersion remains `1.21.0-dev`.

- Merged 63 upstream commits; reviewed eight overlapping files with no textual conflicts.
- Helm 3.16.3 lint passes for defaults and the EKS example at Kubernetes 1.35.0.
- Eight Helm regression tests pass, including 19 unsupported-setting subcases,
  upstream default manifests, schema/legacy flags, image/API inputs, EKS settings,
  package contents, SPIRE migration and authoritative support-copy consistency.
- Full defaults/schema match upstream apart from the default-off affinity field.
- Values generation and helm-docs 1.11.0 reproduce committed files without drift.
- Focused Go unit/race/vet checks, daemon compilation, 13 strict BPF object builds,
  sampled flag-off bytecode comparisons and 17 offline harness/tooling tests pass.
- `git diff --check` passes.

Upstream moved `authentication.mutual.spire` to `encryption.ztunnel.spire`.
Rebuild complete intended overrides from the new defaults and use the documented
`--reset-values` installation command. Do not retain the old nonempty value.

No OCI images were built/run, no refreshed full-agent VM or live-packet tests
executed, and no real EKS/CNI/native performance validation occurred in this run.
Last full-daemon live evidence remains `contrib/vtep-return-affinity/VALIDATION-v29.md`.
Current AL2023 support is unchanged: the experimental feature cannot be enabled
on that kernel until a reviewed kernel port and validation are completed.

[SUPPORT-VTEP.md](SUPPORT-VTEP.md) is the current support matrix. The repository's
`contrib/vtep-return-affinity/VALIDATION-main-20261106.md` contains the full review
and evidence boundary. Drain before incompatible binary upgrades; chart rollback
alone does not establish pinned-state compatibility.
