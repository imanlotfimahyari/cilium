<!-- This file was not reviewed by a human before submission -->
# Upstream-main integration checkpoint — 6 November 2026

Branch: `experimental/vtep-return-affinity-lab-v29`.
Previous published head: `308356ca6c051ddb8b837df103326adffe7b4711`.
Upstream snapshot: `7d0c8c64dbdba8e101b35cd502371ea762590183`.
Local integration commit: `2338e8b6` (publication may use an equivalent merge).

## Integration review

Merged 63 upstream commits since the common ancestor
`26d69186dd96431265a44b68f72ba5db110f364f`. Upstream changed 396 files;
eight overlap the fork: endpoint BPF, endpoint configuration generation, and
six chart/default/schema/documentation files. The merge had no textual conflicts.

Reviewed the overlapping changes semantically. Upstream NodePort and policy
runtime configuration changes retain affinity admission after policy and before
CT publication; return ownership selection remains after policy/CT. The three
endpoint affinity defines remain present. Upstream loader changes and endpoint
replacement-reference fixes are included and their focused tests pass.

The chart adopts upstream's `authentication.mutual.spire` move to
`encryption.ztunnel.spire`, including rejection of the legacy nonempty object.
Installation instructions rebuild complete overrides and use `--reset-values`.
New IPAM release settings retain upstream defaults. The experiment still requires
encryption/ztunnel disabled; no new runtime feature or configuration API is added.
BPF and Helm comparison baselines now match this exact upstream snapshot.

## Completed checks

- Go 1.27.3 focused unit tests pass for returnaffinity, Linux configuration,
  loader, endpoint, endpointmanager and status; the VTEP package has no tests.
- Controller race tests and focused controller/live-tool/probe `go vet` pass.
- `daemon/cmd` compiles with `go test -run '^$'`; no daemon tests execute in that check.
- Clang 21.1.8 strict compilation passes for 13 BPF fixture/runtime objects.
  The Clang tools were extracted from the checkout's pinned official builder.
- `conntrack.h` is byte-identical to this upstream snapshot. Sampled flag-off
  overlay and `tc_lxc_policy_drop` executable sections match upstream.
- Eight Helm regression tests pass, including 19 unsupported-setting subcases,
  upstream default-manifest comparison, SPIRE migration rejection, schema,
  feature flags, EKS overrides, package contents and support-copy consistency.
- Helm 3.16.3 lint passes for defaults and the EKS example at Kubernetes 1.35.0.
- Thirteen offline Kubernetes-harness tests and four tooling tests pass.
  These use fixtures/mocks and are not actual Kubernetes/CNI execution.
- Full values and schema equal merged upstream after removing only the
  dedicated default-off feature and schema provenance comment.
- Values regeneration and helm-docs 1.11.0 reproduce the committed files.
- `git diff --check` passes.

## Evidence boundary and upgrade procedure

No privileged verifier/live-packet/full-agent VM run, OCI image build, real
Kubernetes/EKS test or native performance measurement was performed for this
merge. Last full-daemon live evidence remains `VALIDATION-v29.md` and does not
establish live behavior for the refreshed main. Broad Cilium CI was not run.

Use [SUPPORT.md](SUPPORT.md) as the current support contract. The AL2023 exact
kernel guard remains unchanged. Do not bypass it or infer EKS compatibility from
chart rendering. Rebuild agent and operator images from the published source
commit; use its packaged chart and complete intended override file together.

Do not assume compatible restoration across changed binaries merely because the
merge compiles. Runtime restoration validates program tags, map bindings and
history. Drain selected endpoints before an incompatible upgrade/disable; retain
pins/history and follow the runbook rather than deleting state to force startup.
