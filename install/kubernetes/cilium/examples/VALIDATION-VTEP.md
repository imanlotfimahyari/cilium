<!-- This file was not reviewed by a human before submission -->
# Chart packaging checkpoint — 4 November 2026

Runtime base: `e797812a195bb19647182a385f1100bfdcdb4694` on
`experimental/vtep-return-affinity-lab-v29`. These changes add installation
examples and documentation; agent, datapath, map schemas and hooks are unchanged.

- Helm 3.16.3 lint passes for defaults and the EKS example, targeting Kubernetes 1.35.0.
- Seven Helm regression tests pass, including 19 unsupported-setting subcases,
  default-manifest comparison with v28, schema/legacy flag checks, explicit
  agent/operator images and direct API environment, EKS networking settings,
  enabled/disabled experimental flag rendering and packaged full values/examples.
- helm-docs 1.11.0 reproduces the committed README without drift.
- Make dry run resolves both documented release-image targets, including the
  generic operator variant, requested image names, linux/amd64 and --load.
- git diff --check passes.

Docker is unavailable in this workspace. No OCI image was built, pushed or
executed here. No EKS deployment or AL2023 kernel validation was performed.
The feature remains off by default; the current AL2023 runtime restriction
is unchanged. Earlier full-daemon VM evidence is recorded in
`contrib/vtep-return-affinity/VALIDATION-v29.md` in the repository.
