<!-- This file was not reviewed by a human before submission -->

# Recovered v27: fresh validation — 3 November 2026

**PASS: fresh focused host, packet/controller and full-agent lifecycle checks
on both reviewed kernels.** This remains an experimental lab checkpoint.

## Recovery and publication

The previous local v27 checkout, binaries and raw logs were unavailable.
This checkpoint reconstructs the implementation from published v26 and upstream,
and executes fresh checks. Historical validation claims are not substituted
for newly executed evidence.

| Checkpoint | Identity |
| --- | --- |
| Preserved published v26 | `4b12f57a00e92a652b50a4eeffb137752a7be027` |
| Preserved v26 tree | `79c83c094d4359e49c09fdc6d967deebd44b2df9` |
| Upstream main, all 250 missing commits integrated | `2e94a0a3e3bddb960f6e403b61afa70da10ba561` |
| Recovered merge | `691819609b` |
| Recovered production tree, equal to the prior recorded v27 tree | `50ed154ad05d02e312b037b35677e8668fe9ec68` |
| Restored fresh-tuple fixture and frozen build source | `bd5f35ae81d646d22dcc1dc2d66e7027749ba408` |
| Source-only tree, all 119 files independently fetched and verified | `b344b50b41f693e50d1efe9ed991b10efccde04e` |
| Source-only GitHub commit | `722f8a8f3d43f161f4f08ae310b4173c163e3e51` |
| Durable candidate bundle GitHub commit | `08eaf8a80e499f7de226b39a085f6467a3e55548` |

Source branch: `experimental/vtep-return-affinity-main-v27`.
Archive branch: `backup/vtep-return-affinity-v27`, under `recovery-checkpoints/v27`.
The candidate archive was fetched back, verified byte-for-byte and checked with
`git bundle verify` before longer validation began. Its SHA-256 is
`200a1b959a8e9ffe17dfae18e6a63f0af447a21f02f016233b91d301984e2302`.

The restored changes preserve upstream `HAVE_ENCAP` and the selected-TCP
restriction against legacy VTEP prefix fallback. Return encapsulation and
fixture metadata use upstream `world_ipv4_id()` after removal of the old macro
alias. Each cross-version cookie probe uses a distinct tuple, so TIME-WAIT reuse
cannot bypass its fresh cookie-child binding assertion.

Map schema 3 retains 18 maps, eight tracing hooks and both pod-side TCX hooks.
No feature or configuration API is added by this recovery.

## Fresh completed checks

- Go 1.27.3, Clang 21.1.8; both agent versions build statically from clean commits.
- All 13 selected BPF objects compile with strict warnings.
- `conntrack.h` is byte-identical to the upstream snapshot.
- Sampled flag-off overlay and endpoint-policy-drop executable sections match upstream.
- Controller units, focused loader/cache tests, configuration/status tests: PASS.
- Controller race tests and focused Go vet: PASS.
- Python evidence/preflight and offline Kubernetes-harness units: PASS.
  The latter are not Kubernetes deployment tests.

| Fresh kernel matrix, including root/subtest entries | Linux 6.8.0-31 | Linux 6.12.0-061200 |
| --- | --- | --- |
| Existing conntrack suite | 8 PASS | 8 PASS |
| Core forwarding/policy suite | 17 PASS | 17 PASS |
| Selected controller restore/pressure/damage checks | 38 PASS | 38 PASS |
| Cookie packet and adversarial ledger checks | 30 PASS | 30 PASS |
| Complete runner duration | 336.877s | 337.693s |

Both final matrix reports have no failed or skipped tests, report errors, or
unsuccessful VM exits. The checks include both IPv4 listener forms, exact child
ownership, collision/replay/admission pressure and actual kernel-window expiry
while established flows survive. Each disconnected QEMU/TCG guest uses two
vCPUs and 1,536 MiB. These durations are emulated correctness evidence.

## Actual-agent lifecycle gate

Status: **PASS on both kernels**. The sequence uses the rebuilt v26 binary
with its own BPF sources → recovered v27 → rebuilt v26. Both final reports
contain the root, loader regression and all ten nested lifecycle entries:
12 required entries, no failed/skipped tests, report errors, or unsuccessful
VM exits. Existing conntrack/core regressions pass as well.

| Actual-agent check | Linux 6.8.0-31 | Linux 6.12.0-061200 |
| --- | --- | --- |
| Live upgrade to recovered v27 | PASS | PASS |
| Live rollback to rebuilt v26 | PASS | PASS |
| Connection ownership and 18 map/eight tracing-link/two pod-hook identities preserved | PASS | PASS |
| Fresh cookie child binding while the agent is down and after restore | PASS | PASS |
| TIME-WAIT ownership and fresh-record periodic cookie GC | PASS | PASS |
| Endpoint retirement and reused-address/interface pod replacement | PASS | PASS |
| Unsafe-disable refusal and recovery | PASS | PASS |
| Coordinated drain, full hook/pin removal and ordinary TCP with feature off | PASS | PASS |
| Actual-loader pruned-map replacement regression | PASS | PASS |
| Real-agent root duration | 1,789.08s | 1,679.66s |
| Complete runner duration | 1,834.488s | 1,724.569s |

The final agent guests use two vCPUs and 3,072 MiB each. These are disconnected
QEMU/TCG correctness tests, not native performance benchmarks. Cross-version
claims concern these two rebuilt prototype artifacts and this recorded
toolchain, not arbitrary releases or the unavailable original binaries.

## Reconstructed harness corrections

The first command reconstruction selected the eight-entry pressure fixture as
the production controller runtime and omitted the separate cookie-runtime
argument. Strict map compatibility correctly refused the small fixture, and
required-coverage checks caught the skipped packet tests. Final commands use
`--runtime-object bpf_vtep_return.o` and separately
`--cookie-runtime-object cookie_runtime.o`. Source and assertions are unchanged.

The first full-agent archive failed during initramfs unpacking, before Cilium
started. Debug-only sections were then removed from copied Go executables;
every allocated ELF section was verified identical, including code, data and
Go build information. The final guests also receive more memory headroom.
The corrected guests unpack, start Cilium and pass the entire lifecycle suite.
The passing packet/controller
runs used the original test executables; the full-agent runs use their
runtime-identical copies. Failed attempts remain separate from final evidence.

## Frozen full-agent artifacts

| Artifact | SHA-256 |
| --- | --- |
| Recovered v27 agent | `a6a22c1bd471db8cac9567a13ff49dfd42c6d98da00d9ec055a2dcdaf838176e` |
| Preserved v26 rebuilt agent | `50bcd491b8ecbdbd1d885730f2cc375608974fd98ee1b1819bad50a85e868f1c` |
| Live test executable | `3718066c0e9e134ba9841a008e19a5f44a7f890cd6b842b7cc6a01cf1472eadc` |
| BPF test runner | `8a5e95c1c4f973fb9fc1fdee90cf7ca7be24d74ba9b472472080f048677ce93e` |

Both restored vendor kernel binaries match the previously recorded hashes:

- Linux 6.8: `529a76e832d2b92041ab3f7355b70b096263aa971dbace1ffca7bf23d0497f4d`.
- Linux 6.12: `144439e925a02129b01c74a37a73466494cac3876d65bc3850e3b9f1b260d44c`.

## Remaining limits

Real Kubernetes/CNI operation with normal identities and combined policy
workflows remains deferred. Actual-agent fixtures use the no-policy allocator;
policy/conntrack checks are separate packet-fixture evidence. Native performance,
broader kernels, node reboot/rolling deployment and unrelated older-binary
rollback remain unvalidated. The original lost executables were not recovered;
live pins created by different builders/kernel combinations are not covered
by these rebuilt-artifact transition tests. Existing unsupported paths and drain requirements
remain. These lab results do not establish production readiness or acceptance.

Human review is pending. Commits disclose AIL:4 and modified files carry the
required review marker. A human must review and honestly confirm the influence
score before upstream submission; live-cluster evidence is also still required.
