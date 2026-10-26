# v18 validation — 26 October 2026

## Scope and source

The implementation checkpoint is `de831993a7`, based on local v17
`72d76a7a572b175d66844633774397a31db7baaa`. That baseline's tree
`79acba64e18532d253d4197a3f8be9577eb848c0` matches published v17
`7268d416e9f477ebde34e92703ea36df8a8fbb00` exactly. The upstream integration
baseline remains `b28d80469415d4494a1a9d86ae18ee2de8a5146b`.

This milestone adds an isolated SYN-cookie capability probe, live tests, an
optional VM artifact argument and strict compilation coverage. It does not
change production agent/BPF code, the thirteen-map/six-tracing-hook graph, map
schema, journal, routing or configuration API. Production cookie handshakes
remain fail-closed. See [SYNCOOKIES.md](SYNCOOKIES.md) for the kernel handoff,
the guarantees exercised and the peer-binding work still required.

## Final executed evidence

| Kernel | Result | Child-probe test | Existing cookie-rejection test | Complete VM runner |
| --- | --- | --- | --- | --- |
| Ubuntu 6.8.0-31 generic | PASS | 2.48s | 6.53s | 25.445s |
| Canonical 6.12.0-061200 generic | PASS | 2.47s | 6.53s | 27.215s |

Both are disconnected amd64 QEMU/TCG guests, not native performance runs. Both
reports have no errors, failures or skipped tests and end with `VTEP_VM_EXIT=0`.
Each live suite records eighteen PASS entries: the capability root, two family
groups, ten individual capability cases, the existing rejection root and its
four synthetic/actual-policy family combinations. Conntrack and core Cilium BPF
regressions also pass in each guest.

The new required cases cover normal handshake control, real forced-cookie
child creation before the passive callback, invalid raw ACK rejection, an
unselected namespace with the identical tuple, and exact tuple reuse while
holding the old server FD. All five run through both listener families. Actual
kernel `SyncookiesRecv` and `SyncookiesFailed` counters are checked; a synthetic
successful callback alone cannot satisfy these tests. Accepted FDs must expose
the same nonzero kernel cookie as their own socket-storage record.

Strict BPF compilation, unchanged `conntrack.h`, sampled flag-off executable
section comparisons, Go vet for the live package, all four Python evidence/
preflight tests and `git diff --check` pass. The live binary uses Go 1.27.3 and
`CGO_ENABLED=0 go test -c ./contrib/vtep-return-affinity/live`.

The initial probe was rejected by the verifier for direct TCP-field access
beyond the `sock` return type and a separately reloaded nullable sockops pointer.
The final probe uses checked CO-RE kernel reads for those TCP fields and retains
a checked local sockops pointer. Initial failed reports are preserved separately
and do not count as passing evidence.

## Reproduction

Use the trusted kernel/module, QEMU, BusyBox and BPF test-runner arguments from
README.md. Build the objects with `run_spike.py` and the static live test binary.
In `kernel_matrix.py`, supply both kernel cases and these additional VM arguments:

```sh
--live-tests /opt/vtep-build/livetest \
--cookie-object /opt/vtep-build/syncookie_child.o \
--handoff-object /opt/vtep-build/socket_handoff.o \
--core-object /opt/vtep-build/socket_core.o \
--live-test-run '^TestPrivileged(SYNcookieChildEvidence|SYNcookiesFailClosed)$' \
--require-test TestPrivilegedSYNcookieChildEvidence \
--require-test TestPrivilegedSYNcookiesFailClosed
```

For both `mapped=false` and `mapped=true`, also require each exact subtest below
under `TestPrivilegedSYNcookieChildEvidence/mapped=<value>/`:

- `normal_handshake_has_no_cookie_marker`
- `validated_child_precedes_passive_callback`
- `invalid_cookie_ACK_has_no_child_evidence`
- `unselected_namespace_with_identical_tuple_is_ignored`
- `tuple_reuse_keeps_old_FD_evidence`

Use separate output directories for reruns. An absent or skipped required test
fails the evidence report. Missing BTF, an unreviewed hook prototype, verifier
refusal or missing probe artifact must not be reported as capability support.

## What remains

The probe establishes a candidate kernel-validated child handoff. It has no
original SYN-ticket/outer-peer binding and cannot authorize return routing.
Cross-peer sequence collisions/replay, SYN-ACK proof collection, bounded
admission and retention, ACK-with-data, retransmissions, expiry, pressure and
managed agent lifecycle must be implemented and tested before cookie forwarding
can be enabled. Forced cookies do not establish real backlog-overflow behavior
or denial-of-service capacity.

No Kubernetes deployment, new full-agent rollout/reboot test, native benchmark
or broader kernel-support claim is added here. v17 evidence remains unchanged.
The experiment is default off and not production ready.

## Evidence fingerprints

Only fingerprints are committed; the raw logs, JSON reports and executable
artifacts remain outside the source tree.

- `v18-cookie-verifier-fixed/linux68.log` — SHA-256 `1fcb8551ec5ec35848eaa6938d08e00d87a59d3881eec7e3e4a7e2e1ae0cc63f`
- `v18-cookie-verifier-fixed/linux68.json` — SHA-256 `5b28c03fa2027c3f4e7c3d6cd8fe32254e53445e5c12b197a64462d6073f2e3c`
- `v18-cookie-verifier-fixed/linux612.log` — SHA-256 `caa897592e46fb0a82474a12ec209ff0035ae3458bca68d186f58fa8845e639e`
- `v18-cookie-verifier-fixed/linux612.json` — SHA-256 `54a0a620992e56e147a6baa14ef90cf7893897b0bbde869fff4a8a5771226957`
- `v18-cookie-verifier-fixed/matrix.json` — SHA-256 `0454403b36c0e2d7d9c1c519f239b072a95ed8dd7a7144c40c00044713d673c7`
- `build-v18/syncookie_child.o` — SHA-256 `395c4209179d4d636ead63d427f43561acfdabb1b2cc77bcf1491b0f4545784b`
- `build-v18/livetest` — SHA-256 `813ba01de415d91fb52c5bfd9d0d7563c11ad660a785feb0d92858944e42163c`
