# v16 validation — 26 October 2026

Upstream baseline remains `b28d80469415d4494a1a9d86ae18ee2de8a5146b`.
Recovered source baseline is published `9ea88478`, whose tree exactly matches
the original v15 local checkpoint `b3231c22`.

## Implemented changes

- Reject future/ambiguous journal fields, duplicate keys including case aliases,
  noncanonical namespace keys, trailing JSON, non-regular files and inputs above
  64 MiB. Refusal preserves the original history. The agent and offline exporter
  now share this decoder; the 8,192-record admission bound is unchanged.
- Select the reviewed Linux 6.8 or 6.12 TIME-WAIT publication function using BTF.
  Validate every tracing argument read through raw indexes, including the exact
  packet-constructor return slot. Preserve all existing pinned target, program
  tag and map-ID checks. Still thirteen maps and six tracing hooks; journal and
  map schemas stay at version 2. No BPF forwarding instructions were changed.
- Exercise real TFO-option SYN payload rejection and socketless RST, ACK and
  data rejection through actual Cilium policy/CT fixtures, for both listener
  families. Check that established ownership and application traffic survive.
- Exercise real qdisc loss followed by retransmission through a configured
  reordering qdisc after CT deletion. Verify every byte and socket owner across
  two VXLAN peers and native traffic. This is a small correctness workload,
  not a long-duration stress test or proof of every possible packet ordering.
- Exercise 256 KiB transfers per peer with default TSO/GSO enabled and with
  TSO/GSO/GRO explicitly disabled and queried. GRO was off in the default
  fixture. This does not validate hardware NIC offloads or GRO-enabled paths.
- Expand forced SYN-cookie rejection to both listener families and both the
  synthetic and actual Cilium fixtures. These tests prove rejection under real
  kernel cookie generation, not SYN-cookie forwarding support.
- Add machine-readable kernel-matrix and two-boot recovery runners. A zero exit
  with no matched tests, missing required tests or skipped required subtests is
  rejected. Optional skips remain explicit in the report.

## Final executed evidence

All guests are disconnected QEMU/TCG on amd64. Supplied kernels are Ubuntu's
6.8.0-31 generic and Canonical's 6.12.0-061200 generic mainline build. The latter
packages were downloaded from the official mainline archive and checked against
its published SHA-256 values. This is lab coverage, not a supported-kernel claim.

| Check | Result | Scope |
| --- | --- | --- |
| Linux 6.8.0-31 controller/packet matrix | PASS, 203.985s | All controller lifecycle/fault tests, conntrack/core BPF tests and 14 required live top-level tests |
| Linux 6.12.0-061200 controller/packet matrix | PASS, 206.710s | All controller lifecycle/fault tests, conntrack/core BPF tests and 14 required live top-level tests |
| Final raw socketless RST/ACK/data tests | PASS on both kernels | Both listener families; no borrowed owner; existing data still works |
| Real two-boot controller recovery | PASS on Linux 6.12 | Persistent disposable ext4 image, distinct boot ID, vanished bpffs, enabled refusal, explicit disabled recovery and fresh 13-map/6-hook graph |
| Unit/race/vet and loader/endpoint/status tests | PASS | Compiler supplied on PATH; default-off loader regression retained |
| Strict BPF compilation and sampled flag-off comparison | PASS | Unchanged conntrack.h and sampled executable sections |
| Python validation evidence tests and Kubernetes harness unit tests | PASS | No actual Kubernetes deployment |
| Native network performance | BLOCKED | Explicit KVM request rejected: /dev/kvm unavailable; no emulation-to-native extrapolation |

The matrix deliberately skips the disk-dependent reboot test; the separate
reboot runner requires it to pass in both actual VM boots. The matrix includes
TIME-WAIT ownership/destruction, queued tuple reuse, lost-proof collection,
actual policy/CT ordering, invalid/expired/generation-mismatched proofs and
one-time duplicate rejection. It also restores the exact managed graph across
controller restart on both kernels. The first Linux 6.12 attempt failed on the
renamed publication function; its failure was retained and the ABI fix was then
retested, including the complete final matrix.

The two-boot test instantiates the controller with actual hooks/maps. It does
not run a Kubernetes node or either full daemon binary across that reboot.
The v15 full-daemon result remains historical evidence; that binary lifecycle
was not rerun for v16 or extended to Linux 6.12.

A host-only recovery microbenchmark at 8,192 sparse retired ranges measured
45.5 ms/decode and about 1.91 MB allocated per operation on this shared runner.
This is startup parsing cost, not packet-path performance or a production SLA.

## Reproduce and extend

Use the static binaries/object build commands in README.md. Supply trusted
artifact paths to privileged_vm.py; use --require-test for each mandatory exact
Go test name, and --report for its JSON evidence. For the final packet matrix:

```sh
python3 contrib/vtep-return-affinity/kernel_matrix.py \
  --config kernels.json --output /tmp/vtep-matrix -- \
  <the privileged_vm.py artifact and coverage arguments>
```

The configuration contains no executable code:

```json
{"kernels": [
  {"name": "linux68", "kernel": "/opt/vtep-kernels/6.8/vmlinuz", "modules": "/opt/vtep-kernels/6.8/modules"},
  {"name": "linux612", "kernel": "/opt/vtep-kernels/6.12/vmlinuz", "modules": "/opt/vtep-kernels/6.12/modules"}
]}
```

The executed live selector was
`^TestPrivileged(MappedIPv4Handoff|SYNcookiesFailClosed|UnsupportedTCPDoesNotBorrowOwner|CoreLossRecovery|CoreOffloadModes|TIMEWAIT.*)$`.
Supply handoff/core/TIME-WAIT owner/packet/core objects and the runtime object,
plus controller and live test binaries. Kernel cases run sequentially, and a
failure or missing kernel is retained rather than counted as coverage.

For two-boot recovery, supply kernel/modules, QEMU, BusyBox, BPF runner/objects,
controller test binary and runtime object after the separator:

```sh
python3 contrib/vtep-return-affinity/reboot_validate.py \
  --output /tmp/vtep-reboot -- \
  <the privileged_vm.py trusted artifact arguments>
```

This creates and formats a new disposable image internally; it never formats
an existing operator disk. The prepare/verify selectors and required test are
set by the wrapper. Keep the output directory for both phase reports and logs.

## Remaining gates

1. SYN-cookie forwarding needs a separately reviewed kernel-validated child
   handoff, bounded state and adversarial collision/replay/pressure tests.
   TFO payloads and unauthoritative socketless replies deliberately fail closed.
2. Six tracing hooks and the skb/MAC metadata handoff still need architectural
   review and shared maintenance agreement. No upstream acceptance is implied.
3. Native A/B CPU, memory, throughput and tail-latency benchmarks; long-running
   admission/connection churn; NIC/GRO combinations and a wider kernel matrix.
4. Actual full-agent cross-version upgrade and older-binary rollback; full node
   reboot with workloads; rolling multi-node operation. The offline exporter
   and controller tests are not substitutes for those rollout tests.
5. Real Kubernetes/CNI, normal identity allocation and NetworkPolicy validation
   remain deferred as agreed. Scope exclusions in README.md still apply.

Complete loss of authoritative peer state still requires affected connections
to reconnect. The feature remains experimental and default off.

## Evidence fingerprints

Only fingerprints are committed; the execution logs are retained separately.

- `vtep-v16-matrix/linux68.log` — SHA-256 `013e2dc6503079c673da4dd24145a7467ff77c046c5dcc7ecd1f7c9ff419cbf4`
- `vtep-v16-matrix/linux612.log` — SHA-256 `2daff0c6bf61952b2512781f9ffbb25ee2bfea6bf23d2712064227097e7503f9`
- `vtep-v16-matrix/matrix.json` — SHA-256 `afd66ca3942f3bb54bcecd5e752323f59be595c866fd126ae289210de97d2f68`
- `vtep-v16-socketless/matrix.json` — SHA-256 `bb70acd4fd4d05ac3a903c117462e002b712e56581cd70e91f1b38c4b0384e4b`
- `vtep-v16-reboot-final/prepare.log` — SHA-256 `4ad01c02a2a737dc64baab13b04716ec0ee35a2b2a99e6b02b6c53699a849bce`
- `vtep-v16-reboot-final/verify.log` — SHA-256 `6e99f74f297e33715bd791f9d184869be8dda63e9797d7dd033d94036497ff29`
- `vtep-v16-reboot-final/reboot.json` — SHA-256 `882ff057703cff9fd51ed6802486331b62e6d7931931f56f8245bcd5b1c57aba`
- `vtep-v16-native-capability.json` — SHA-256 `3dc6a6f90d990bb5e37bca5edf8d79a5c977faccaa48de4f98929138c357127e`
