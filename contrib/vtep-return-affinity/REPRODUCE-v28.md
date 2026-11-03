<!-- This file was not reviewed by a human before submission -->

# Reproducing v28 focused validation

Run from this source checkout with the Go version in go.mod and Clang 21.1.8.
Supply trusted vendor kernels/modules/configs matching the hashes in
VALIDATION-v28.md, static BusyBox, QEMU 8.2 and their shared dependencies.
`${WORKSPACE}` below is a placeholder to replace in each JSON argument;
these commands do not download dependencies or create a Kubernetes cluster.

```sh
# With go and clang installed/on PATH:
go test -p 2 ./pkg/datapath/vtep/returnaffinity ./contrib/vtep-return-affinity/k8s/probe
go test -race -p 2 ./pkg/datapath/vtep/returnaffinity ./contrib/vtep-return-affinity/k8s/probe
go vet -p 2 ./pkg/datapath/vtep/returnaffinity ./contrib/vtep-return-affinity/k8s/probe
go test -p 2 ./pkg/datapath/loader -run '^(TestWrap|TestVTEPAffinityTemplateIsolation|TestObjectCache|TestObjectCacheReuse|TestObjectCacheEndpointTemplateReady)$'
python3 -m unittest discover -s contrib/vtep-return-affinity/k8s -v
python3 -m unittest discover -s contrib/vtep-return-affinity -p 'test_*.py'
python3 contrib/vtep-return-affinity/run_spike.py --clang clang --output "$WORKSPACE/validation/build"
CGO_ENABLED=0 go test -p 2 -c -o "$WORKSPACE/validation/build/agenttest" ./pkg/datapath/vtep/returnaffinity
CGO_ENABLED=0 go test -p 2 -c -o "$WORKSPACE/validation/build/livetest" ./contrib/vtep-return-affinity/live
CGO_ENABLED=0 go test -p 2 -c -o "$WORKSPACE/validation/build/bpftest" ./bpf/tests/bpftest
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$WORKSPACE/validation/build/affinity-probe" ./contrib/vtep-return-affinity/k8s/probe
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$WORKSPACE/validation/build/vtep-capacity" ./contrib/vtep-return-affinity/capacity
git diff --check
```

The two exact runner argument lists, with required coverage and no silent skips:

```json
{
  "linux68": [
    "python3",
    "contrib/vtep-return-affinity/privileged_vm.py",
    "--qemu-root",
    "${WORKSPACE}/tools/vm-root",
    "--busybox",
    "${WORKSPACE}/tools/vm-root/usr/bin/busybox",
    "--kernel",
    "${WORKSPACE}/tools/vm-root/boot/vmlinuz-6.8.0-31-generic",
    "--module-root",
    "${WORKSPACE}/tools/vm-root/lib/modules/6.8.0-31-generic",
    "--runner",
    "${WORKSPACE}/validation/build/bpftest",
    "--bpf-dir",
    "${WORKSPACE}/validation/build/vm-bpf",
    "--agent-tests",
    "${WORKSPACE}/validation/build/agenttest",
    "--agent-test-run",
    "^(TestPrivilegedPreQueueOnlyStampsSYNACKs|TestPrivilegedTracingRestartPreservesCompleteGraph|TestPrivilegedTracingRejectsPartialOrChangedState|TestPrivilegedTracingPinLossRevokesReadiness|TestPrivilegedCookieIngressDamageRefusesRestore|TestPrivilegedRuntimeMapDamageRevokesReadiness|TestPrivilegedCookieIngressPinLossRevokesReadiness|TestPrivilegedControllerRestartUnderPressure|TestPrivilegedCapacityReadOnlyAndPressure)$",
    "--runtime-object",
    "${WORKSPACE}/validation/build/bpf_vtep_return.o",
    "--live-tests",
    "${WORKSPACE}/validation/build/livetest",
    "--live-test-run",
    "^(TestPrivilegedCookieVXLANForwarding|TestPrivilegedCookieIngressPolicyRejects|TestPrivilegedCookieCollision|TestPrivilegedCookieACKPressureAndData|TestPrivilegedCookieConsumedReplay|TestPrivilegedCookieLedgerPressureAndRealExpiry|TestPrivilegedCookiePacketPressure|TestPrivilegedCookieExistingTupleCannotBorrowPeer|TestPrivilegedSYNcookiePeerLedger)$",
    "--cookie-peer-object",
    "${WORKSPACE}/validation/build/cookie_peer_ledger.o",
    "--cookie-core-object",
    "${WORKSPACE}/validation/build/socket_cookie_core.o",
    "--timewait-packet-object",
    "${WORKSPACE}/validation/build/timewait_packet.o",
    "--memory",
    "1536M",
    "--cpus",
    "2",
    "--timeout",
    "1000",
    "--log",
    "${WORKSPACE}/validation/kernel/linux68.log",
    "--report",
    "${WORKSPACE}/validation/kernel/linux68.json",
    "--require-test",
    "TestPrivilegedPreQueueOnlyStampsSYNACKs",
    "--require-test",
    "TestPrivilegedTracingRestartPreservesCompleteGraph",
    "--require-test",
    "TestPrivilegedTracingRejectsPartialOrChangedState",
    "--require-test",
    "TestPrivilegedTracingPinLossRevokesReadiness",
    "--require-test",
    "TestPrivilegedCookieIngressDamageRefusesRestore",
    "--require-test",
    "TestPrivilegedRuntimeMapDamageRevokesReadiness",
    "--require-test",
    "TestPrivilegedCookieIngressPinLossRevokesReadiness",
    "--require-test",
    "TestPrivilegedControllerRestartUnderPressure",
    "--require-test",
    "TestPrivilegedCookieVXLANForwarding",
    "--require-test",
    "TestPrivilegedCookieIngressPolicyRejects",
    "--require-test",
    "TestPrivilegedCookieCollision",
    "--require-test",
    "TestPrivilegedCookieACKPressureAndData",
    "--require-test",
    "TestPrivilegedCookieConsumedReplay",
    "--require-test",
    "TestPrivilegedCookieLedgerPressureAndRealExpiry",
    "--require-test",
    "TestPrivilegedCookiePacketPressure",
    "--require-test",
    "TestPrivilegedCookieExistingTupleCannotBorrowPeer",
    "--require-test",
    "TestPrivilegedSYNcookiePeerLedger",
    "--cookie-runtime-object",
    "${WORKSPACE}/validation/build/cookie_runtime.o",
    "--require-test",
    "TestPrivilegedCapacityReadOnlyAndPressure"
  ],
  "linux612": [
    "python3",
    "contrib/vtep-return-affinity/privileged_vm.py",
    "--qemu-root",
    "${WORKSPACE}/tools/vm-root",
    "--busybox",
    "${WORKSPACE}/tools/vm-root/usr/bin/busybox",
    "--kernel",
    "${WORKSPACE}/tools/kernel612/boot/vmlinuz-6.12.0-061200-generic",
    "--module-root",
    "${WORKSPACE}/tools/kernel612/lib/modules/6.12.0-061200-generic",
    "--runner",
    "${WORKSPACE}/validation/build/bpftest",
    "--bpf-dir",
    "${WORKSPACE}/validation/build/vm-bpf",
    "--agent-tests",
    "${WORKSPACE}/validation/build/agenttest",
    "--agent-test-run",
    "^(TestPrivilegedPreQueueOnlyStampsSYNACKs|TestPrivilegedTracingRestartPreservesCompleteGraph|TestPrivilegedTracingRejectsPartialOrChangedState|TestPrivilegedTracingPinLossRevokesReadiness|TestPrivilegedCookieIngressDamageRefusesRestore|TestPrivilegedRuntimeMapDamageRevokesReadiness|TestPrivilegedCookieIngressPinLossRevokesReadiness|TestPrivilegedControllerRestartUnderPressure|TestPrivilegedCapacityReadOnlyAndPressure)$",
    "--runtime-object",
    "${WORKSPACE}/validation/build/bpf_vtep_return.o",
    "--live-tests",
    "${WORKSPACE}/validation/build/livetest",
    "--live-test-run",
    "^(TestPrivilegedCookieVXLANForwarding|TestPrivilegedCookieIngressPolicyRejects|TestPrivilegedCookieCollision|TestPrivilegedCookieACKPressureAndData|TestPrivilegedCookieConsumedReplay|TestPrivilegedCookieLedgerPressureAndRealExpiry|TestPrivilegedCookiePacketPressure|TestPrivilegedCookieExistingTupleCannotBorrowPeer|TestPrivilegedSYNcookiePeerLedger)$",
    "--cookie-peer-object",
    "${WORKSPACE}/validation/build/cookie_peer_ledger.o",
    "--cookie-core-object",
    "${WORKSPACE}/validation/build/socket_cookie_core.o",
    "--timewait-packet-object",
    "${WORKSPACE}/validation/build/timewait_packet.o",
    "--memory",
    "1536M",
    "--cpus",
    "2",
    "--timeout",
    "1000",
    "--log",
    "${WORKSPACE}/validation/kernel/linux612.log",
    "--report",
    "${WORKSPACE}/validation/kernel/linux612.json",
    "--require-test",
    "TestPrivilegedPreQueueOnlyStampsSYNACKs",
    "--require-test",
    "TestPrivilegedTracingRestartPreservesCompleteGraph",
    "--require-test",
    "TestPrivilegedTracingRejectsPartialOrChangedState",
    "--require-test",
    "TestPrivilegedTracingPinLossRevokesReadiness",
    "--require-test",
    "TestPrivilegedCookieIngressDamageRefusesRestore",
    "--require-test",
    "TestPrivilegedRuntimeMapDamageRevokesReadiness",
    "--require-test",
    "TestPrivilegedCookieIngressPinLossRevokesReadiness",
    "--require-test",
    "TestPrivilegedControllerRestartUnderPressure",
    "--require-test",
    "TestPrivilegedCookieVXLANForwarding",
    "--require-test",
    "TestPrivilegedCookieIngressPolicyRejects",
    "--require-test",
    "TestPrivilegedCookieCollision",
    "--require-test",
    "TestPrivilegedCookieACKPressureAndData",
    "--require-test",
    "TestPrivilegedCookieConsumedReplay",
    "--require-test",
    "TestPrivilegedCookieLedgerPressureAndRealExpiry",
    "--require-test",
    "TestPrivilegedCookiePacketPressure",
    "--require-test",
    "TestPrivilegedCookieExistingTupleCannotBorrowPeer",
    "--require-test",
    "TestPrivilegedSYNcookiePeerLedger",
    "--cookie-runtime-object",
    "${WORKSPACE}/validation/build/cookie_runtime.o",
    "--require-test",
    "TestPrivilegedCapacityReadOnlyAndPressure"
  ]
}
```

Actual Kubernetes execution is separate; see [the lab instructions](k8s/README.md).
