<!-- This file was not reviewed by a human before submission -->

# Reproducing the v29 lab checkpoint

Use the recorded source, toolchain, vendor kernels/config/modules and libraries
from VALIDATION-v29.md. Run from the checkout root. `${WORKSPACE}` in the JSON
argument lists is a placeholder to replace. No dependencies, cluster or paid
resources are provisioned by these commands.

```sh
# Go 1.27.3 and the chart's pinned generator versions on PATH:
CGO_ENABLED=0 GOMEMLIMIT=3GiB go build -p 2 -trimpath -ldflags='-s -w' -o "$WORKSPACE/validation/build/cilium-agent" ./daemon
# Rebuild the unchanged test binaries, or verify reused v28 artifact hashes:
CGO_ENABLED=0 go test -p 2 -c -o "$WORKSPACE/v28-validation/build/livetest" ./contrib/vtep-return-affinity/live
CGO_ENABLED=0 go test -p 2 -c -o "$WORKSPACE/v28-validation/build/bpftest" ./bpf/tests/bpftest
python3 contrib/vtep-return-affinity/run_spike.py --clang clang --output "$WORKSPACE/v28-validation/build"
VTEP_HELM_BINARY=helm python3 -m unittest discover -s contrib/vtep-return-affinity -p 'test_*.py' -v
python3 -m unittest discover -s contrib/vtep-return-affinity/k8s -v
helm lint install/kubernetes/cilium
helm-docs --chart-search-root=install/kubernetes/cilium
git diff --check
```

Values were checked with the existing Makefile/yq recipe. The complete schema
was regenerated in a temporary chart using `helm-schema -c CHART
--skip-auto-generation title,description,required,default,additionalProperties`
and compared excluding only the review-only root `$comment`. Preserve the
required human-review markers in the fork's generated files.

The runtime libraries/iptables plugins must be staged for the VM; current agent
runs require no previous binary. The exact supplied coverage arguments are:

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
    "${WORKSPACE}/v28-validation/build/bpftest",
    "--bpf-dir",
    "${WORKSPACE}/v28-validation/build/vm-bpf",
    "--live-tests",
    "${WORKSPACE}/v28-validation/build/livetest",
    "--live-test-run",
    "^TestPrivileged(CookieLoaderPrunedReplacements|RealAgentCookieProcess)$",
    "--full-agent",
    "${WORKSPACE}/validation/build/cilium-agent",
    "--source-bpf",
    "${WORKSPACE}/cilium-v29/bpf",
    "--clang",
    "${WORKSPACE}/tools/vm-root/usr/bin/clang-21",
    "--netfilter-root",
    "${WORKSPACE}/tools/netfilter-root",
    "--cookie-core-object",
    "${WORKSPACE}/v28-validation/build/socket_cookie_core.o",
    "--timewait-packet-object",
    "${WORKSPACE}/v28-validation/build/timewait_packet.o",
    "--memory",
    "3072M",
    "--cpus",
    "2",
    "--timeout",
    "3600",
    "--log",
    "${WORKSPACE}/validation/full-agent/linux68.log",
    "--report",
    "${WORKSPACE}/validation/full-agent/linux68.json",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess",
    "--require-test",
    "TestPrivilegedCookieLoaderPrunedReplacements",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/periodic_GC_preserves_TIMEWAIT_owner",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/kernel_cookie_children_have_exact_owners",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/native_owner_bypasses_overlapping_VTEP_prefix",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/periodic_GC_expires_cookie_tombstones_preserving_owners",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/retirement_prevents_legacy_fallthrough",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/pod_replacement_with_reused_address_and_interface_name",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/disabled_agent_refuses_live_membership",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/coordinated_drain_then_disabled_agent",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/SIGKILL_restart_preserves_live_connections"
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
    "${WORKSPACE}/v28-validation/build/bpftest",
    "--bpf-dir",
    "${WORKSPACE}/v28-validation/build/vm-bpf",
    "--live-tests",
    "${WORKSPACE}/v28-validation/build/livetest",
    "--live-test-run",
    "^TestPrivileged(CookieLoaderPrunedReplacements|RealAgentCookieProcess)$",
    "--full-agent",
    "${WORKSPACE}/validation/build/cilium-agent",
    "--source-bpf",
    "${WORKSPACE}/cilium-v29/bpf",
    "--clang",
    "${WORKSPACE}/tools/vm-root/usr/bin/clang-21",
    "--netfilter-root",
    "${WORKSPACE}/tools/netfilter-root",
    "--cookie-core-object",
    "${WORKSPACE}/v28-validation/build/socket_cookie_core.o",
    "--timewait-packet-object",
    "${WORKSPACE}/v28-validation/build/timewait_packet.o",
    "--memory",
    "3072M",
    "--cpus",
    "2",
    "--timeout",
    "3600",
    "--log",
    "${WORKSPACE}/validation/full-agent/linux612.log",
    "--report",
    "${WORKSPACE}/validation/full-agent/linux612.json",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess",
    "--require-test",
    "TestPrivilegedCookieLoaderPrunedReplacements",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/periodic_GC_preserves_TIMEWAIT_owner",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/kernel_cookie_children_have_exact_owners",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/native_owner_bypasses_overlapping_VTEP_prefix",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/periodic_GC_expires_cookie_tombstones_preserving_owners",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/retirement_prevents_legacy_fallthrough",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/pod_replacement_with_reused_address_and_interface_name",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/disabled_agent_refuses_live_membership",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/coordinated_drain_then_disabled_agent",
    "--require-test",
    "TestPrivilegedRealAgentCookieProcess/SIGKILL_restart_preserves_live_connections"
  ]
}
```

Real cluster/image execution remains separate; see the lab guide. TCG results
are not native performance measurements.
