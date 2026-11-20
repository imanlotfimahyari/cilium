<!-- This file was not reviewed by a human before submission -->

# Exact AL2023 kernel port

Target: `6.12.115-140.210.amzn2023.x86_64` on x86_64.
This report covers a disconnected QEMU/TCG lab using the exact vendor kernel
and modules. It does not claim EKS, other AL2023 builds, ARM64 or native
performance support.

## Timing and attach review

The Amazon Linux release
[2023.12.20261112](https://docs.aws.amazon.com/linux/al2023/release-notes/relnotes-2023.12.20261112.html)
includes `kernel6.12-6.12.115-140.210.amzn2023`. The following artifact
digests were checked against the release repository metadata:

| Artifact | SHA-256 |
| --- | --- |
| x86_64 binary RPM | `7df1ca49b2ad5adc9cb5803e1aa70cdd27c9f0face4e91ebcf451e0d5b7b069a` |
| Source RPM | `f6625800b8e081f0e9018aeff129db8dc5231db7d70353bce29a897b94bd2f5e` |
| Booted vmlinuz | `dfa337a3c268f8da0aa633c144c9edfc061804309b4124a0fdc2650febf0c153` |
| Packaged kernel config | `0a766e6d70232330ae9f543d0ecc8a7a86a5613b0fb49df217ee22fcbe67a79a` |

The packaged x86_64 config sets `CONFIG_HZ=100`, BPF JIT, BTF and SYN
cookies. The source uses the same 60-second period (60 × HZ) and validates
the current and previous epochs. The Amazon patch touching the cookie-child
function changes an error path; the loader still checks the cookie and TIME-WAIT
function signatures against the running kernel's BTF.

The program encodes the selected period as an instruction constant:
6,000 jiffies for this build, 60,000 jiffies for the two reviewed Ubuntu builds.
Only one SYN-ACK producer loads, under the existing logical hook name; no
pin or map schema was added. The installed package config is checked through
`/lib/modules/<release>/config` when `/proc/config.gz` is absent. The
VM staged this packaged config in the module tree rather than under `/boot`.

## Completed checks

| Check | Result |
| --- | --- |
| Exact AL2023 kernel | Conntrack and core BPF, controller link restoration, forced-cookie VXLAN (IPv4 and IPv4-mapped IPv6 listeners) passed. |
| Ubuntu `6.8.0-31-generic` | Same focused controller, conntrack/BPF and live VXLAN checks passed. |
| Ubuntu `6.12.0-061200-generic` | Same focused controller, conntrack/BPF and live VXLAN checks passed. |
| Local | Go unit/race/vet checks, 13 strict BPF builds, sampled flag-off comparisons, four harness tests, eight Helm tests and Helm lint (default and EKS values) passed. |

The live packet fixture now loads its shared TC programs with no expected
direction and attaches each to its specific TCX link. Linux 6.12.115 rejects
mixed expected attach types in the same program array. This fixture change
matches the existing endpoint loader; it changes neither production TCX hook
direction nor policy.

The new producer has a distinct program tag. The Ubuntu producer's tag also
changed during recompilation. Do not assume that upgrading or rolling back
with existing tracing pins is supported. Drain and disable with the compatible
agent before transitioning between these source versions.

## Full daemon

The first full-daemon run hit the VM's 420-second deadline during drain/disable.
The focused rerun with a longer deadline **passed**, with no skips:

- Real forced-cookie traffic and accurate socket owners, including native
  traffic on an overlapping prefix.
- Agent SIGKILL/restart with live flows, TIME-WAIT ownership and tracing links
  preserved.
- Real cookie expiry and periodic collection: two freshly issued records
  observed and collected, four established flows preserved, new admission passed.
- Endpoint retirement, replacement with reused addresses/interface names,
  refusal to disable with live membership, and coordinated drain/disable.
- Cookie map replacement after loader pruning.

The fixture uses the real Cilium daemon with a standalone no-policy allocator.
The separate datapath tests exercise policy/conntrack; neither substitutes for
a Kubernetes cluster with normal identity allocation and CNI execution.

## Deployment boundary

Use matching agent/operator images and the default-off Helm chart. Start in
a disposable EKS deployment and check the kernel on every node that would
run an enabled agent. Validate actual CNI, identities/policy, VXLAN peers
and lifecycle before wider use. Other kernel releases continue to fail
closed. No Services/NAT compatibility or live EKS deployment is established
by the VM results.
