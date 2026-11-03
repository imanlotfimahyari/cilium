# v26 fresh-cookie periodic agent GC — 3 November 2026

Implementation `efccb8e9c7`, following [v25](VALIDATION-v25.md). This is a
test-only checkpoint: the agent, BPF sources, map schema, hooks, configuration
and default-off behavior are unchanged. It closes the specific v25 evidence
gap where the expiry assertion could encounter an already-empty ledger after
a long restart/recovery.

## Executed evidence

| Focused actual-agent check | Linux 6.8.0-31 | Linux 6.12.0-061200 |
| --- | --- | --- |
| Two fresh, consumed kernel-cookie records observed before waiting | PASS | PASS |
| Original records unchanged and present before actual expiry | PASS | PASS |
| Running agent collects both records after expiry | PASS | PASS |
| Observed removal after expiry, in kernel jiffies | +5,174 / +5,176 | +922 / +924 |
| Four established socket owners and TCP flows survive the wait/collection | PASS | PASS |
| All 18 map IDs, eight tracing-link IDs and both pod-hook IDs unchanged | PASS | PASS |
| New real cookie handshake and correct-peer forwarding after collection | PASS | PASS |
| Focused fresh-record/collection assertion | PASS, 68.88s | PASS, 72.84s |
| Complete actual-agent test including startup/compilation | PASS, 469.68s | PASS, 465.62s |
| Complete runner including existing conntrack/core regressions | PASS, 500.848s | PASS, 496.240s |

Both final reports pass the required root and nested test, with no failed or
skipped tests, report errors or unsuccessful VM exits. Go test compilation,
Go vet and `git diff --check` pass. The two disconnected amd64 QEMU/TCG guests
ran concurrently, each with two vCPUs and 2,048 MiB. Durations and observed
collection offsets are correctness evidence under emulation, not native
performance measurements or a production latency guarantee.

## Why this is a fresh periodic-GC proof

`TestPrivilegedRealAgentFreshCookieGC` starts the actual v25 Cilium agent and
creates its selected endpoint before the application listener. It forces Linux
SYN cookies, establishes two baseline flows, then creates two additional real
handshakes through different configured peers. Kernel cookie-receive and agent
child-binding counters must increase.

The helper opens the canonical ledger **read-only**. It must find both exact
new records, matching namespace/generation, ports, peer, consumed state and
the reviewed two-epoch expiry formula. Each must still have at least 50,000
jiffies remaining when first observed; an empty/already-expired ledger fails.

One unattached test program samples actual kernel jiffies. The test neither
invokes a collector nor changes clocks, records or expiry fields. It checks
that each record remains identical before expiry, then requires the running
agent to delete it within three normal collection intervals after expiry.
Every ten seconds it checks all four socket owners and transfers real TCP data;
it repeats those checks after deletion and verifies the canonical graph IDs.
A final fresh handshake proves continued admission through the correct peer.
The same live agent process must remain running throughout the observation.

The full cookie lifecycle fixture now uses this stronger helper too. This
checkpoint runs the focused scenario only; v25's complete restart/rollback,
replacement and drain/disable suite was **not rerun**. Its historical report
remains tied to the earlier test binary and explicitly described expiry scope.

## Artifacts and reproduction

| Artifact | SHA-256 |
| --- | --- |
| Reused, unchanged v25 agent | `4e315b3974abcd7547d01658169881f546c170516ec617ebe6d275f28d4c2359` |
| Unchanged v25 BPF source-tree fingerprint | `efeeb69af88caceec59ff8b4c7f1bc4236dfbb8667467c1a0fe515ff692d5140` |
| New live test binary | `39608339966e554fef93054c2262dce368a9dcde75a5d72f8ba5b5f690deca97` |

Build the live test with the Go version required by `go.mod`:

```sh
CGO_ENABLED=0 go test -c -o "$BUILD/livetest" ./contrib/vtep-return-affinity/live
```

Use v25's explicit trusted kernel/modules/config, agent executable, BPF source,
Clang, BusyBox, iptables runtime and BPF runner with `privileged_vm.py`.
Select `^TestPrivilegedRealAgentFreshCookieGC$`, omit all previous-agent options,
and add `--cookie-core-object` pointing to `socket_cookie_core.o` built by
`run_spike.py`. Only its read-only clock sampler is loaded by this check.
Require both `TestPrivilegedRealAgentFreshCookieGC` and
`TestPrivilegedRealAgentFreshCookieGC/fresh_records_expire_via_periodic_agent_GC`.
The executed outer timeout was 1,000 seconds. The full cookie lifecycle fixture
also now requires this clock object because it shares the strengthened helper.

## Remaining limits

This closes a validation gap without extending forwarding support. The v25
contract and restrictions remain: reviewed IPv4/VXLAN/veth/TCX lab kernels,
external configured peers, no-policy allocator in the daemon fixture and the
existing experimental option off by default. Kubernetes with normal identities
and NetworkPolicy, native sustained-load/resource measurements, broader kernel
coverage and production rollout validation remain outstanding. No tenant
isolation, native-cookie, Services/NAT, encryption, Geneve, IPv6, TFO or general
socketless-reply support is added. Complete authoritative ownership loss still
requires affected connections to reconnect.
