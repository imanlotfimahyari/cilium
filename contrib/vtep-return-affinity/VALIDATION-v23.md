# v23 candidate SYN-cookie peer-binding ledger — 3 November 2026

Implementation checkpoint: `47fdea7b116f2d6a9e8ee53da012b4af24ffed70`,
with host privilege-gating follow-up `32a8262b19`.
Parent v22 report/source is local `2cc8ba5efc`, published
`7645832051c9768b1dc13f8c0f4a4314bd11d7bf`, matching tree
`e710f766b35d64a70120a6eae419debc7f954679`.

**Production SYN-cookie forwarding remains unsupported.** This is an isolated
BPF candidate ledger with a synthetic-evidence test adapter, not trusted VXLAN
SYN/ACK capture, kernel-child publication or agent-managed installation.
There is no production map, hook, flag, schema or forwarding behavior change.

## Executed evidence

| Validated milestone | Linux 6.8 | Linux 6.12 |
| --- | --- | --- |
| v22 actual-daemon restart under live admission pressure | PASS, 542.44s | PASS, 511.56s |
| v23 candidate ledger, eleven required cases | PASS, 1.47s | PASS, 1.47s |
| v23 full VM runner with conntrack/core regressions | PASS, 16.493s | PASS, 16.53s |
| v23 failures / skips | 0 / 0 | 0 / 0 |

The first row references the separate [v22 full-agent report](VALIDATION-v22.md).
All final ledger cases execute on disconnected amd64 QEMU/TCG guests with two
vCPUs and 1,536 MiB. Race workers lock their OS threads and pin to CPUs 0/1;
a one-CPU run is refused. These are kernel-BPF correctness tests, not native
performance, real cookie generation or live SYN-flood measurements. Final
reports require the root and all eleven children, with no failed/skipped tests.
Earlier one-CPU and smaller two-CPU runs retain their separate scope; the table
uses the final strengthened source only.

Strict compilation, Go vet and all four host Python evidence/preflight tests
pass. The production runtime, core and TIME-WAIT-core BPF objects remain
byte-identical to tested v20 objects. Sampled flag-off sections and conntrack.h
remain identical to the original comparison baseline.

## Candidate rules

A non-evicting eight-entry test hash indexes namespace, generation, exact IPv4
TCP tuple and both initial sequence numbers. Its first peer, issue epoch and
expiry are immutable. State transitions use kernel atomic compare-and-swap.
Inputs must eventually come from trusted post-policy SYN/ACK and actual kernel
SYN-ACK/validated-child evidence; the current adapter deliberately supplies
synthetic inputs and never forwards packets or publishes an owner.

- Same-peer retransmission within the original issue epoch can reuse an issued
  record. A different peer, or identical evidence reissued in another epoch,
  quarantines the issued record instead of overwriting its peer. Already
  consumed records never become issued again.
- Wrong-peer ACK consumption is rejected without burning the rightful peer's
  issued record. One successful consumer burns the evidence; publication failure
  must not reset it. Existing socket ownership is separate and is never retargeted.
- Issued, consumed and quarantined records remain until the full modeled cookie
  acceptance window ends. GC cannot use ordinary short handshake TTLs. An expired
  record must be collected before a new incarnation can be inserted.
- Before deletion, one collector atomically claims the exact expired value as
  COLLECTING. Other collectors/issuers cannot revive or delete that incarnation;
  concurrent stale collectors must not delete a newly inserted value of the key.
- Capacity pressure rejects new issuance and preserves every surviving record,
  including consumed tombstones. Namespace/generation, tuple and both ISNs must
  all match. Invalid identity, zero peer and overflowing clock inputs refuse.

The reviewed Linux 6.8 and 6.12 sources use `MAX_SYNCOOKIE_AGE=2` and
`TCP_SYNCOOKIE_PERIOD=60*HZ`, based on `get_jiffies_64()`. The candidate computes
expiry at the end of the issue epoch's two-period window. The test adapter uses
virtual jiffies and a 100-tick period to test exact boundaries without sleeping
for minutes. A future trusted loader must establish the reviewed kernel/HZ and
use actual kernel jiffies; live clock/suspend behavior is not established here.

Primary references:

- https://github.com/torvalds/linux/blob/v6.8/include/net/tcp.h
- https://github.com/torvalds/linux/blob/v6.12/include/net/tcp.h
- https://github.com/torvalds/linux/blob/v6.8/net/ipv4/syncookies.c
- https://github.com/torvalds/linux/blob/v6.12/net/ipv4/syncookies.c

## Executed adversarial cases

1. Invalid identity and clock overflow refuse.
2. Same-peer retransmission; wrong-peer replay; exactly one consume; no reset.
3. Cross-peer collision quarantines both candidates and preserves the first peer.
4. Cross-epoch cookie collision refuses even for the same peer.
5. Exact expiry boundary, mandatory GC and new-incarnation recovery.
6. Namespace, generation, both addresses/ports and both ISNs are exact.
7. Full capacity preserves live/consumed records and resumes after safe GC.
8. Sixteen concurrent consumers have one winner.
9. Concurrent competing peers never produce a last-writer-wins binding.
10. Collision racing consumption never assigns the competing peer.
11. Concurrent collectors/reissuers preserve the fresh incarnation, over 32 rounds.

## Reproduce

Build `cookie_peer_ledger.o` with run_spike.py and a static live-test binary from
this checkpoint. Use the ordinary VM artifact arguments, with:

```sh
--live-tests /opt/vtep-build/livetest \
--live-test-run '^TestPrivilegedSYNcookiePeerLedger$' \
--cookie-peer-object /opt/vtep-build/cookie_peer_ledger.o \
--cpus 2 --memory 1536M
```

Require `TestPrivilegedSYNcookiePeerLedger` and all eleven exact child names
from cookie_peer_ledger_test.go using repeated `--require-test`. The report now
records vCPU count and memory. A requested one-CPU ledger run fails rather than
claiming multicore validation. No hooks are attached for this ledger test.

## Required before enabling cookie forwarding

1. Capture the policy-approved SYN and actual kernel-generated SYN-ACK as one
   trusted issuance event; reject emission if recording fails or is ambiguous.
2. Carry trusted ingress peer/ACK evidence through ordinary policy into the
   exact kernel-validated child. Consume and publish before application replies;
   never infer a peer from a tuple or trust packet-supplied metadata.
3. Test real VXLAN cookie handshakes, retransmission/loss, invalid and cross-peer
   ACKs, ACK-with-data, tuple reuse, pressure and actual clock boundaries, for
   both listener families. v18 establishes child-hook capability only.
4. Integrate new state/hooks with map schema, compatibility, restore readiness,
   GC, namespace retirement and drain/disable. The current agent does not load
   or preserve this candidate ledger.
5. Measure tombstone/admission memory and SYN-flood availability. Retaining
   state for the cookie window gives up part of the kernel's stateless-cookie
   benefit; full capacity intentionally rejects new handshakes.

Real Kubernetes identities/NetworkPolicy, native performance and broader rollout
remain separate gates. The main prototype stays experimental and default-off.

## Evidence fingerprints

Only hashes are committed; raw logs, binaries and downloaded kernel sources are
outside the source tree.

- `v23-cookie-ledger-final3/linux68.log` — `e9f994510b98098e3d1f40a204bacdb369b3c8c3363b91d645cd151ea0470fe8`
- `v23-cookie-ledger-final3/linux68.json` — `7c5514c99a246f94f9295302919ea7dbd73017356b7202425e6b7c85a42ac166`
- `v23-cookie-ledger-final3/linux612.log` — `761e40dc5ae757253257dfd87d4dbdf73396ae74fa12ff11f04c772cf1d16950`
- `v23-cookie-ledger-final3/linux612.json` — `346b5d3829b158508df28450dc1f04967dcc22a8d853e2247b24dfdfa310e6ab`
- `v23-cookie-ledger-final3/matrix.json` — `ce344faae7f84f57f51b510e7ca4d5f92c3b450661df5d48112bee8f4e5f9e85`
- `build-v23/livetest-final3` — `561f889bc66f897e6c6c82cf505f72e0d43ce534bbe4c84451badcef41a4e3f7`
- `build-v23/cookie_peer_ledger.o` — `5309f9c9736fe47d1939db3a5ba50a6bd764cefe9df2f6c237f543d5afeee86b`
- `kernel-cookie-review/tcp-6.8.h` — `bb119c0de108ee1eb482987aa608cc663b81bf6137fef95382a8d73e6b3f44bf`
- `kernel-cookie-review/tcp-6.12.h` — `cdf696125e9484f7a5579eb0fa0841acb92f39ba6cd2dab219670e837fcf1b8c`
- `kernel-cookie-review/syncookies-6.8.c` — `c27aa61c1786be01b7512bceedddf86900481f19c54bc3e74f4f5b5b931a814d`
- `kernel-cookie-review/syncookies-6.12.c` — `d66e0ebd761066a513c5abaa18316421fe3305cd78cb3f0f81922b8296c34ce4`
