# Offline journal compatibility export

This utility addresses the v2-to-v1 journal format barrier between the v9+
prototype and the v8 **feature-aware prototype**. It does not make rollback to
an arbitrary released/unmodified Cilium binary safe. An actual older-agent
process rollout and Kubernetes downgrade remain untested.

## Preconditions and order

1. Drain the selected pods through CNI deletion and remove their old veths and
   namespace bindings, following the main README.
2. Start the current feature-aware agent with experimental return affinity
   disabled. Wait for successful startup: it must verify drain, remove the
   custom pins and durably publish the disabled state.
3. Stop that agent and prevent its service/DaemonSet from immediately restarting
   it during the offline conversion. The converter shares the agent's file
   lease and refuses a running controller, even when the feature is disabled.
4. Check the export, then apply it using the exact journal and pins paths from
   the stopped agent's configuration. Keep the target prototype's experimental
   flag disabled when testing its startup.

Build the utility from this checkout:

```sh
go build -o /tmp/vtep-journal-downgrade ./contrib/vtep-return-affinity/downgrade
```

First check (the journal remains unchanged):

```sh
/tmp/vtep-journal-downgrade \
  --journal /var/run/cilium/state/vtep-return-affinity.json \
  --pins /sys/fs/bpf/cilium/vtep-return-affinity
```

If validation succeeds, apply with the same paths:

```sh
/tmp/vtep-journal-downgrade \
  --journal /var/run/cilium/state/vtep-return-affinity.json \
  --pins /sys/fs/bpf/cilium/vtep-return-affinity --apply
```

These are default-path examples, not automatic discovery. Custom state/BPF roots
must be reflected in both arguments. The utility never stops Cilium, drains
pods, unmounts namespaces or removes pins. Do not point it at another agent's
state. Re-running an already successful export is idempotent.

## Preserved guarantees

The converter requires the current boot ID, a durable disabled/uninitialized
journal, no surviving custom pins and no uncompacted full memberships. Unknown
fields, invalid history, symlink journal files and overlapping agent leases are
rejected. Conversion uses the existing fsync/rename/parent-fsync publication.

Every compacted retired cookie becomes an explicit version-1 retired membership.
The placeholder uses `lo` with interface index zero and an empty namespace path;
zero can never match a live interface. These records describe already drained
incarnations and keep the v8 prototype's old-cookie checks effective. They do
not claim a live namespace or allow it to reopen. Unrelated cookie gaps remain
unblocked. Boot ID, disabled state and peer configuration are preserved.

Expansion is limited to 8,192 cookies, not 8,192 ranges. A very long compacted
range is refused before expansion and nothing is discarded. Keep the current
binary, or complete a coordinated drain/disable and reboot reconciliation with
that binary before retrying. Never truncate the ranges or delete the journal.

The current agent can read the exported v1 history again and migrate it back to
v2. Reimport retains the old-cookie rejection. Startup now acquires the lease
before reading authoritative journal contents, preventing stale snapshots from
an earlier controller/exporter from overwriting newer history.

## Validation scope

Focused tests cover check-only behavior, lossless/idempotent export, uint64
boundaries, malformed/future input, the expansion cap, pins/active-state/lease
refusal and lease-before-read ordering. The isolated controller test exercises
export/reimport and the unchanged physical-drain predicate against the kernel.
These establish journal/controller compatibility; they are not evidence of an
actual older daemon, reboot or Kubernetes rollout.

## TIME-WAIT map schema 2

v14 adds six TIME-WAIT maps to the versioned map bundle and six pinned tracing
links. This is independent of journal format 2. No in-place migration or tracing
code replacement is supported: drain selected pods and disable using the old
binary before installing schema 2 or returning to the previous prototype. The
offline journal converter does not migrate live maps, hooks or connections.
