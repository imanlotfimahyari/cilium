// This file was not reviewed by a human before submission
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

// CapacityReport is a read-only, non-atomic diagnostic. It is neither a
// readiness verdict nor evidence that draining or fallback is safe. Only map
// metadata, entry counts and aggregate counters leave the diagnostic reader.
type CapacityReport struct {
	Complete    bool              `json:"complete"`
	Atomic      bool              `json:"atomic"`
	Started     time.Time         `json:"started"`
	Finished    time.Time         `json:"finished"`
	Maps        []CapacityMap     `json:"maps"`
	Counters    map[string]uint64 `json:"counters,omitempty"`
	Errors      []string          `json:"errors,omitempty"`
	Limitations []string          `json:"limitations"`
}

type CapacityMap struct {
	Name             string  `json:"name"`
	ID               uint32  `json:"id"`
	Kind             string  `json:"kind"`
	MaxEntries       uint32  `json:"max_entries"`
	ObservedEntries  *uint32 `json:"observed_entries,omitempty"`
	AtCapacity       bool    `json:"at_capacity"`
	Note             string  `json:"note,omitempty"`
	Stage            string  `json:"stage"`
	ObservedHeadroom *uint32 `json:"observed_headroom,omitempty"`
	Pressure         string  `json:"pressure"`
}

// Unknown/failed enumeration never becomes apparent free capacity. These are
// instantaneous observations, not insertion-failure counts or reservations.
func describeCapacity(entry *CapacityMap) {
	entry.Stage = "runtime"
	switch entry.Name {
	case "cilium_vtep_admit4":
		entry.Stage = "syn_admission"
	case "cilium_vtep_req4":
		entry.Stage = "request_binding"
	case CookieLedgerMap, CookieACKMap, CookieChildMap, CookiePacketMap:
		entry.Stage = "cookie_handoff"
	case TimewaitOwnerMap, TimewaitPacketMap, TimewaitProofMap:
		entry.Stage = "timewait_handoff"
	}
	entry.Pressure = "unknown"
	if entry.ObservedEntries == nil || *entry.ObservedEntries > entry.MaxEntries {
		return
	}
	headroom := entry.MaxEntries - *entry.ObservedEntries
	entry.ObservedHeadroom = &headroom
	entry.Pressure = "available_at_sample"
	if headroom == 0 {
		entry.Pressure = "full_at_sample"
	}
}

type capacityKeys interface{ NextKeyBytes(any) ([]byte, error) }

// Under churn, NextKey may revisit the start when the previous key disappears.
// Bound both work and memory; never label a partial or cyclic walk as empty or
// full. No keys/values are emitted, including in error messages.
func countCapacityKeys(ctx context.Context, m capacityKeys, maximum uint32) (uint32, error) {
	seen := make(map[string]struct{})
	var previous any // Initial BPF_MAP_GET_NEXT_KEY requires a genuinely nil cursor.
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		key, err := m.NextKeyBytes(previous)
		if err != nil {
			return 0, fmt.Errorf("entry enumeration failed")
		}
		if key == nil {
			return uint32(len(seen)), nil
		}
		if _, exists := seen[string(key)]; exists {
			return 0, fmt.Errorf("entry enumeration revisited a key; retry after churn subsides")
		}
		if uint32(len(seen)) >= maximum {
			return 0, fmt.Errorf("entry enumeration exceeded the validated map capacity")
		}
		seen[string(key)] = struct{}{}
		previous = key
	}
}

// InspectCapacity opens only the existing validated v3 bundle. It never creates,
// updates, deletes, pins, unpins, collects or replaces anything. Keep this scan
// out of packet processing, readiness and GC: it is explicitly operator-invoked.
func InspectCapacity(ctx context.Context, mapDirectory string) (report CapacityReport) {
	report.Started = time.Now().UTC()
	report.Limitations = []string{
		"non-atomic occupancy; observed headroom is not reserved capacity",
		"admission and request binding have no dedicated insertion-failure counters",
		"socket-local storage occupancy and total socket memory are unknown",
		"map inspection does not validate hooks, readiness or safe rollback",
	}
	defer func() { report.Finished = time.Now().UTC() }()
	readOnly := &ebpf.LoadPinOptions{ReadOnly: true}
	bundle, err := openSocketBundle(mapDirectory, SocketCapacity, readOnly)
	if err != nil {
		// Detailed restore errors may include operator paths. Keep the JSON
		// diagnostic aggregate-only and never report missing maps as empty.
		report.Errors = append(report.Errors, "cannot open complete compatible map bundle; verify pins, permissions and schema with the agent")
		return report
	}
	defer bundle.Close()
	for _, spec := range socketMapSpecs(SocketCapacity) {
		if ctx.Err() != nil {
			report.Errors = append(report.Errors, "diagnostic deadline or cancellation reached")
			return report
		}
		m := bundle.maps[spec.Name]
		entry := CapacityMap{Name: spec.Name, Kind: spec.Type.String(), MaxEntries: spec.MaxEntries}
		info, err := m.Info()
		if err != nil {
			report.Errors = append(report.Errors, spec.Name+": cannot inspect map identity")
			continue
		}
		id, ok := info.ID()
		if !ok {
			report.Errors = append(report.Errors, spec.Name+": map identity unavailable")
			continue
		}
		entry.ID = uint32(id)
		switch spec.Type {
		case ebpf.Hash:
			count, err := countCapacityKeys(ctx, m, spec.MaxEntries)
			if err != nil {
				report.Errors = append(report.Errors, spec.Name+": "+err.Error())
			} else {
				entry.ObservedEntries = &count
				entry.AtCapacity = count == spec.MaxEntries
			}
		case ebpf.SkStorage:
			entry.Note = "socket-local storage is not enumerable here; max_entries=0 is not zero occupancy or a total connection limit"
		default:
			entry.Note = "fixed runtime/control slots; not admission occupancy"
		}
		describeCapacity(&entry)
		report.Maps = append(report.Maps, entry)
	}
	// Counter names retain their actual meaning. Rejected TIME-WAIT transfers
	// have several causes and must not be relabelled as map-full drops.
	var life struct{ Transferred, Rejected, Freed uint64 }
	var packet struct{ Scopes, Packets, Stamps, Pressure uint64 }
	if err := errors.Join(bundle.maps[TimewaitLifeMap].Lookup(uint32(0), &life), bundle.maps[TimewaitStatsMap].Lookup(uint32(0), &packet)); err != nil {
		report.Errors = append(report.Errors, "cannot read aggregate TIME-WAIT counters")
	} else {
		report.Counters = map[string]uint64{"timewait_transferred": life.Transferred, "timewait_rejected": life.Rejected, "timewait_freed": life.Freed,
			"packet_scopes": packet.Scopes, "packets": packet.Packets, "proof_stamps": packet.Stamps, "packet_or_proof_insert_failures": packet.Pressure}
	}
	var cookie struct{ Issued, Bound, Rejected, Pressure uint64 }
	if err := bundle.maps[CookieStatsMap].Lookup(uint32(0), &cookie); err != nil {
		report.Errors = append(report.Errors, "cannot read aggregate cookie counters")
	} else {
		if report.Counters == nil {
			report.Counters = make(map[string]uint64)
		}
		report.Counters["cookie_issued"] = cookie.Issued
		report.Counters["cookie_bound"] = cookie.Bound
		report.Counters["cookie_rejected"] = cookie.Rejected
		report.Counters["cookie_insert_failures"] = cookie.Pressure
	}
	if err := bundle.checkPinsWithOptions(mapDirectory, readOnly); err != nil {
		report.Errors = append(report.Errors, "canonical pins or schema changed during inspection; counts are not trustworthy")
	}
	report.Complete = len(report.Errors) == 0
	return report
}
