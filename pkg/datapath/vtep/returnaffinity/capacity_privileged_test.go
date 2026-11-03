// This file was not reviewed by a human before submission
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Real map syscalls in the disconnected disposable guest. This tests map
// pressure/diagnostics, not packet producers, GC or live-connection survival.
func TestPrivilegedCapacityReadOnlyAndPressure(t *testing.T) {
	if os.Getenv("VTEP_RETURN_ISOLATED_VM") != "1" {
		t.Skip("requires isolated VM")
	}
	dir := filepath.Dir(privilegedPinPath(t))
	maps := freshSocketMapsWithCapacity(t, SocketCapacity)
	bundle, err := PinSocketBundle(dir, SocketCapacity, maps)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	inspect := func(t *testing.T) CapacityReport {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		report := InspectCapacity(ctx, dir)
		if !report.Complete || report.Atomic || len(report.Maps) != 18 {
			t.Fatalf("incomplete real-map report: %+v", report)
		}
		for _, row := range report.Maps {
			if row.ID != uint32(socketMapID(t, bundle.maps[row.Name])) {
				t.Fatal("inspection replaced a canonical map")
			}
			if (row.Name == SocketOwnerMap || row.Name == CookieChildMap) && (row.ObservedEntries != nil || row.AtCapacity || row.Note == "") {
				t.Fatal("socket-local occupancy was guessed")
			}
			if (row.Name == SocketOwnerMap || row.Name == CookieChildMap) && (row.ObservedHeadroom != nil || row.Pressure != "unknown") {
				t.Fatal("socket storage was reported as available admission capacity")
			}
		}
		return report
	}
	t.Run("empty_bundle_and_aggregate_counters", func(t *testing.T) {
		stats := struct{ Scopes, Packets, Stamps, Pressure uint64 }{11, 12, 13, 14}
		if err := maps[TimewaitStatsMap].Update(uint32(0), stats, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		cookie := struct{ Issued, Bound, Rejected, Pressure uint64 }{21, 22, 23, 24}
		if err := maps[CookieStatsMap].Update(uint32(0), cookie, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		r := inspect(t)
		if r.Counters["packet_or_proof_insert_failures"] != 14 || r.Counters["proof_stamps"] != 13 || r.Counters["cookie_issued"] != 21 || r.Counters["cookie_bound"] != 22 || r.Counters["cookie_rejected"] != 23 || r.Counters["cookie_insert_failures"] != 24 {
			t.Fatal("counter layout/meaning changed")
		}
		for _, row := range r.Maps {
			if row.ObservedEntries != nil && *row.ObservedEntries != 0 {
				t.Fatal("fresh hash map was not empty")
			}
		}
	})
	for _, spec := range socketMapSpecs(SocketCapacity) {
		if spec.Name != SocketAdmitMap && spec.Name != SocketRequestMap && spec.Name != TimewaitOwnerMap && spec.Name != TimewaitPacketMap && spec.Name != TimewaitProofMap && spec.Name != CookieLedgerMap && spec.Name != CookieACKMap && spec.Name != CookiePacketMap {
			continue
		}
		t.Run(spec.Name, func(t *testing.T) {
			m := maps[spec.Name]
			key, value := make([]byte, spec.KeySize), make([]byte, spec.ValueSize)
			for i := uint32(0); i < spec.MaxEntries; i++ {
				binary.NativeEndian.PutUint32(key, i)
				value[0] = byte(i%251 + 1)
				if err := m.Update(key, value, ebpf.UpdateNoExist); err != nil {
					t.Fatal(err)
				}
			}
			binary.NativeEndian.PutUint32(key, spec.MaxEntries)
			if err := m.Update(key, value, ebpf.UpdateNoExist); !errors.Is(err, unix.E2BIG) && !errors.Is(err, unix.ENOSPC) {
				t.Fatalf("full hash did not reject new insertion: %v", err)
			}
			for i := uint32(0); i < spec.MaxEntries; i++ {
				binary.NativeEndian.PutUint32(key, i)
				if err := m.Lookup(key, &value); err != nil || value[0] != byte(i%251+1) {
					t.Fatalf("pressure evicted or changed entry %d: %v", i, err)
				}
			}
			r := inspect(t)
			found := false
			for _, row := range r.Maps {
				if row.Name == spec.Name {
					found = row.AtCapacity && row.ObservedEntries != nil && *row.ObservedEntries == spec.MaxEntries &&
						row.ObservedHeadroom != nil && *row.ObservedHeadroom == 0 && row.Pressure == "full_at_sample"
					if spec.Name == SocketAdmitMap && row.Stage != "syn_admission" || spec.Name == SocketRequestMap && row.Stage != "request_binding" {
						t.Fatal("pressure attributed to the wrong stage")
					}
				}
			}
			if !found {
				t.Fatal("full map was not reported at capacity")
			}
			readOnly, err := openSocketBundle(dir, SocketCapacity, &ebpf.LoadPinOptions{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer readOnly.Close()
			value[0] = 0
			if err := readOnly.maps[spec.Name].Update(key, value, ebpf.UpdateExist); !errors.Is(err, unix.EPERM) {
				t.Fatalf("kernel did not refuse update on read-only descriptor: %v", err)
			}
			if err := readOnly.maps[spec.Name].Delete(key); !errors.Is(err, unix.EPERM) {
				t.Fatalf("kernel did not refuse delete on read-only descriptor: %v", err)
			}
			if err := m.Lookup(key, &value); err != nil || value[0] != byte((spec.MaxEntries-1)%251+1) {
				t.Fatal("read-only attempts mutated original entry")
			}
			// Only the writable test fixture frees a slot. The diagnostic never
			// deletes state or decides which ownership record may be collected.
			if err := m.Delete(key); err != nil {
				t.Fatal(err)
			}
			r = inspect(t)
			for _, row := range r.Maps {
				if row.Name == spec.Name && (row.AtCapacity || row.ObservedEntries == nil || *row.ObservedEntries != spec.MaxEntries-1 ||
					row.ObservedHeadroom == nil || *row.ObservedHeadroom != 1 || row.Pressure != "available_at_sample") {
					t.Fatal("released capacity was not observed")
				}
			}
			binary.NativeEndian.PutUint32(key, spec.MaxEntries)
			if err := m.Update(key, value, ebpf.UpdateNoExist); err != nil {
				t.Fatal("insertion did not resume after a slot was freed", err)
			}
			// Remove disposable fixture entries before the next independent map.
			for i := uint32(0); i <= spec.MaxEntries; i++ {
				binary.NativeEndian.PutUint32(key, i)
				if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatal(err)
				}
			}
		})
	}
	t.Run("missing_and_replaced_pin_refuse", func(t *testing.T) {
		path := filepath.Join(dir, SocketAdmitMap)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if r := InspectCapacity(context.Background(), dir); r.Complete || len(r.Errors) == 0 {
			t.Fatal("missing pin reported complete")
		}
		replacement, err := ebpf.NewMap(socketMapSpecs(SocketCapacity)[2])
		if err != nil {
			t.Fatal(err)
		}
		defer replacement.Close()
		if err := replacement.Pin(path); err != nil {
			t.Fatal(err)
		}
		if err := bundle.checkPinsWithOptions(dir, &ebpf.LoadPinOptions{ReadOnly: true}); err == nil {
			t.Fatal("held canonical identity accepted a replacement pin")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := maps[SocketAdmitMap].Pin(path); err != nil {
			t.Fatal(err)
		}
		inspect(t)
	})
}
