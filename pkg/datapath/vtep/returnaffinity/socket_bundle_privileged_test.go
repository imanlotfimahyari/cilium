// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func freshSocketMaps(t *testing.T) map[string]*ebpf.Map {
	t.Helper()
	maps := make(map[string]*ebpf.Map)
	for _, spec := range socketMapSpecs(8) {
		if spec.Name == SocketSchemaMap {
			continue
		}
		if spec.Type == ebpf.SkStorage {
			spec.Key = &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
			u64 := &btf.Int{Name: "u64", Size: 8}
			spec.Value = &btf.Struct{Name: "test_owner", Size: 32, Members: []btf.Member{
				{Name: "namespace", Type: u64}, {Name: "generation", Type: u64, Offset: 64},
				{Name: "cookie", Type: u64, Offset: 128}, {Name: "peer_origin", Type: u64, Offset: 192},
			}}
		}
		m, err := ebpf.NewMap(spec)
		if err != nil {
			t.Fatalf("create %s: %v", spec.Name, err)
		}
		maps[spec.Name] = m
		t.Cleanup(func() { m.Close() })
	}
	return maps
}

func socketMapID(t *testing.T, m *ebpf.Map) ebpf.MapID {
	t.Helper()
	info, err := m.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("kernel supplied no map ID")
	}
	return id
}

func TestPrivilegedSocketBundleWarmRestoreAndRollback(t *testing.T) {
	dir := filepath.Dir(privilegedPinPath(t))
	maps := freshSocketMaps(t)
	first, err := PinSocketBundle(dir, 8, maps)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.RollbackPreflight(); !errors.Is(err, ErrSocketRollbackRequiresQuiescence) {
		t.Fatalf("empty maps must not be taken as proof of socket quiescence: %v", err)
	}
	control := struct {
		Generation, TTL uint64
		Phase, Reserved uint32
	}{1, 30000000000, 1, 0}
	if err := maps[SocketControlMap].Update(uint64(10), control, ebpf.UpdateNoExist); err != nil {
		t.Fatal(err)
	}
	if err := maps[SocketNonceMap].Update(uint64(10), uint64(123), ebpf.UpdateNoExist); err != nil {
		t.Fatal(err)
	}
	ids := make(map[string]ebpf.MapID)
	for name, m := range maps {
		ids[name] = socketMapID(t, m)
		m.Close()
	}
	first.Close()
	restored, err := OpenSocketBundle(dir, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	for name, id := range ids {
		if socketMapID(t, restored.maps[name]) != id {
			t.Fatalf("%s was replaced", name)
		}
	}
	var nonce uint64
	if err := restored.maps[SocketNonceMap].Lookup(uint64(10), &nonce); err != nil || nonce != 123 {
		t.Fatalf("lost nonce history: %d %v", nonce, err)
	}
	for _, phase := range []uint32{1, 2} {
		control.Phase = phase
		if err := restored.maps[SocketControlMap].Update(uint64(10), control, ebpf.UpdateExist); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(restored.RollbackPreflight(), ErrSocketRollbackRequiresQuiescence) {
			t.Fatalf("phase %d incorrectly allows an in-place downgrade", phase)
		}
	}
	if err := restored.maps[SocketControlMap].Delete(uint64(10)); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(restored.RollbackPreflight(), ErrSocketRollbackRequiresQuiescence) {
		t.Fatal("nonce-only history incorrectly allows downgrade")
	}
	if err := restored.maps[SocketNonceMap].Delete(uint64(10)); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(restored.RollbackPreflight(), ErrSocketRollbackRequiresQuiescence) {
		t.Fatal("loss of all control history incorrectly allows downgrade")
	}
	if _, err := PinSocketBundle(dir, 8, maps); err == nil {
		t.Fatal("fresh publication overwrote existing pins")
	}
}

func TestPrivilegedSocketBundleRejectsPartialOrChangedState(t *testing.T) {
	for _, scenario := range []string{"missing_owner", "missing_schema", "schema_version", "capacity"} {
		t.Run(scenario, func(t *testing.T) {
			dir := filepath.Dir(privilegedPinPath(t))
			maps := freshSocketMaps(t)
			b, err := PinSocketBundle(dir, 8, maps)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			ownerID := socketMapID(t, maps[SocketOwnerMap])
			capacity := uint32(8)
			switch scenario {
			case "missing_owner":
				err = os.Remove(filepath.Join(dir, SocketOwnerMap))
			case "missing_schema":
				err = os.Remove(filepath.Join(dir, SocketSchemaMap))
			case "schema_version":
				changed := currentSocketSchema
				changed.Version++
				err = b.maps[SocketSchemaMap].Update(uint32(0), changed, ebpf.UpdateAny)
			case "capacity":
				capacity++
			}
			if err != nil {
				t.Fatal(err)
			}
			if restored, err := OpenSocketBundle(dir, capacity); err == nil {
				restored.Close()
				t.Fatal("unsafe restore accepted")
			}
			if socketMapID(t, maps[SocketOwnerMap]) != ownerID {
				t.Fatal("failed restore replaced socket ownership")
			}
			if scenario == "missing_owner" {
				if _, err := os.Stat(filepath.Join(dir, SocketOwnerMap)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed restore recreated missing ownership map")
				}
			}
		})
	}
}

func privilegedPinPath(t *testing.T) string {
	t.Helper()
	testutils.PrivilegedTest(t)
	dir, err := os.MkdirTemp("/sys/fs/bpf", "vtep-socket-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "maps")
}

func TestPrivilegedBundleDetectsEveryMissingPin(t *testing.T) {
	for _, spec := range socketMapSpecs(8) {
		t.Run(spec.Name, func(t *testing.T) {
			dir := filepath.Dir(privilegedPinPath(t))
			b, err := PinSocketBundle(dir, 8, freshSocketMaps(t))
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			if err := b.checkPins(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, spec.Name)); err != nil {
				t.Fatal(err)
			}
			if err := b.checkPins(dir); err == nil {
				t.Fatal("missing canonical pin was not detected")
			}
		})
	}
}
