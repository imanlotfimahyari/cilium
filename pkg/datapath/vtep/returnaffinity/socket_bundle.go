// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	SocketControlMap  = "cilium_vtep_sock_ctl4"
	SocketNonceMap    = "cilium_vtep_nonce4"
	SocketAdmitMap    = "cilium_vtep_admit4"
	SocketRequestMap  = "cilium_vtep_req4"
	SocketOwnerMap    = "cilium_vtep_sock4"
	SocketPeerMap     = "cilium_vtep_peers4"
	TimewaitOwnerMap  = "vtep_tw_owners"
	TimewaitLifeMap   = "vtep_tw_stats"
	TimewaitScopeMap  = "tw_reply_scope"
	TimewaitPacketMap = "tw_output_packet"
	TimewaitProofMap  = "cilium_vtep_tw_proof4"
	TimewaitStatsMap  = "tw_packet_stats"
	SocketSchemaMap   = "cilium_vtep_sock_schema"
)

var ErrSocketRollbackRequiresQuiescence = errors.New("socket-affinity rollback requires draining and replacing the selected namespaces")

type socketSchema struct {
	Version  uint32
	Reserved uint32
	Magic    uint64
}

var currentSocketSchema = socketSchema{Version: 2, Magic: 0x56544550534f434b}

// SocketBundle owns descriptors, not socket lifetimes. Closing it preserves all
// pins and actual kernel map identities. The caller must serialize controllers
// with AcquireLease and give MapReplacements to the Cilium collection loader.
// No controller should allow its loader to recreate a member independently.
type SocketBundle struct {
	mu     sync.Mutex
	maps   map[string]*ebpf.Map
	closed bool
}

func socketMapSpecs(capacity uint32) []*ebpf.MapSpec {
	return []*ebpf.MapSpec{
		{Name: SocketControlMap, Type: ebpf.Hash, KeySize: 8, ValueSize: 24, MaxEntries: 1024},
		{Name: SocketNonceMap, Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 1024},
		{Name: SocketAdmitMap, Type: ebpf.Hash, KeySize: 16, ValueSize: 48, MaxEntries: capacity},
		{Name: SocketRequestMap, Type: ebpf.Hash, KeySize: 16, ValueSize: 56, MaxEntries: capacity},
		{Name: SocketOwnerMap, Type: ebpf.SkStorage, KeySize: 4, ValueSize: 32, Flags: unix.BPF_F_NO_PREALLOC},
		{Name: SocketPeerMap, Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 64},
		{Name: TimewaitOwnerMap, Type: ebpf.Hash, KeySize: 8, ValueSize: 48, MaxEntries: capacity},
		{Name: TimewaitLifeMap, Type: ebpf.Array, KeySize: 4, ValueSize: 24, MaxEntries: 1},
		{Name: TimewaitScopeMap, Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 72, MaxEntries: 1},
		{Name: TimewaitPacketMap, Type: ebpf.Hash, KeySize: 8, ValueSize: 56, MaxEntries: capacity},
		{Name: TimewaitProofMap, Type: ebpf.Hash, KeySize: 16, ValueSize: 64, MaxEntries: capacity},
		{Name: TimewaitStatsMap, Type: ebpf.Array, KeySize: 4, ValueSize: 32, MaxEntries: 1},
		{Name: SocketSchemaMap, Type: ebpf.Array, KeySize: 4, ValueSize: 16, MaxEntries: 1},
	}
}

func checkSocketMap(m *ebpf.Map, spec *ebpf.MapSpec) error {
	info, err := m.Info()
	if err != nil {
		return err
	}
	if info.Type != spec.Type || info.KeySize != spec.KeySize || info.ValueSize != spec.ValueSize ||
		info.MaxEntries != spec.MaxEntries || info.Flags != spec.Flags {
		return fmt.Errorf("incompatible %s; refusing socket-state replacement", spec.Name)
	}
	return nil
}

// OpenSocketBundle is strictly restorative: a missing, partial, incompatible or
// unversioned bundle is an error. It never creates a missing member or updates
// the schema. All validation completes before a descriptor set is returned.
func OpenSocketBundle(dir string, capacity uint32) (_ *SocketBundle, err error) {
	if capacity == 0 {
		return nil, fmt.Errorf("socket admission capacity must be positive")
	}
	b := &SocketBundle{maps: make(map[string]*ebpf.Map)}
	defer func() {
		if err != nil {
			b.Close()
		}
	}()
	schemaMap, loadErr := ebpf.LoadPinnedMap(filepath.Join(dir, SocketSchemaMap), nil)
	if loadErr != nil {
		return nil, fmt.Errorf("restore schema: %w", loadErr)
	}
	b.maps[SocketSchemaMap] = schemaMap
	marker := socketMapSpecs(capacity)
	if err := checkSocketMap(schemaMap, marker[len(marker)-1]); err != nil {
		return nil, err
	}
	var schema socketSchema
	if err := schemaMap.Lookup(uint32(0), &schema); err != nil {
		return nil, err
	}
	if schema != currentSocketSchema {
		return nil, fmt.Errorf("unsupported socket-affinity schema; drain and disable with the previous binary before upgrading or downgrading")
	}
	for _, spec := range socketMapSpecs(capacity) {
		if spec.Name == SocketSchemaMap {
			continue
		}
		m, loadErr := ebpf.LoadPinnedMap(filepath.Join(dir, spec.Name), nil)
		if loadErr != nil {
			return nil, fmt.Errorf("restore %s: %w", spec.Name, loadErr)
		}
		b.maps[spec.Name] = m
		if err := checkSocketMap(m, spec); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// PinSocketBundle adopts explicitly supplied maps from a freshly loaded
// collection. It validates every member before pinning, clones descriptors,
// creates a version marker, and publishes that marker last. Existing paths are
// never overwritten. Failed publication removes only pins made by this call.
// This is not an API for adopting unknown surviving state after a restart.
func PinSocketBundle(dir string, capacity uint32, supplied map[string]*ebpf.Map) (_ *SocketBundle, err error) {
	if capacity == 0 {
		return nil, fmt.Errorf("socket admission capacity must be positive")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	specs := socketMapSpecs(capacity)
	for _, spec := range specs {
		if _, statErr := os.Lstat(filepath.Join(dir, spec.Name)); !errors.Is(statErr, os.ErrNotExist) {
			return nil, fmt.Errorf("socket pin already exists or cannot be inspected: %s", spec.Name)
		}
		if spec.Name != SocketSchemaMap {
			m := supplied[spec.Name]
			if m == nil {
				return nil, fmt.Errorf("missing supplied socket map %s", spec.Name)
			}
			if err := checkSocketMap(m, spec); err != nil {
				return nil, err
			}
		}
	}
	b := &SocketBundle{maps: make(map[string]*ebpf.Map)}
	var pinned []string
	defer func() {
		if err != nil {
			for _, path := range pinned {
				os.Remove(path)
			}
			b.Close()
		}
	}()
	for _, spec := range specs {
		var m *ebpf.Map
		if spec.Name == SocketSchemaMap {
			m, err = ebpf.NewMap(spec)
			if err == nil {
				err = m.Update(uint32(0), currentSocketSchema, ebpf.UpdateAny)
			}
		} else {
			m, err = supplied[spec.Name].Clone()
		}
		if m != nil {
			b.maps[spec.Name] = m
		}
		if err != nil {
			return nil, err
		}
		path := filepath.Join(dir, spec.Name)
		if err := m.Pin(path); err != nil {
			return nil, err
		}
		pinned = append(pinned, path)
	}
	return b, nil
}

// MapReplacements pins collection reloads to these exact map objects. The schema
// map is controller-only and is not passed to collections that do not declare it.
func (b *SocketBundle) MapReplacements(spec *ebpf.CollectionSpec) (map[string]*ebpf.Map, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrStopped
	}
	out := make(map[string]*ebpf.Map)
	for name := range spec.Maps {
		if m := b.maps[name]; m != nil {
			out[name] = m
		}
	}
	return out, nil
}

// A held descriptor keeps a map alive after pin loss, but does not make the
// graph restorable. Detect that loss before readiness or further admissions;
// never adopt a replacement with an identical shape and unrelated ownership.
func (b *SocketBundle) checkPins(dir string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrStopped
	}
	for name, held := range b.maps {
		pin, err := ebpf.LoadPinnedMap(filepath.Join(dir, name), nil)
		if err != nil {
			return fmt.Errorf("canonical runtime map pin lost: %s: %w", name, err)
		}
		a, ae := held.Info()
		z, ze := pin.Info()
		pin.Close()
		if ae != nil || ze != nil {
			return fmt.Errorf("inspect canonical runtime map %s: %w", name, errors.Join(ae, ze))
		}
		ai, aok := a.ID()
		zi, zok := z.ID()
		if !aok || !zok || ai != zi {
			return fmt.Errorf("canonical runtime map pin replaced: %s", name)
		}
	}
	var schema socketSchema
	if err := b.maps[SocketSchemaMap].Lookup(uint32(0), &schema); err != nil {
		return err
	}
	if schema != currentSocketSchema {
		return fmt.Errorf("canonical runtime map schema changed")
	}
	return nil
}

// RollbackPreflight reports why an in-place downgrade must be refused. READY or
// retired namespace records, nonce history, or pending work prove surviving
// state. Empty hash maps cannot prove absence of socket-local ownership or queued
// output: these maps may have lost records. This API never grants permission to
// downgrade. Draining/replacing namespaces and removing attachments requires a
// separately coordinated lifecycle; retirement alone is not quiescence.
func (b *SocketBundle) RollbackPreflight() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrStopped
	}
	for _, name := range []string{SocketControlMap, SocketNonceMap, SocketAdmitMap, SocketRequestMap} {
		key, err := b.maps[name].NextKeyBytes(nil)
		if err != nil {
			return err
		}
		if key != nil {
			return ErrSocketRollbackRequiresQuiescence
		}
	}
	return fmt.Errorf("%w: empty control maps do not prove socket quiescence", ErrSocketRollbackRequiresQuiescence)
}

func (b *SocketBundle) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	var result error
	for _, m := range b.maps {
		result = errors.Join(result, m.Close())
	}
	return result
}
