// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Syscall/lifecycle test only: these invalid records never represent forwarding
// authority. Real application traffic is exercised by the separate live suite.
func TestPrivilegedControllerRestartUnderPressure(t *testing.T) {
	c, spec := tracingController(t)
	mapIDs, linkIDs := map[string]ebpf.MapID{}, map[string]link.ID{}
	for name, m := range c.bundle.maps {
		mapIDs[name] = socketMapID(t, m)
	}
	for name, l := range c.tracing {
		info, err := l.Info()
		if err != nil {
			t.Fatal(err)
		}
		linkIDs[name] = info.ID
	}
	if len(mapIDs) != 18 || len(linkIDs) != 8 {
		t.Fatal("incomplete canonical graph")
	}
	maps := map[string]*ebpf.Map{}
	for _, name := range []string{SocketAdmitMap, SocketRequestMap, TimewaitProofMap, TimewaitOwnerMap, TimewaitPacketMap} {
		m, err := c.bundle.maps[name].Clone()
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		maps[name] = m
	}
	// These two hashes cannot be reclaimed from guessed expiry. Capacity and
	// non-eviction must survive startup collection, not trigger unsafe cleanup.
	for _, name := range []string{TimewaitOwnerMap, TimewaitPacketMap} {
		m := maps[name]
		info, err := m.Info()
		if err != nil || info.MaxEntries != SocketCapacity {
			t.Fatal("unexpected production map capacity", err)
		}
		for i := uint64(0); i < uint64(info.MaxEntries); i++ {
			if err := m.Update(i+1, make([]byte, info.ValueSize), ebpf.UpdateNoExist); err != nil {
				t.Fatal(err)
			}
		}
	}
	var steps atomic.Uint64
	stop, done := make(chan struct{}), make(chan error, 1)
	go func() {
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				done <- nil
				return
			case <-tick.C:
				for _, name := range []string{SocketAdmitMap, SocketRequestMap, TimewaitProofMap} {
					m := maps[name]
					info, err := m.Info()
					if err != nil {
						done <- err
						return
					}
					for i := uint64(0); i < 64; i++ {
						key := make([]byte, 16)
						binary.NativeEndian.PutUint64(key, 0x1000000000000000+i)
						if err := m.Update(key, make([]byte, info.ValueSize), ebpf.UpdateNoExist); err != nil && !errors.Is(err, unix.EEXIST) {
							done <- fmt.Errorf("concurrent %s producer: %w", name, err)
							return
						}
					}
				}
				for _, name := range []string{TimewaitOwnerMap, TimewaitPacketMap} {
					info, err := maps[name].Info()
					if err != nil {
						done <- err
						return
					}
					if err := maps[name].Update(uint64(SocketCapacity+1), make([]byte, info.ValueSize), ebpf.UpdateNoExist); !errors.Is(err, unix.E2BIG) && !errors.Is(err, unix.ENOSPC) {
						done <- fmt.Errorf("full %s lost non-evicting behavior: %v", name, err)
						return
					}
				}
				steps.Add(1)
			}
		}
	}()
	stopped := false
	finish := func() {
		if !stopped {
			stopped = true
			close(stop)
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	}
	defer finish()
	waitProgress := func(before uint64) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for steps.Load() <= before+2 {
			if time.Now().After(deadline) {
				t.Fatal("concurrent producer stopped making progress")
			}
			time.Sleep(time.Millisecond)
		}
	}
	for range 2 {
		before := steps.Load()
		waitProgress(before)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		waitProgress(steps.Load()) // BPF pins and independent producer survive controller downtime.
		var err error
		c, err = restoreTracingController(t, c, spec)
		if err != nil {
			t.Fatal(err)
		}
		for name, id := range mapIDs {
			if socketMapID(t, c.bundle.maps[name]) != id {
				t.Fatalf("restart replaced map %s", name)
			}
		}
		for name, id := range linkIDs {
			info, err := c.tracing[name].Info()
			if err != nil || info.ID != id {
				t.Fatalf("restart replaced tracing hook %s: %v", name, err)
			}
		}
		for range 3 {
			c.mu.Lock()
			err := c.collectLocked()
			c.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			waitProgress(steps.Load())
		}
		if err := c.Readiness(); err != nil {
			t.Fatal("capacity pressure damaged readiness", err)
		}
	}
	finish()
	c.mu.Lock()
	err := c.collectLocked()
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{SocketAdmitMap, SocketRequestMap, TimewaitProofMap} {
		if key, err := maps[name].NextKeyBytes(nil); err != nil || key != nil {
			t.Fatal("stopped invalid producer was not reclaimed", name, err)
		}
	}
	for _, name := range []string{TimewaitOwnerMap, TimewaitPacketMap} {
		info, err := maps[name].Info()
		if err != nil {
			t.Fatal(err)
		}
		for i := uint64(1); i <= SocketCapacity; i++ {
			v, err := maps[name].LookupBytes(i)
			if err != nil || !bytes.Equal(v, make([]byte, info.ValueSize)) {
				t.Fatal("restart/GC evicted or changed occupied record", name, i, err)
			}
		}
	}
	t.Logf("producer completed %d rounds across two controller restarts with unchanged 18-map/8-hook graph", steps.Load())
}
