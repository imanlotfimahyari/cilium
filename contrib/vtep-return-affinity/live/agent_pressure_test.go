// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Called with the real daemon down, in a disconnected disposable guest only.
// Synthetic invalid occupancy causes deterministic exhaustion without creating
// forwarding authority. Only the restarted daemon may collect these records.
func agentRestartPressure(t *testing.T, f *handoffFixture, pins string, connections [][2]*net.TCPConn) func() {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(agentMapPin(t, pins, "cilium_vtep_admit4"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	info, err := m.Info()
	if err != nil || info.MaxEntries != 4096 || info.KeySize != 16 {
		t.Fatal("unexpected production admission-map shape", err)
	}
	mapID, ok := info.ID()
	if !ok {
		t.Fatal("canonical map ID missing")
	}
	key := func(i uint64) []byte {
		b := make([]byte, 16)
		binary.NativeEndian.PutUint64(b, 0x1000000000000000+i)
		return b
	}
	value := make([]byte, info.ValueSize)
	for i := uint64(0); i < uint64(info.MaxEntries); i++ {
		if err := m.Update(key(i), value, ebpf.UpdateNoExist); err != nil {
			t.Fatal("cannot fill isolated admission map", err)
		}
	}
	if err := m.Update(key(uint64(info.MaxEntries)), value, ebpf.UpdateNoExist); !errors.Is(err, unix.E2BIG) && !errors.Is(err, unix.ENOSPC) {
		t.Fatal("full admission map did not reject another insert", err)
	}
	err = f.peerNS[1].Do(func() error {
		d := net.Dialer{Timeout: 300 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 47020}}
		c, err := d.Dial("tcp4", "198.51.100.10:8080")
		if c != nil {
			c.Close()
		}
		return err
	})
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("full admission map allowed a new real handshake: %v", err)
	}
	for i := uint64(0); i < uint64(info.MaxEntries); i++ {
		v, err := m.LookupBytes(key(i))
		if err != nil || !bytes.Equal(v, value) {
			t.Fatal("failed handshake changed occupied record", err)
		}
	}
	var cursor uint64
	produced, stopProducer := pressureWorkerAt(t, 50*time.Millisecond, func() error {
		for range 128 {
			err := m.Update(key(cursor%uint64(info.MaxEntries)), value, ebpf.UpdateNoExist)
			cursor++
			if err != nil && !errors.Is(err, unix.EEXIST) && !errors.Is(err, unix.E2BIG) && !errors.Is(err, unix.ENOSPC) {
				return err
			}
		}
		return nil
	})
	transferred, stopTraffic := pressureWorkerAt(t, 20*time.Millisecond, func() error {
		for peer, pair := range connections {
			payload := fmt.Appendf(nil, "real-agent-pressure-peer-%d", peer)
			pair[1].SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := pair[1].Write(payload); err != nil {
				return err
			}
			pair[0].SetReadDeadline(time.Now().Add(10 * time.Second))
			b := make([]byte, len(payload))
			if _, err := io.ReadFull(pair[0], b); err != nil {
				return err
			}
			if !bytes.Equal(b, payload) {
				return fmt.Errorf("wrong payload for peer %d", peer)
			}
		}
		return nil
	})
	// Prove both workers actually started before the daemon is launched.
	waitHandoff(t, func() bool { return produced.Load() >= 2 && transferred.Load() >= 2 })
	p, x := produced.Load(), transferred.Load()
	finished := false
	return func() {
		if finished {
			return
		}
		finished = true
		stopProducer()
		stopTraffic()
		if produced.Load() <= p || transferred.Load() <= x {
			t.Fatal("workers made no progress across actual daemon restoration")
		}
		// No fixture deletes, collector test runs, or manual pin replacement.
		// The daemon's real five-second GC loop must reclaim stopped occupancy.
		deadline := time.Now().Add(20 * time.Second)
		for {
			k, err := m.NextKeyBytes(nil)
			if err != nil {
				t.Fatal(err)
			}
			if k == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("restarted daemon did not reclaim stopped admission pressure")
			}
			time.Sleep(100 * time.Millisecond)
		}
		current, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		if id, ok := current.ID(); !ok || id != mapID {
			t.Fatal("pressure recovery replaced canonical admission map")
		}
		client, server := f.connect(t, 1, 47021)
		defer client.Close()
		defer server.Close()
		transferHandoff(t, client, server, "new-admission-after-real-agent-pressure-GC")
		t.Logf("actual restart pressure producer=%d two-peer-transfer-rounds=%d; real periodic GC restored new admission", produced.Load(), transferred.Load())
	}
}
