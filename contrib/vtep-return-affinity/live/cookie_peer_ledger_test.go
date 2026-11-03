// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type cookiePeerKey struct {
	Namespace, Generation uint64
	Local, Remote         uint32
	LocalPort, RemotePort uint16
	ClientISN, ServerISN  uint32
	Reserved              uint32
}

type cookiePeerRecord struct {
	Epoch, Expires uint64
	Peer, State    uint32
}

type cookiePeerLedger struct {
	program *ebpf.Program
	m       *ebpf.Map
}

func newCookiePeerLedger(t *testing.T) cookiePeerLedger {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(tcpModeObject(t, "VTEP_RETURN_COOKIE_PEER_OBJECT"))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load candidate ledger: %+v", err)
	}
	t.Cleanup(coll.Close)
	return cookiePeerLedger{coll.Programs["cookie_peer_test"], coll.Maps["cookie_peer_ledger"]}
}

// Virtual jiffies: period=100, current/previous epochs accepted. No TCP packet,
// outer peer, policy verdict or kernel-created child is fabricated by this API.
func (l cookiePeerLedger) run(op uint32, key cookiePeerKey, peer uint32, now uint64) (bool, error) {
	data := make([]byte, 64)
	binary.NativeEndian.PutUint64(data[0:8], key.Namespace)
	binary.NativeEndian.PutUint64(data[8:16], key.Generation)
	binary.NativeEndian.PutUint32(data[16:20], key.Local)
	binary.NativeEndian.PutUint32(data[20:24], key.Remote)
	binary.NativeEndian.PutUint16(data[24:26], key.LocalPort)
	binary.NativeEndian.PutUint16(data[26:28], key.RemotePort)
	binary.NativeEndian.PutUint32(data[28:32], key.ClientISN)
	binary.NativeEndian.PutUint32(data[32:36], key.ServerISN)
	binary.NativeEndian.PutUint32(data[36:40], key.Reserved)
	binary.NativeEndian.PutUint64(data[40:48], now)
	binary.NativeEndian.PutUint64(data[48:56], 100)
	binary.NativeEndian.PutUint32(data[56:60], peer)
	binary.NativeEndian.PutUint32(data[60:64], op)
	ret, _, err := l.program.Test(data)
	return ret == 1, err
}

func (l cookiePeerLedger) expect(t *testing.T, op uint32, key cookiePeerKey, peer uint32, now uint64, want bool) {
	t.Helper()
	got, err := l.run(op, key, peer, now)
	if err != nil || got != want {
		t.Fatalf("op=%d peer=%d time=%d got=%v want=%v: %v", op, peer, now, got, want, err)
	}
}

func cookieLedgerOnCPU(t *testing.T, cpu int, start <-chan struct{}, work func()) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var previous, selected unix.CPUSet
	if err := unix.SchedGetaffinity(0, &previous); err != nil {
		t.Error(err)
		return
	}
	selected.Set(cpu)
	if err := unix.SchedSetaffinity(0, &selected); err != nil {
		t.Error(err)
		return
	}
	defer func() {
		if err := unix.SchedSetaffinity(0, &previous); err != nil {
			t.Error(err)
		}
	}()
	<-start
	work()
}

func TestPrivilegedSYNcookiePeerLedger(t *testing.T) {
	// Gate before the CPU requirement so ordinary one-CPU CI skips this
	// privileged fixture rather than failing an unrelated host test run.
	tcpModeObject(t, "VTEP_RETURN_COOKIE_PEER_OBJECT")
	// Even a one-CPU guest could serialize goroutines and appear to pass the
	// race cases. Require two CPUs and pin worker threads to both explicitly.
	if runtime.NumCPU() < 2 {
		t.Fatal("candidate ledger concurrency validation requires --cpus 2")
	}
	key := cookiePeerKey{Namespace: 1, Generation: 1, Local: 1, Remote: 2, LocalPort: 8080, RemotePort: 49100, ClientISN: 17, ServerISN: 29}
	t.Run("invalid_identity_and_clock_overflow_refuse", func(t *testing.T) {
		l := newCookiePeerLedger(t)
		variants := []cookiePeerKey{key, key, key}
		variants[0].Namespace = 0
		variants[1].Generation = 0
		variants[2].Reserved = 1
		for _, k := range variants {
			l.expect(t, 1, k, 11, 10, false)
		}
		l.expect(t, 1, key, 0, 10, false)
		l.expect(t, 1, key, 11, ^uint64(0), false)
	})
	t.Run("same_peer_retransmit_and_single_consume", func(t *testing.T) {
		l := newCookiePeerLedger(t)
		l.expect(t, 1, key, 11, 10, true)
		l.expect(t, 1, key, 11, 99, true)
		l.expect(t, 2, key, 12, 99, false) // Wrong-peer replay does not burn A.
		l.expect(t, 2, key, 11, 199, true)
		l.expect(t, 2, key, 11, 199, false)
		l.expect(t, 1, key, 11, 199, false) // Never reset a consumed tombstone.
	})
	t.Run("cross_peer_collision_quarantines_both", func(t *testing.T) {
		l := newCookiePeerLedger(t)
		l.expect(t, 1, key, 11, 10, true)
		l.expect(t, 1, key, 12, 11, false)
		l.expect(t, 1, key, 11, 12, false)
		l.expect(t, 2, key, 11, 99, false)
		l.expect(t, 2, key, 12, 99, false)
		l.expect(t, 3, key, 0, 199, true)
		var v cookiePeerRecord
		if err := l.m.Lookup(key, &v); err != nil || v.Peer != 11 || v.State != 3 || v.Expires != 200 {
			t.Fatal("collision erased or retargeted the original evidence", v, err)
		}
	})
	t.Run("epoch_collision_refuses_even_same_peer", func(t *testing.T) {
		l := newCookiePeerLedger(t)
		l.expect(t, 1, key, 11, 99, true)
		l.expect(t, 1, key, 11, 100, false)
		l.expect(t, 2, key, 11, 100, false)
	})
	t.Run("expiry_requires_GC_and_never_revives_tombstone", func(t *testing.T) {
		l := newCookiePeerLedger(t)
		l.expect(t, 1, key, 11, 99, true)
		l.expect(t, 2, key, 11, 200, false)
		l.expect(t, 1, key, 12, 200, false)
		l.expect(t, 3, key, 0, 200, true)
		l.expect(t, 1, key, 12, 200, true)
		l.expect(t, 2, key, 11, 200, false)
		l.expect(t, 2, key, 12, 200, true)
	})
	t.Run("namespace_generation_tuple_and_both_ISNs_are_exact", func(t *testing.T) {
		l := newCookiePeerLedger(t)
		l.expect(t, 1, key, 11, 10, true)
		variants := []cookiePeerKey{key, key, key, key, key, key, key, key}
		variants[0].Namespace++
		variants[1].Generation++
		variants[2].Local++
		variants[3].Remote++
		variants[4].LocalPort++
		variants[5].RemotePort++
		variants[6].ClientISN++
		variants[7].ServerISN++
		for _, k := range variants {
			l.expect(t, 2, k, 11, 10, false)
		}
		l.expect(t, 2, key, 11, 10, true)
	})
	t.Run("capacity_never_evicts_live_or_consumed_records", func(t *testing.T) {
		l := newCookiePeerLedger(t)
		for i := uint32(0); i < 8; i++ {
			k := key
			k.ServerISN += i
			l.expect(t, 1, k, 11, 10, true)
			if i%2 == 0 {
				l.expect(t, 2, k, 11, 10, true)
			}
		}
		extra := key
		extra.ServerISN += 8
		l.expect(t, 1, extra, 12, 10, false)
		l.expect(t, 3, key, 0, 199, true)
		for i := uint32(0); i < 8; i++ {
			k := key
			k.ServerISN += i
			var v cookiePeerRecord
			if err := l.m.Lookup(k, &v); err != nil || v.Peer != 11 || v.Expires != 200 {
				t.Fatal("capacity evicted original evidence", v, err)
			}
		}
		l.expect(t, 3, key, 0, 200, true)
		l.expect(t, 1, extra, 12, 200, true)
	})
	t.Run("concurrent_consumers_have_one_winner", func(t *testing.T) {
		l := newCookiePeerLedger(t)
		l.expect(t, 1, key, 11, 10, true)
		var wins atomic.Uint32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range 16 {
			wg.Go(func() {
				cookieLedgerOnCPU(t, i%2, start, func() {
					ok, err := l.run(2, key, 11, 10)
					if err != nil {
						t.Error(err)
					} else if ok {
						wins.Add(1)
					}
				})
			})
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("consume winners=%d", wins.Load())
		}
	})
	t.Run("concurrent_peers_never_last_writer_win", func(t *testing.T) {
		for range 16 {
			l := newCookiePeerLedger(t)
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := range 8 {
				wg.Go(func() {
					cookieLedgerOnCPU(t, i%2, start, func() {
						if _, err := l.run(1, key, uint32(11+i%2), 10); err != nil {
							t.Error(err)
						}
					})
				})
			}
			close(start)
			wg.Wait()
			l.expect(t, 2, key, 11, 10, false)
			l.expect(t, 2, key, 12, 10, false)
			var v cookiePeerRecord
			if err := l.m.Lookup(key, &v); err != nil || v.State != 3 || (v.Peer != 11 && v.Peer != 12) {
				t.Fatal("concurrent collision failed to preserve/quarantine first owner", v, err)
			}
		}
	})
	t.Run("consume_racing_collision_never_assigns_competing_peer", func(t *testing.T) {
		for range 16 {
			l := newCookiePeerLedger(t)
			l.expect(t, 1, key, 11, 10, true)
			var wg sync.WaitGroup
			start := make(chan struct{})
			wg.Go(func() {
				cookieLedgerOnCPU(t, 0, start, func() {
					if _, err := l.run(2, key, 11, 10); err != nil {
						t.Error(err)
					}
				})
			})
			wg.Go(func() {
				cookieLedgerOnCPU(t, 1, start, func() {
					if ok, err := l.run(1, key, 12, 10); err != nil || ok {
						t.Errorf("competing peer was issued authority: ok=%v error=%v", ok, err)
					}
				})
			})
			close(start)
			wg.Wait()
			l.expect(t, 2, key, 12, 10, false)
			var v cookiePeerRecord
			if err := l.m.Lookup(key, &v); err != nil || v.Peer != 11 || (v.State != 2 && v.State != 3) {
				t.Fatal("collision race retargeted original authority", v, err)
			}
		}
	})
	t.Run("concurrent_GC_and_reissue_preserve_fresh_incarnation", func(t *testing.T) {
		for round := range 32 {
			l := newCookiePeerLedger(t)
			l.expect(t, 1, key, 11, 10, true)
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := range 4 {
				wg.Go(func() {
					cookieLedgerOnCPU(t, i%2, start, func() {
						for range 16 {
							if ok, err := l.run(3, key, 0, 200); err != nil || !ok {
								t.Errorf("concurrent collection: ok=%v error=%v", ok, err)
								return
							}
							if _, err := l.run(1, key, 12, 200); err != nil {
								t.Error(err)
							}
						}
					})
				})
			}
			close(start)
			wg.Wait()
			l.expect(t, 1, key, 12, 200, true)
			l.expect(t, 2, key, 11, 200, false)
			l.expect(t, 2, key, 12, 200, true)
			var v cookiePeerRecord
			if err := l.m.Lookup(key, &v); err != nil || v.Peer != 12 || v.Expires != 400 || v.State != 2 {
				t.Fatal(fmt.Sprintf("round %d lost fresh incarnation", round), v, err)
			}
		}
	})
}
