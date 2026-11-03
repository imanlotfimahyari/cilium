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
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Workers hold their own descriptors; reload may close the fixture collection.
// Errors are returned to the test goroutine, never hidden behind goroutine Fatal.
func pressureWorker(t *testing.T, work func() error) (*atomic.Uint64, func()) {
	t.Helper()
	return pressureWorkerAt(t, time.Millisecond, work)
}

func pressureWorkerAt(t *testing.T, interval time.Duration, work func() error) (*atomic.Uint64, func()) {
	t.Helper()
	var progress atomic.Uint64
	stop, done := make(chan struct{}), make(chan error, 1)
	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				done <- nil
				return
			case <-tick.C:
				if err := work(); err != nil {
					done <- err
					return
				}
				progress.Add(1)
			}
		}
	}()
	var stopped bool
	finish := func() {
		if stopped {
			return
		}
		stopped = true
		close(stop)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(finish)
	return &progress, finish
}

// Controlled overlap, not a throughput benchmark or a legitimate SYN flood:
// invalid occupancy records compete with real BPF cleanup and packet traffic.
func TestPrivilegedConcurrentPressureReload(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		for _, name := range []string{"cilium_vtep_admit4", "cilium_vtep_req4"} {
			t.Run(fmt.Sprintf("mapped=%v/%s", mapped, name), func(t *testing.T) {
				f := newHandoffListenerFixture(t, tcpModeObject(t, "VTEP_RETURN_CORE_OBJECT"), mapped)
				client, server := f.connect(t, 0, 49000)
				owner := f.owner(t, server)
				otherClient, otherServer := f.connect(t, 1, 49003)
				otherOwner := f.owner(t, otherServer)
				f.noPending(t)
				unchanged, _ := occupyPressureMap(t, f.collection.Maps[name])
				f.setControl(t, time.Second)
				before := f.counts(t)
				drops := coreDirectionalDrops(t, f, 134, 1)
				err := f.peerNS[1].Do(func() error {
					d := net.Dialer{Timeout: 300 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 49001}}
					c, err := d.Dial("tcp4", "198.51.100.10:8080")
					if c != nil {
						c.Close()
					}
					return err
				})
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("full map did not reject handshake: %v", err)
				}
				if name == "cilium_vtep_req4" && f.counts(t).AssignmentFailed <= before.AssignmentFailed ||
					name == "cilium_vtep_admit4" && coreDirectionalDrops(t, f, 134, 1) <= drops {
					t.Fatal("expected pressure rejection path was not exercised")
				}
				unchanged()
				m, err := f.collection.Maps[name].Clone()
				if err != nil {
					t.Fatal(err)
				}
				defer m.Close()
				info, err := m.Info()
				if err != nil {
					t.Fatal(err)
				}
				collector, err := f.collection.Programs["handoff_collect"].Clone()
				if err != nil {
					t.Fatal(err)
				}
				defer collector.Close()
				producer, stopProducer := pressureWorker(t, func() error {
					for i := uint64(0); i < 8; i++ {
						key := make([]byte, info.KeySize)
						binary.NativeEndian.PutUint64(key, 0x1000000000000000+i)
						if err := m.Update(key, make([]byte, info.ValueSize), ebpf.UpdateNoExist); err != nil &&
							!errors.Is(err, unix.EEXIST) && !errors.Is(err, unix.E2BIG) && !errors.Is(err, unix.ENOSPC) {
							return fmt.Errorf("occupancy producer: %w", err)
						}
					}
					return nil
				})
				defer stopProducer()
				collections, stopCollector := pressureWorker(t, func() error {
					ret, err := collector.Run(&ebpf.RunOptions{Data: make([]byte, 64)})
					if err != nil || ret != 0 {
						return fmt.Errorf("concurrent collector: retval=%d error=%v", ret, err)
					}
					return nil
				})
				defer stopCollector()
				transfers, stopTraffic := pressureWorker(t, func() error {
					for peer, pair := range [][2]*net.TCPConn{{client, server}, {otherClient, otherServer}} {
						payload := fmt.Appendf(nil, "peer-%d-established-during-pressure-GC-reload", peer)
						pair[1].SetWriteDeadline(time.Now().Add(3 * time.Second))
						if _, err := pair[1].Write(payload); err != nil {
							return err
						}
						pair[0].SetReadDeadline(time.Now().Add(3 * time.Second))
						buf := make([]byte, len(payload))
						if _, err := io.ReadFull(pair[0], buf); err != nil {
							return err
						}
						if !bytes.Equal(buf, payload) {
							return fmt.Errorf("established payload changed for peer %d", peer)
						}
					}
					return nil
				})
				defer stopTraffic()
				for range 2 {
					p, c, x := producer.Load(), collections.Load(), transfers.Load()
					waitHandoff(t, func() bool { return producer.Load() > p+2 && collections.Load() > c+2 && transfers.Load() > x+2 })
					f.warmReload(t)
					waitHandoff(t, func() bool { return producer.Load() > p+5 && collections.Load() > c+5 && transfers.Load() > x+5 })
					if f.owner(t, server) != owner || f.owner(t, otherServer) != otherOwner {
						t.Fatal("overlapping GC/reload changed established owner")
					}
				}
				stopProducer()
				stopCollector()
				stopTraffic()
				// Only real BPF GC reclaims expired invalid/pending records.
				time.Sleep(1100 * time.Millisecond)
				f.collect(t)
				f.noPending(t)
				f.setControl(t, 30*time.Second)
				a, b := f.connect(t, 1, 49002)
				if f.owner(t, b).Peer != wireIP(f.under[1].ip) || f.owner(t, server) != owner || f.owner(t, otherServer) != otherOwner {
					t.Fatal("capacity recovery changed peer binding")
				}
				transferHandoff(t, a, b, "new-peer-after-concurrent-pressure")
				transferHandoff(t, client, server, "existing-peer-after-concurrent-pressure")
				transferHandoff(t, otherClient, otherServer, "other-existing-peer-after-concurrent-pressure")
				t.Logf("completed producer=%d collector=%d transfers=%d across two compatible reloads", producer.Load(), collections.Load(), transfers.Load())
			})
		}
	}
}
