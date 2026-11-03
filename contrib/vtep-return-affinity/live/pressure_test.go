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
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// Force one independently full, small test map without evicting real records.
// These are invalid synthetic occupancy records, not forged forwarding owners.
func occupyPressureMap(t *testing.T, m *ebpf.Map) (assertUnchanged func(), clear func()) {
	t.Helper()
	if os.Getenv("VTEP_RETURN_ISOLATED_VM") != "1" {
		t.Fatal("pressure injection requires disposable VM")
	}
	info, err := m.Info()
	if err != nil || info.MaxEntries != 8 || (info.KeySize != 8 && info.KeySize != 16) {
		t.Fatalf("unexpected pressure fixture shape: %v", err)
	}
	if key, err := m.NextKeyBytes(nil); err != nil || key != nil {
		t.Fatal("pressure fixture map must start empty")
	}
	var keys [][]byte
	value := make([]byte, info.ValueSize)
	for i := uint64(0); i < 8; i++ {
		key := make([]byte, info.KeySize)
		binary.NativeEndian.PutUint64(key, 0x1000000000000000+i)
		if err := m.Update(key, value, ebpf.UpdateNoExist); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	return func() {
			for _, key := range keys {
				actual, err := m.LookupBytes(key)
				if err != nil || !bytes.Equal(actual, value) {
					t.Fatal("pressure evicted or changed an existing record", err)
				}
			}
		}, func() {
			for _, key := range keys {
				if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatal(err)
				}
			}
		}
}

func TestPrivilegedHandshakeMapPressure(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		for _, name := range []string{"cilium_vtep_admit4", "cilium_vtep_req4"} {
			t.Run(fmt.Sprintf("mapped=%v/%s", mapped, name), func(t *testing.T) {
				f := newHandoffListenerFixture(t, tcpModeObject(t, "VTEP_RETURN_CORE_OBJECT"), mapped)
				client, server := f.connect(t, 0, 48900)
				owner := f.owner(t, server)
				f.noPending(t)
				assertUnchanged, _ := occupyPressureMap(t, f.collection.Maps[name])
				f.setControl(t, time.Second)
				f.policy(t, 48901, 3)
				before := f.counts(t)
				beforeDrop := coreDirectionalDrops(t, f, 134, 1)
				err := f.peerNS[1].Do(func() error {
					d := net.Dialer{Timeout: 300 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 48901}}
					c, err := d.Dial("tcp4", "198.51.100.10:8080")
					if c != nil {
						c.Close()
					}
					return err
				})
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("full map allowed handshake or failed for another reason: %v", err)
				}
				if name == "cilium_vtep_req4" {
					if f.counts(t).AssignmentFailed <= before.AssignmentFailed {
						t.Fatal("request-map insert failure not exercised")
					}
				} else if coreDirectionalDrops(t, f, 134, 1) <= beforeDrop {
					t.Fatal("full admission map did not exercise ingress rejection")
				}
				assertUnchanged()
				if f.owner(t, server) != owner {
					t.Fatal("pressure retargeted established socket")
				}
				transferHandoff(t, client, server, "established-during-handshake-pressure")
				// Real collector removes invalid fixture entries and expired
				// pending admissions; it must never reclaim established storage.
				time.Sleep(1100 * time.Millisecond)
				f.collect(t)
				f.noPending(t)
				f.setControl(t, 30*time.Second)
				recoveredClient, recoveredServer := f.connect(t, 1, 48902)
				if f.owner(t, recoveredServer).Peer != wireIP(f.under[1].ip) || f.owner(t, server) != owner {
					t.Fatal("recovered admission borrowed an old peer")
				}
				transferHandoff(t, recoveredClient, recoveredServer, "new-admission-after-GC")
				transferHandoff(t, client, server, "old-flow-after-GC")
			})
		}
	}
}

func TestPrivilegedTIMEWAITMapPressure(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		for _, name := range []string{"vtep_tw_owners", "tw_output_packet", "cilium_vtep_tw_proof4"} {
			t.Run(fmt.Sprintf("mapped=%v/%s", mapped, name), func(t *testing.T) {
				f, coll := timewaitCore(t, mapped)
				client, server := f.connect(t, 0, 48910)
				owner := f.owner(t, server)
				if name == "vtep_tw_owners" {
					closingClient, closingServer := f.connect(t, 1, 48911)
					assertUnchanged, clear := occupyPressureMap(t, coll.Maps[name])
					var before timewaitStats
					if err := coll.Maps["vtep_tw_stats"].Lookup(uint32(0), &before); err != nil {
						t.Fatal(err)
					}
					if err := closingServer.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					closingClient.SetReadDeadline(time.Now().Add(3 * time.Second))
					if _, err := closingClient.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
						t.Fatal(err)
					}
					if err := closingClient.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					closingServer.SetReadDeadline(time.Now().Add(3 * time.Second))
					if _, err := closingServer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
						t.Fatal(err)
					}
					waitHandoff(t, func() bool {
						var after timewaitStats
						if err := coll.Maps["vtep_tw_stats"].Lookup(uint32(0), &after); err != nil {
							t.Fatal(err)
						}
						return after.Rejected > before.Rejected
					})
					assertUnchanged()
					if f.owner(t, server) != owner {
						t.Fatal("failed transfer retargeted live connection")
					}
					transferHandoff(t, client, server, "existing-flow-during-owner-pressure")
					clear()                             // Only disposable invalid fixture records are removed.
					closeTWPacket(t, f, coll, 1, 48912) // Future transfers and ACKs work.
				} else {
					_, fin, fd := closeTWPacket(t, f, coll, 1, 48911)
					assertUnchanged, clear := occupyPressureMap(t, coll.Maps[name])
					before := readTWPacketStats(t, coll)
					replayTWPacket(t, f, 1, fd, fin)
					waitHandoff(t, func() bool { return readTWPacketStats(t, coll).Pressure > before.Pressure })
					assertNoTIMEWAITACK(t, fd, 48911)
					assertUnchanged()
					if f.owner(t, server) != owner {
						t.Fatal("ACK pressure retargeted live socket")
					}
					transferHandoff(t, client, server, "existing-flow-during-ACK-pressure")
					if name == "cilium_vtep_tw_proof4" {
						ret, err := coll.Programs["tw_collect_proofs"].Run(&ebpf.RunOptions{Data: make([]byte, 64)})
						if err != nil || ret != 0 {
							t.Fatal("proof collector failed", ret, err)
						}
						if key, err := coll.Maps[name].NextKeyBytes(nil); err != nil || key != nil {
							t.Fatal("expired proofs were not reclaimed")
						}
					} else {
						clear()
					} // Packet fixtures are not real skb lifetimes.
					replayTWPacket(t, f, 1, fd, fin)
					receiveTWACK(t, fd, 48911, binary.BigEndian.Uint32(fin[42:46]), binary.BigEndian.Uint32(fin[38:42])+1)
				}
				if f.owner(t, server) != owner {
					t.Fatal("recovery changed established owner")
				}
				transferHandoff(t, client, server, "existing-flow-after-pressure-recovery")
			})
		}
	}
}
