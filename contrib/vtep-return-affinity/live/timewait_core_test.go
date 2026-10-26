// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func timewaitCore(t *testing.T, mapped bool) (*handoffFixture, *ebpf.Collection) {
	t.Helper()
	f := newHandoffListenerFixture(t, tcpModeObject(t, "VTEP_RETURN_TIMEWAIT_CORE_OBJECT"), mapped)
	return f, attachTIMEWAITPackets(t, f)
}

func latestProof(t *testing.T, f *handoffFixture, coll *ebpf.Collection) handoffKey {
	t.Helper()
	key := handoffKey{Namespace: f.cookie}
	if err := coll.Maps["cilium_vtep_nonce4"].Lookup(f.cookie, &key.Token); err != nil {
		t.Fatal(err)
	}
	return key
}

func proofGone(t *testing.T, coll *ebpf.Collection, key handoffKey) bool {
	t.Helper()
	v, err := coll.Maps["cilium_vtep_tw_proof4"].LookupBytes(key)
	if err != nil {
		t.Fatal(err)
	}
	return v == nil
}

func coreDrops(t *testing.T, f *handoffFixture, reason byte) uint64 {
	return coreDirectionalDrops(t, f, reason, 2)
}

func coreDirectionalDrops(t *testing.T, f *handoffFixture, reason, direction byte) uint64 {
	t.Helper()
	var key []byte
	var values []struct{ Count, Bytes uint64 }
	it := f.collection.Maps["cilium_metrics"].Iterate()
	var count uint64
	for it.Next(&key, &values) {
		if len(key) >= 2 && key[0] == reason && key[1]&3 == direction {
			for _, v := range values {
				count += v.Count
			}
		}
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return count
}

func clearCoreCT(t *testing.T, f *handoffFixture) {
	t.Helper()
	for _, name := range []string{"cilium_ct4_global", "cilium_ct_any4_global"} {
		m := f.collection.Maps[name]
		for {
			key, err := m.NextKeyBytes(nil)
			if err != nil {
				t.Fatal(err)
			}
			if key == nil {
				break
			}
			if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatal(err)
			}
		}
	}
}

func queueTIMEWAIT(t *testing.T, f *handoffFixture, latency uint32, duplicate float32) func() {
	t.Helper()
	q := netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: f.pod.remote.Attrs().Index,
		Parent: netlink.HANDLE_ROOT, Handle: netlink.MakeHandle(1, 0)},
		netlink.NetemQdiscAttrs{Latency: latency, Limit: 64, Duplicate: duplicate})
	if err := f.podNS.Do(func() error { return netlink.QdiscAdd(q) }); err != nil {
		t.Fatal(err)
	}
	remove := func() { f.podNS.Do(func() error { return netlink.QdiscDel(q) }) }
	t.Cleanup(remove)
	return remove
}

func assertNoTIMEWAITACK(t *testing.T, fd, port int) {
	t.Helper()
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		var buf [2048]byte
		n, _, err := unix.Recvfrom(fd, buf[:], 0)
		if errors.Is(err, unix.EAGAIN) {
			time.Sleep(time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if n >= 54 && binary.BigEndian.Uint16(buf[34:36]) == 8080 &&
			binary.BigEndian.Uint16(buf[36:38]) == uint16(port) && buf[47] == 0x10 {
			t.Fatal("rejected or duplicated proof forwarded a TIME-WAIT ACK")
		}
	}
}

func TestPrivilegedTIMEWAITCoreForwarding(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		name := "AF_INET"
		if mapped {
			name = "mapped_AF_INET6"
		}
		t.Run(name, func(t *testing.T) {
			f, coll := timewaitCore(t, mapped)
			for i, peer := range []int{0, 1, -1} {
				port := 48400 + i
				_, fin, fd := closeTWPacket(t, f, coll, peer, port)
				before := readTWPacketStats(t, coll)
				replayTWPacket(t, f, peer, fd, fin)
				receiveTWACK(t, fd, port, binary.BigEndian.Uint32(fin[42:46]), binary.BigEndian.Uint32(fin[38:42])+1)
				if !proofGone(t, coll, latestProof(t, f, coll)) || readTWPacketStats(t, coll).Stamps <= before.Stamps {
					t.Fatal("actual endpoint path did not consume its exact proof")
				}
			}
			stats := readTWPacketStats(t, coll)
			if stats.Tunnel+stats.Native+stats.Denied != 0 {
				t.Fatal("synthetic routing was used")
			}
		})
	}
}

func TestPrivilegedTIMEWAITCorePolicyOrdering(t *testing.T) {
	f, coll := timewaitCore(t, false)
	t.Cleanup(func() {
		if t.Failed() {
			f.dumpCoreStatus(t)
		}
	})
	owner, fin, fd := closeTWPacket(t, f, coll, 0, 48410)
	f.policy(t, 48410, 1) // Ingress allowed; deny new egress.
	// An admitted ingress connection's CT_REPLY legitimately bypasses a new
	// egress deny, just as it does without the affinity experiment.
	replayTWPacket(t, f, 0, fd, fin)
	receiveTWACK(t, fd, 48410, binary.BigEndian.Uint32(fin[42:46]), binary.BigEndian.Uint32(fin[38:42])+1)
	remove := queueTIMEWAIT(t, f, 500_000, 0)
	before := readTWPacketStats(t, coll)
	replayTWPacket(t, f, 0, fd, fin)
	waitHandoff(t, func() bool { return readTWPacketStats(t, coll).Stamps > before.Stamps })
	key := latestProof(t, f, coll)
	if proofGone(t, coll, key) {
		t.Fatal("ACK did not enter the actual pre-egress queue")
	}
	// The replayed FIN recreates ingress CT. Delete CT after stamping, while
	// this exact ACK is queued, to force the actual endpoint's egress verdict.
	clearCoreCT(t, f)
	drops := coreDrops(t, f, 181) // DROP_POLICY_DENY: explicit policy-entry denial.
	waitHandoff(t, func() bool { return coreDrops(t, f, 181) > drops })
	if proofGone(t, coll, key) {
		t.Fatal("proof was consumed before the policy denial")
	}
	assertNoTIMEWAITACK(t, fd, 48410)
	time.Sleep(10 * time.Second)
	if ret, _, err := coll.Programs["tw_collect_proofs"].Test(make([]byte, 64)); err != nil || ret != 0 {
		t.Fatalf("collect unused proof: %d %v", ret, err)
	}
	if !proofGone(t, coll, key) {
		t.Fatal("denied packet's unused proof was not reclaimed")
	}
	var record timewaitOwner
	if err := coll.Maps["vtep_tw_owners"].Lookup(owner.Cookie, &record); err != nil || record.Owner != owner {
		t.Fatalf("proof GC changed owner: %v", err)
	}
	remove()
	f.policy(t, 48410, 3)
	replayTWPacket(t, f, 0, fd, fin)
	receiveTWACK(t, fd, 48410, binary.BigEndian.Uint32(fin[42:46]), binary.BigEndian.Uint32(fin[38:42])+1)
}

func TestPrivilegedTIMEWAITCoreInvalidProofs(t *testing.T) {
	for _, scenario := range []string{"expired", "generation", "ack", "missing_cookie", "origin", "unknown_peer"} {
		t.Run(scenario, func(t *testing.T) {
			f, coll := timewaitCore(t, false)
			owner, fin, fd := closeTWPacket(t, f, coll, 0, 48420)
			queueTIMEWAIT(t, f, 500_000, 0)
			before := readTWPacketStats(t, coll)
			drops := coreDrops(t, f, 134) // DROP_INVALID
			replayTWPacket(t, f, 0, fd, fin)
			waitHandoff(t, func() bool { return readTWPacketStats(t, coll).Stamps > before.Stamps })
			key := latestProof(t, f, coll)
			proof, err := coll.Maps["cilium_vtep_tw_proof4"].LookupBytes(key)
			if err != nil || len(proof) != 64 {
				t.Fatalf("queued proof: %d %v", len(proof), err)
			}
			switch scenario {
			case "expired":
				binary.NativeEndian.PutUint64(proof[56:64], 1)
			case "generation":
				binary.NativeEndian.PutUint64(proof[8:16], owner.Generation+1)
			case "ack":
				proof[52] ^= 1
			case "missing_cookie":
				binary.NativeEndian.PutUint64(proof[16:24], 0)
			case "origin":
				binary.NativeEndian.PutUint32(proof[28:32], 0)
			case "unknown_peer":
				copy(proof[24:28], []byte{192, 0, 2, 222})
			}
			if err := coll.Maps["cilium_vtep_tw_proof4"].Update(key, proof, ebpf.UpdateExist); err != nil {
				t.Fatal(err)
			}
			waitHandoff(t, func() bool { return proofGone(t, coll, key) })
			// The unknown peer passes proof validation but must still fail the
			// trusted destination lookup. Other invalid claims fail earlier.
			if scenario != "unknown_peer" {
				waitHandoff(t, func() bool { return coreDrops(t, f, 134) > drops })
			}
			assertNoTIMEWAITACK(t, fd, 48420)
			var record timewaitOwner
			if err := coll.Maps["vtep_tw_owners"].Lookup(owner.Cookie, &record); err != nil || record.Owner != owner {
				t.Fatal("invalid packet changed authoritative owner", err)
			}
		})
	}
}

func TestPrivilegedTIMEWAITCoreDuplicateProof(t *testing.T) {
	f, coll := timewaitCore(t, false)
	_, fin, fd := closeTWPacket(t, f, coll, 0, 48430)
	queueTIMEWAIT(t, f, 100_000, 100)
	drops := coreDrops(t, f, 134)
	replayTWPacket(t, f, 0, fd, fin)
	receiveTWACK(t, fd, 48430, binary.BigEndian.Uint32(fin[42:46]), binary.BigEndian.Uint32(fin[38:42])+1)
	waitHandoff(t, func() bool { return coreDrops(t, f, 134) > drops })
	assertNoTIMEWAITACK(t, fd, 48430)
	if !proofGone(t, coll, latestProof(t, f, coll)) {
		t.Fatal("delivered proof survived duplicate consumption")
	}
}
