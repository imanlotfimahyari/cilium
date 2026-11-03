// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// The only test program loaded here samples the real kernel jiffies clock.
// No test-side collector, tracing attachment, clock rewrite or ledger mutation
// is permitted: deletion must come from the already-running real agent.
func verifyFreshAgentCookieGC(t *testing.T, f *handoffFixture, agent *agentProcess, pins string, existing [][2]*net.TCPConn) {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(tcpModeObject(t, "VTEP_RETURN_COOKIE_CORE_OBJECT"))
	if err != nil {
		t.Fatal(err)
	}
	clock, err := ebpf.NewProgram(spec.Programs["handoff_cookie_clock"])
	if err != nil {
		t.Fatal(err)
	}
	defer clock.Close()
	now := func() uint64 {
		t.Helper()
		ret, out, err := clock.Test(make([]byte, 64))
		if err != nil || ret != 1 || len(out) < 8 {
			t.Fatal("read kernel cookie clock", ret, err)
		}
		return binary.NativeEndian.Uint64(out[:8])
	}
	ledger, err := ebpf.LoadPinnedMap(agentMapPin(t, pins, "cookie_peer_ledger"), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	owners := openAgentOwnerMap(t, pins)
	defer owners.Close()
	graph := snapshotAgentAffinity(t, pins)
	statsBefore := openAgentCookieStats(t, pins)
	receivedBefore := cookieCounter(t, f.podNS, "SyncookiesRecv")
	started := now()
	var clients, servers [2]*net.TCPConn
	savedOwners := make([]handoffOwner, len(existing)+2)
	flows := append([][2]*net.TCPConn(nil), existing...)
	for i := range clients {
		clients[i], servers[i] = f.connect(t, i, 49320+i)
		defer clients[i].Close()
		defer servers[i].Close()
		flows = append(flows, [2]*net.TCPConn{clients[i], servers[i]})
	}
	for i, pair := range flows {
		savedOwners[i] = ownerFromMap(t, owners, pair[1])
	}
	if cookieCounter(t, f.podNS, "SyncookiesRecv") < receivedBefore+2 || openAgentCookieStats(t, pins).Bound < statsBefore.Bound+2 {
		t.Fatal("fresh handshakes did not traverse the real kernel/agent cookie path")
	}
	saved := map[cookiePeerKey]cookiePeerRecord{}
	var key cookiePeerKey
	var record cookiePeerRecord
	it := ledger.Iterate()
	for it.Next(&key, &record) {
		if key.Namespace != f.cookie || (key.RemotePort != wire16(49320) && key.RemotePort != wire16(49321)) {
			continue
		}
		i := 0
		if key.RemotePort == wire16(49321) {
			i = 1
		}
		owner := savedOwners[len(existing)+i]
		if key.Generation != f.cookie || key.Local != wireIP(f.pod.ip) || key.LocalPort != wire16(8080) || key.Reserved != 0 || record.State != 2 || record.Peer != owner.Peer || owner.Peer != wireIP(f.under[i].ip) || record.Epoch < started/60000 || record.Expires != (record.Epoch+2)*60000 {
			t.Fatal("fresh ledger record does not match its real consumed cookie/peer")
		}
		saved[key] = record
	}
	if err := it.Err(); err != nil || len(saved) != 2 {
		t.Fatalf("must observe both newly issued records before waiting: count=%d error=%v", len(saved), err)
	}
	observed := now()
	for _, record := range saved {
		if record.Expires <= observed || record.Expires-observed < 50000 {
			t.Fatal("record was already near expiry; no fresh-window proof")
		}
	}
	deadline := time.Now().Add(140 * time.Second)
	nextTransfer := time.Time{}
	removed := make(map[cookiePeerKey]uint64)
	checkFlows := func() {
		t.Helper()
		select {
		case <-agent.done:
			t.Fatalf("agent exited during periodic GC: %v", agent.err)
		default:
		}
		for i, pair := range flows {
			if ownerFromMap(t, owners, pair[1]) != savedOwners[i] {
				t.Fatal("GC changed an established socket owner")
			}
			transferHandoff(t, pair[0], pair[1], fmt.Sprintf("periodic-cookie-GC-flow-%d", i))
		}
	}
	for len(removed) < len(saved) {
		for key, original := range saved {
			var actual cookiePeerRecord
			err := ledger.Lookup(key, &actual)
			sampled := now()
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				if sampled < original.Expires {
					t.Fatal("periodic agent GC removed valid cookie authority before expiry")
				}
				if _, done := removed[key]; !done {
					removed[key] = sampled
					t.Logf("periodic agent GC removed a real cookie record at expiry +%d jiffies", sampled-original.Expires)
				}
			} else if err != nil || actual != original {
				t.Fatal("GC changed or recreated an immutable cookie record", err)
			}
			if sampled > original.Expires+15000 && err == nil {
				t.Fatal("running agent did not collect the expired cookie record within three GC intervals")
			}
		}
		if time.Now().After(nextTransfer) {
			checkFlows()
			t.Log("fresh-cookie GC wait: both peer records monitored; all four TCP owners and flows intact")
			nextTransfer = time.Now().Add(10 * time.Second)
		}
		if time.Now().After(deadline) {
			t.Fatal("fresh-cookie periodic GC exceeded the real-window deadline")
		}
		if len(removed) < len(saved) {
			time.Sleep(250 * time.Millisecond)
		}
	}
	checkFlows()
	assertAgentGraph(t, graph, snapshotAgentAffinity(t, pins))
	beforeNew := openAgentCookieStats(t, pins)
	client, server := f.connect(t, 1, 49322)
	defer client.Close()
	defer server.Close()
	if ownerFromMap(t, owners, server).Peer != wireIP(f.under[1].ip) || openAgentCookieStats(t, pins).Bound <= beforeNew.Bound {
		t.Fatal("new cookie admission failed after real periodic collection")
	}
	transferHandoff(t, client, server, "new-cookie-after-periodic-GC")
	t.Logf("fresh-cookie periodic GC complete: %d records observed live then collected; %d established flows preserved; new admission passed", len(saved), len(flows))
}
