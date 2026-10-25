// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type agentAffinityGraph struct {
	Root  string
	Maps  map[string]ebpf.MapID
	Links map[string]link.ID
}

func agentMapPin(t *testing.T, root, name string) string {
	t.Helper()
	var pin string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == name && !d.IsDir() {
			if pin != "" {
				return fmt.Errorf("duplicate canonical map %s", name)
			}
			pin = path
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if pin == "" {
		t.Fatalf("missing canonical map %s", name)
	}
	return pin
}

func snapshotAgentAffinity(t *testing.T, root string) agentAffinityGraph {
	t.Helper()
	pins := filepath.Dir(agentMapPin(t, root, "cilium_vtep_sock_schema"))
	s := agentAffinityGraph{Root: filepath.Dir(pins), Maps: make(map[string]ebpf.MapID), Links: make(map[string]link.ID)}
	entries, err := os.ReadDir(pins)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pins, e.Name()), nil)
		if err != nil {
			t.Fatal(err)
		}
		info, err := m.Info()
		m.Close()
		if err != nil {
			t.Fatal(err)
		}
		id, ok := info.ID()
		if !ok {
			t.Fatal("map has no ID")
		}
		s.Maps[e.Name()] = id
	}
	entries, err = os.ReadDir(filepath.Join(s.Root, "tracing"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		l, err := link.LoadPinnedLink(filepath.Join(s.Root, "tracing", e.Name()), nil)
		if err != nil {
			t.Fatal(err)
		}
		info, err := l.Info()
		l.Close()
		if err != nil {
			t.Fatal(err)
		}
		s.Links[e.Name()] = info.ID
	}
	if len(s.Maps) != 13 || len(s.Links) != 6 {
		t.Fatalf("incomplete agent runtime: %d maps/%d links", len(s.Maps), len(s.Links))
	}
	return s
}

type agentTimewait struct {
	f        *handoffFixture
	coll     *ebpf.Collection
	owner    handoffOwner
	fin      []byte
	fd, port int
}

// Load only a receiving peer's capture sink. All ownership, tracing, stamping,
// collection and forwarding programs in this test are loaded by the daemon.
func newAgentTimewait(t *testing.T, f *handoffFixture, root string) *agentTimewait {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(tcpModeObject(t, "VTEP_RETURN_TIMEWAIT_PACKET_OBJECT"))
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != "tw_capture_only" {
			delete(spec.Programs, name)
		}
	}
	for name := range spec.Maps {
		if name != "tw_capture_ports" {
			delete(spec.Maps, name)
		}
	}
	spec.Variables = nil
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coll.Close)
	for _, name := range []string{"cilium_vtep_sock4", "vtep_tw_owners", "tw_packet_stats", "cilium_vtep_tw_proof4", "cilium_vtep_nonce4"} {
		m, err := ebpf.LoadPinnedMap(agentMapPin(t, root, name), nil)
		if err != nil {
			t.Fatal(err)
		}
		coll.Maps[name] = m
	}
	a := &agentTimewait{f: f, coll: coll, port: 47010}
	client, server := f.connect(t, 0, a.port)
	a.owner = ownerFromMap(t, coll.Maps["cilium_vtep_sock4"], server)
	_, a.fin, a.fd = closeTWConnection(t, f, coll, 0, a.port, client, server, a.owner)
	a.verify(t)
	return a
}

func (a *agentTimewait) verify(t *testing.T) {
	t.Helper()
	var record timewaitOwner
	if err := a.coll.Maps["vtep_tw_owners"].Lookup(a.owner.Cookie, &record); err != nil || record.Owner != a.owner {
		t.Fatalf("agent lost exact TIME-WAIT ownership: %v", err)
	}
	for {
		var buf [2048]byte
		_, _, err := unix.Recvfrom(a.fd, buf[:], 0)
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	before := readTWPacketStats(t, a.coll)
	replayTWPacket(t, a.f, 0, a.fd, a.fin)
	receiveTWACK(t, a.fd, a.port, binary.BigEndian.Uint32(a.fin[42:46]), binary.BigEndian.Uint32(a.fin[38:42])+1)
	after := readTWPacketStats(t, a.coll)
	if after.Scopes <= before.Scopes || after.Stamps <= before.Stamps {
		t.Fatalf("ACK did not traverse agent TIME-WAIT producers: before=%+v after=%+v", before, after)
	}
	var token uint64
	if err := a.coll.Maps["cilium_vtep_nonce4"].Lookup(a.f.cookie, &token); err != nil {
		t.Fatal(err)
	}
	if v, err := a.coll.Maps["cilium_vtep_tw_proof4"].LookupBytes(struct{ NS, Token uint64 }{a.f.cookie, token}); err != nil || v != nil {
		t.Fatalf("delivered ACK proof not consumed: %v", err)
	}
}

// Real FIN replay refreshes Linux's TIME-WAIT timer while the TCG daemon
// recompiles for more than 60 seconds. Do not fabricate lifetime/map state.
func (a *agentTimewait) keepAlive(t *testing.T) func() {
	t.Helper()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				_ = unix.Sendto(a.fd, a.fin, 0, &unix.SockaddrLinklayer{Ifindex: a.f.peerVTEP[0].Attrs().Index, Halen: 6, Protocol: wire16(unix.ETH_P_IP)})
			}
		}
	}()
	return func() { close(stop); <-done }
}

func (a *agentTimewait) verifyPeriodicGC(t *testing.T) {
	t.Helper()
	f := a.f
	q := netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: f.pod.remote.Attrs().Index, Parent: netlink.HANDLE_ROOT, Handle: netlink.MakeHandle(1, 0)}, netlink.NetemQdiscAttrs{Loss: 100, Limit: 64})
	if err := f.podNS.Do(func() error { return netlink.QdiscAdd(q) }); err != nil {
		t.Fatal(err)
	}
	defer f.podNS.Do(func() error { return netlink.QdiscDel(q) })
	before := readTWPacketStats(t, a.coll)
	replayTWPacket(t, f, 0, a.fd, a.fin)
	waitHandoff(t, func() bool { return readTWPacketStats(t, a.coll).Stamps > before.Stamps })
	key, err := a.coll.Maps["cilium_vtep_tw_proof4"].NextKeyBytes(nil)
	if err != nil || key == nil {
		t.Fatalf("lost packet has no proof: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		v, err := a.coll.Maps["cilium_vtep_tw_proof4"].LookupBytes(key)
		if err != nil {
			t.Fatal(err)
		}
		if v == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual agent did not collect expired proof")
		}
		time.Sleep(100 * time.Millisecond)
	}
	var record timewaitOwner
	if err := a.coll.Maps["vtep_tw_owners"].Lookup(a.owner.Cookie, &record); err != nil || record.Owner != a.owner {
		t.Fatalf("periodic proof GC changed live TIME-WAIT owner: %v", err)
	}
}

func assertAgentGraph(t *testing.T, before, after agentAffinityGraph) {
	t.Helper()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("restart changed canonical map/link identities: before=%+v after=%+v", before, after)
	}
}

func assertAgentGraphRemoved(t *testing.T, graph agentAffinityGraph) {
	t.Helper()
	if _, err := os.Stat(graph.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disabled agent retained runtime graph: %v", err)
	}
	for name, id := range graph.Links {
		l, err := link.NewFromID(id)
		if err == nil {
			l.Close()
			t.Fatalf("disabled agent retained tracing hook %s", name)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("query removed hook %s: %v", name, err)
		}
	}
}
