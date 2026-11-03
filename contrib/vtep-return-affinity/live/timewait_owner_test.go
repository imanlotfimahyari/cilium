// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/datapath/vtep/returnaffinity"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type timewaitOwner struct {
	Owner handoffOwner
	Flow  handoffFlow
}

type timewaitStats struct{ Transferred, Rejected, Freed uint64 }

// This experiment does not change forwarding. It tests the actual kernel
// full-socket -> TIME-WAIT handoff and final-reference destruction callbacks.
func TestPrivilegedTIMEWAITOwnershipLifetime(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		name := "AF_INET"
		if mapped {
			name = "mapped_AF_INET6"
		}
		t.Run(name, func(t *testing.T) { testTIMEWAITOwnershipLifetime(t, mapped) })
	}
}

func testTIMEWAITOwnershipLifetime(t *testing.T, mapped bool) {
	object := tcpModeObject(t, "VTEP_RETURN_TIMEWAIT_OBJECT")
	f := newHandoffListenerFixture(t, tcpModeObject(t, "VTEP_RETURN_HANDOFF_OBJECT"), mapped)
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := returnaffinity.ConfigureTimewaitTarget(spec); err != nil {
		t.Fatal(err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	replacements := make(map[string]*ebpf.Map)
	for name := range spec.Maps {
		if m := f.collection.Maps[name]; m != nil {
			replacements[name] = m
		}
	}
	load := func() *ebpf.Collection {
		t.Helper()
		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements})
		if err != nil {
			t.Fatalf("load TIME-WAIT lifetime hooks: %+v", err)
		}
		return coll
	}
	coll := load()
	defer func() { coll.Close() }()
	pins, err := os.MkdirTemp("/sys/fs/bpf", "vtep-timewait-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(pins)
	for _, name := range []string{"vtep_tw_owners", "vtep_tw_stats"} {
		if err := coll.Maps[name].Pin(filepath.Join(pins, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"vtep_tw_destroy", "vtep_tw_transfer"} {
		l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		if err := l.Pin(filepath.Join(pins, name)); err != nil {
			l.Close()
			t.Fatal(err)
		}
		l.Close() // bpffs pins, not these descriptors, now preserve the hooks.
	}
	owners := coll.Maps["vtep_tw_owners"]
	lookup := func(cookie uint64) (timewaitOwner, error) {
		var record timewaitOwner
		err := owners.Lookup(cookie, &record)
		return record, err
	}
	assertOwner := func(owner handoffOwner, port int) {
		t.Helper()
		record, err := lookup(owner.Cookie)
		if err != nil || record.Owner != owner || record.Flow.Pod != wireIP(f.pod.ip) ||
			record.Flow.PodPort != wire16(8080) || record.Flow.ClientPort != wire16(uint16(port)) || record.Flow.Sequence != 0 {
			t.Fatalf("TIME-WAIT incarnation lost exact socket ownership: record=%+v owner=%+v err=%v", record, owner, err)
		}
	}
	closeToTIMEWAIT := func(peer, port int, capture bool) (handoffOwner, []byte) {
		t.Helper()
		client, server := f.connect(t, peer, port)
		owner := f.owner(t, server)
		var fd = -1
		if capture {
			var err error
			fd, err = packetSocketProtocol(f.peerNS[peer], f.peerVTEP[peer], unix.ETH_P_ALL)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if err := unix.SetNonblock(fd, true); err != nil {
				t.Fatal(err)
			}
		}
		if err := server.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		client.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("server FIN: %v", err)
		}
		if err := client.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		server.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := server.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("client FIN: %v", err)
		}
		var fin []byte
		if capture {
			waitHandoff(t, func() bool {
				b := make([]byte, 2048)
				n, _, err := unix.Recvfrom(fd, b, 0)
				if errors.Is(err, unix.EAGAIN) {
					return false
				}
				if err != nil {
					t.Fatal(err)
				}
				if n >= 54 && b[14]>>4 == 4 && binary.BigEndian.Uint16(b[34:36]) == uint16(port) && b[47]&1 != 0 {
					fin = append([]byte(nil), b[:n]...)
					return true
				}
				return false
			})
		}
		// Closing the original FD must not prematurely delete TIME-WAIT state.
		server.Close()
		client.Close()
		return owner, fin
	}

	first, fin := closeToTIMEWAIT(0, 48200, true)
	waitHandoff(t, func() bool { _, err := lookup(first.Cookie); return err == nil })
	assertOwner(first, 48200)

	// Close the experiment's collection/map FDs, then reopen the pinned maps
	// and hooks. Restart reuses the existing tracing programs without detach.
	// This link implementation cannot Update tracing programs in place;
	// replacing their code is a separate, unvalidated rollout operation.
	beforeInfo, err := owners.Info()
	if err != nil {
		t.Fatal(err)
	}
	beforeID, _ := beforeInfo.ID()
	coll.Close()
	for _, name := range []string{"vtep_tw_owners", "vtep_tw_stats"} {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pins, name), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		replacements[name] = m
	}
	coll = load()
	owners = coll.Maps["vtep_tw_owners"]
	afterInfo, err := owners.Info()
	if err != nil {
		t.Fatal(err)
	}
	if afterID, _ := afterInfo.ID(); afterID != beforeID {
		t.Fatal("pinned TIME-WAIT owner map was replaced")
	}
	for _, name := range []string{"vtep_tw_destroy", "vtep_tw_transfer"} {
		l, err := link.LoadPinnedLink(filepath.Join(pins, name), nil)
		if err != nil {
			t.Fatal(err)
		}
		info, err := l.Info()
		l.Close()
		if err != nil || info.Tracing() == nil || ebpf.AttachType(info.Tracing().AttachType) != ebpf.AttachTraceFEntry {
			t.Fatalf("pinned tracing hook changed: %s info=%+v err=%v", name, info, err)
		}
	}
	assertOwner(first, 48200)

	var saved []handoffOwner
	for i := range 7 {
		peer := i % 2
		if i == 6 {
			peer = -1 // Explicit native ownership must survive the same handoff.
		}
		owner, _ := closeToTIMEWAIT(peer, 48201+i, false)
		assertOwner(owner, 48201+i)
		saved = append(saved, owner)
	}
	// Plain non-evicting hash: a ninth TIME-WAIT handoff cannot replace an
	// existing owner. Forwarding remains fail-closed, including this case.
	full, _ := closeToTIMEWAIT(1, 48208, false)
	if _, err := lookup(full.Cookie); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("over-capacity handoff unexpectedly retained: %v", err)
	}
	assertOwner(first, 48200)
	for i, owner := range saved {
		assertOwner(owner, 48201+i)
	}
	var stats timewaitStats
	if err := coll.Maps["vtep_tw_stats"].Lookup(uint32(0), &stats); err != nil || stats.Transferred != 8 || stats.Rejected != 1 {
		t.Fatalf("handoff/capacity evidence: %+v err=%v", stats, err)
	}

	// Under the kernel's normal RFC1337=0 behavior an in-window RST destroys
	// TIME-WAIT. This tests actual final-reference cleanup without a 60s wait,
	// a timer guess, forced map deletion or calling a BPF test adapter.
	if err := f.podNS.Do(func() error { return os.WriteFile("/proc/sys/net/ipv4/tcp_rfc1337", []byte("0"), 0600) }); err != nil {
		t.Fatal(err)
	}
	reset := append([]byte(nil), fin...)
	ip := reset[14:]
	ihl := int(ip[0]&15) * 4
	tcp := ip[ihl:]
	binary.BigEndian.PutUint32(tcp[4:8], binary.BigEndian.Uint32(tcp[4:8])+1)
	tcp[13] = 4 // RST, at the sequence immediately after the client's FIN.
	finishTCPChecksums(reset)
	fd, err := packetSocketProtocol(f.peerNS[0], f.peerVTEP[0], unix.ETH_P_ALL)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Sendto(fd, reset, 0, &unix.SockaddrLinklayer{Ifindex: f.peerVTEP[0].Attrs().Index, Halen: 6, Protocol: wire16(unix.ETH_P_IP)}); err != nil {
		t.Fatal(err)
	}
	waitHandoff(t, func() bool { _, err := lookup(first.Cookie); return errors.Is(err, ebpf.ErrKeyNotExist) })
	for i, owner := range saved {
		assertOwner(owner, 48201+i)
	}
	second, _ := closeToTIMEWAIT(1, 48200, false) // Exact tuple reused through another outer peer.
	if second.Cookie == first.Cookie || second.Peer != wireIP(f.under[1].ip) {
		t.Fatal("reused tuple inherited an old incarnation")
	}
	assertOwner(second, 48200)
	if _, err := lookup(first.Cookie); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal("reused tuple resurrected the old owner")
	}
	if err := coll.Maps["vtep_tw_stats"].Lookup(uint32(0), &stats); err != nil || stats.Transferred != 9 || stats.Freed != 1 || stats.Rejected != 1 {
		t.Fatalf("final lifetime evidence: %+v err=%v", stats, err)
	}
	t.Log("verified pre-publication transfer, FD-independent lifetime, pinned reload, non-evicting pressure, actual destruction and cross-peer exact tuple reuse")
}

// Packet taps can expose CHECKSUM_PARTIAL. Finalize both checksums before replay.
func finishTCPChecksums(frame []byte) {
	ip := frame[14:]
	ihl, total := int(ip[0]&15)*4, int(binary.BigEndian.Uint16(ip[2:4]))
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:ihl]))
	tcp := ip[ihl:total]
	tcp[16], tcp[17] = 0, 0
	pseudo := append([]byte(nil), ip[12:20]...)
	pseudo = append(pseudo, 0, unix.IPPROTO_TCP, byte(len(tcp)>>8), byte(len(tcp)))
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
}
