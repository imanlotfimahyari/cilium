// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"time"

	"github.com/cilium/cilium/pkg/datapath/vtep/returnaffinity"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type twPacketStats struct{ Scopes, Packets, Stamps, Tunnel, Native, Denied, Pressure uint64 }

func attachTIMEWAITPackets(t *testing.T, f *handoffFixture) *ebpf.Collection {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(tcpModeObject(t, "VTEP_RETURN_TIMEWAIT_PACKET_OBJECT"))
	if err != nil {
		t.Fatal(err)
	}
	if err := returnaffinity.ConfigureTimewaitTarget(spec); err != nil {
		t.Fatal(err)
	}
	replacements := make(map[string]*ebpf.Map)
	for name, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
		if existing := f.collection.Maps[name]; existing != nil && name[0] != '.' {
			replacements[name] = existing
		}
	}
	var mac [6]byte
	copy(mac[:], f.pod.remote.Attrs().HardwareAddr)
	for name, value := range map[string]any{"tw_netns_cookie": f.cookie,
		"tw_tunnel_ifindex": uint32(f.nodeVTEP.Attrs().Index), "tw_pod_mac": mac} {
		if err := spec.Variables[name].Set(value); err != nil {
			t.Fatal(err)
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements})
	if err != nil {
		t.Fatalf("load exact-packet TIME-WAIT experiment: %+v", err)
	}
	t.Cleanup(coll.Close)
	// Cleanup and exits precede producers; no test connection exists yet.
	for _, name := range []string{"vtep_tw_destroy", "tw_packet_release", "tw_ack_exit", "tw_packet_created", "vtep_tw_transfer", "tw_ack_enter"} {
		l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		t.Cleanup(func() { l.Close() })
	}
	if err := f.podNS.Do(func() error {
		l, err := link.AttachTCX(link.TCXOptions{Interface: f.pod.remote.Attrs().Index,
			Program: coll.Programs["tw_stamp"], Attach: ebpf.AttachTCXEgress, Anchor: link.Head()})
		if err == nil {
			t.Cleanup(func() { l.Close() })
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if f.core {
		if f.collection.Maps["cilium_vtep_tw_proof4"] == nil {
			t.Fatal("actual endpoint fixture does not enable TIME-WAIT proofs")
		}
		return coll
	}
	if err := f.router.Do(func() error {
		l, err := link.AttachTCX(link.TCXOptions{Interface: f.pod.host.Attrs().Index,
			Program: coll.Programs["tw_route"], Attach: ebpf.AttachTCXIngress, Anchor: link.Head()})
		if err == nil {
			t.Cleanup(func() { l.Close() })
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return coll
}

func readTWPacketStats(t *testing.T, coll *ebpf.Collection) twPacketStats {
	t.Helper()
	var stats twPacketStats
	var runtime struct{ Scopes, Packets, Stamps, Pressure uint64 }
	if err := coll.Maps["tw_packet_stats"].Lookup(uint32(0), &runtime); err != nil {
		t.Fatal(err)
	}
	stats.Scopes, stats.Packets, stats.Stamps, stats.Pressure = runtime.Scopes, runtime.Packets, runtime.Stamps, runtime.Pressure
	if m := coll.Maps["tw_route_stats"]; m != nil {
		var route struct{ Tunnel, Native, Denied uint64 }
		if err := m.Lookup(uint32(0), &route); err != nil {
			t.Fatal(err)
		}
		stats.Tunnel, stats.Native, stats.Denied = route.Tunnel, route.Native, route.Denied
	}
	return stats
}

// Create real TIME-WAIT state and retain a checksummed client FIN for replay.
func closeTWPacket(t *testing.T, f *handoffFixture, coll *ebpf.Collection, peer, port int) (handoffOwner, []byte, int) {
	t.Helper()
	client, server := f.connect(t, peer, port)
	owner := f.owner(t, server)
	return closeTWConnection(t, f, coll, peer, port, client, server, owner)
}

func closeTWConnection(t *testing.T, f *handoffFixture, coll *ebpf.Collection, peer, port int, client, server *net.TCPConn, owner handoffOwner) (handoffOwner, []byte, int) {
	t.Helper()
	ns, iface := f.nativeNS, f.native.remote
	if peer >= 0 {
		ns, iface = f.peerNS[peer], f.peerVTEP[peer]
	}
	fd, err := packetSocketProtocol(ns, iface, unix.ETH_P_ALL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
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
	waitHandoff(t, func() bool {
		var record timewaitOwner
		return coll.Maps["vtep_tw_owners"].Lookup(owner.Cookie, &record) == nil && record.Owner == owner
	})
	var fin []byte
	waitHandoff(t, func() bool {
		buf := make([]byte, 2048)
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if errors.Is(err, unix.EAGAIN) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		if n < 54 || buf[14]>>4 != 4 || binary.BigEndian.Uint16(buf[34:36]) != uint16(port) || buf[47]&1 == 0 {
			return false
		}
		fin = append([]byte(nil), buf[:n]...)
		return true
	})
	finishTCPChecksums(fin)
	// Wait for the final close ACK to reach the still-open client. Closing
	// its FD earlier can cause FIN retransmissions or a stray RST, while a
	// buffered original ACK can be mistaken for a later replay's result.
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	waitHandoff(t, func() bool {
		var info *unix.TCPInfo
		var infoErr error
		if err := raw.Control(func(fd uintptr) {
			info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		}); err != nil {
			t.Fatal(err)
		}
		if infoErr != nil {
			t.Fatal(infoErr)
		}
		return info.State == 7 // Linux TCP_CLOSE after the final ACK.
	})
	client.Close()
	server.Close()
	// Packet taps see actual decapsulated delivery before this receiver sink.
	// Suppress a closed old client's automatic RST, which would demonstrate
	// the already documented lack of peer-specific TCP namespaces instead.
	if err := coll.Maps["tw_capture_ports"].Update(uint32(port), uint32(1), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := ns.Do(func() error {
		l, err := link.AttachTCX(link.TCXOptions{Interface: iface.Attrs().Index,
			Program: coll.Programs["tw_capture_only"], Attach: ebpf.AttachTCXIngress, Anchor: link.Head()})
		if err == nil {
			t.Cleanup(func() { l.Close() })
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for {
		var old [2048]byte
		_, _, err := unix.Recvfrom(fd, old[:], 0)
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return owner, fin, fd
}

func replayTWPacket(t *testing.T, f *handoffFixture, peer, fd int, frame []byte) {
	t.Helper()
	iface := f.native.remote
	if peer >= 0 {
		iface = f.peerVTEP[peer]
	}
	if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: iface.Attrs().Index, Halen: 6, Protocol: wire16(unix.ETH_P_IP)}); err != nil {
		t.Fatal(err)
	}
}

func receiveTWACK(t *testing.T, fd, port int, seq, ack uint32) {
	t.Helper()
	waitHandoff(t, func() bool {
		buf := make([]byte, 2048)
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if errors.Is(err, unix.EAGAIN) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		return n >= 54 && buf[14] == 0x45 && binary.BigEndian.Uint16(buf[34:36]) == 8080 &&
			binary.BigEndian.Uint16(buf[36:38]) == uint16(port) && buf[47] == 0x10 &&
			binary.BigEndian.Uint32(buf[38:42]) == seq && binary.BigEndian.Uint32(buf[42:46]) == ack
	})
}

func TestPrivilegedTIMEWAITExactPacket(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		name := "AF_INET"
		if mapped {
			name = "mapped_AF_INET6"
		}
		t.Run(name, func(t *testing.T) {
			tcpModeObject(t, "VTEP_RETURN_TIMEWAIT_PACKET_OBJECT")
			f := newHandoffListenerFixture(t, tcpModeObject(t, "VTEP_RETURN_HANDOFF_OBJECT"), mapped)
			coll := attachTIMEWAITPackets(t, f)
			defer func() {
				if t.Failed() {
					t.Logf("TIME-WAIT packet evidence: %+v; baseline=%+v", readTWPacketStats(t, coll), f.counts(t))
				}
			}()
			for i, peer := range []int{0, 1, -1} {
				port := 48300 + i
				_, fin, fd := closeTWPacket(t, f, coll, peer, port)
				before := readTWPacketStats(t, coll)
				replayTWPacket(t, f, peer, fd, fin)
				waitHandoff(t, func() bool { a := readTWPacketStats(t, coll); return a.Tunnel+a.Native > before.Tunnel+before.Native })
				after := readTWPacketStats(t, coll)
				if after.Scopes <= before.Scopes || after.Packets <= before.Packets || after.Stamps <= before.Stamps ||
					(peer >= 0 && after.Tunnel <= before.Tunnel) || (peer < 0 && after.Native <= before.Native) {
					t.Fatalf("missing handoff stage: before=%+v after=%+v", before, after)
				}
				receiveTWACK(t, fd, port, binary.BigEndian.Uint32(fin[42:46]), binary.BigEndian.Uint32(fin[38:42])+1)
			}
			t.Logf("actual TIME-WAIT ACKs reached both original VXLAN peers and native client: %+v", readTWPacketStats(t, coll))
		})
	}
}

func TestPrivilegedTIMEWAITPacketPolicyAndLoss(t *testing.T) {
	tcpModeObject(t, "VTEP_RETURN_TIMEWAIT_PACKET_OBJECT")
	f := newHandoffFixture(t, tcpModeObject(t, "VTEP_RETURN_HANDOFF_OBJECT"))
	coll := attachTIMEWAITPackets(t, f)
	owner, fin, fd := closeTWPacket(t, f, coll, 0, 48310)
	before := readTWPacketStats(t, coll)
	f.policy(t, 48310, 1) // Ingress remains allowed, egress is denied.
	replayTWPacket(t, f, 0, fd, fin)
	waitHandoff(t, func() bool { return readTWPacketStats(t, coll).Denied > before.Denied })
	if after := readTWPacketStats(t, coll); after.Tunnel != before.Tunnel {
		t.Fatal("proof bypassed egress denial")
	}
	f.policy(t, 48310, 3)
	replayTWPacket(t, f, 0, fd, fin)
	waitHandoff(t, func() bool { return readTWPacketStats(t, coll).Tunnel > before.Tunnel })
	if err := coll.Maps["vtep_tw_owners"].Delete(owner.Cookie); err != nil {
		t.Fatal(err)
	}
	before = readTWPacketStats(t, coll)
	drops := f.counts(t).ReplyDrop
	replayTWPacket(t, f, 0, fd, fin)
	waitHandoff(t, func() bool { return f.counts(t).ReplyDrop > drops })
	if after := readTWPacketStats(t, coll); after.Tunnel != before.Tunnel || after.Stamps != before.Stamps {
		t.Fatal("lost ownership guessed a replacement")
	}
	t.Log("synthetic egress denial enforced; loss of the authoritative owner fails closed")
}

func TestPrivilegedTIMEWAITQueuedTupleReuse(t *testing.T) {
	tcpModeObject(t, "VTEP_RETURN_TIMEWAIT_PACKET_OBJECT")
	f := newHandoffFixture(t, tcpModeObject(t, "VTEP_RETURN_HANDOFF_OBJECT"))
	coll := attachTIMEWAITPackets(t, f)
	owner, fin, fd := closeTWPacket(t, f, coll, 0, 48320)
	qdisc := netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: f.pod.remote.Attrs().Index, Parent: netlink.HANDLE_ROOT, Handle: netlink.MakeHandle(1, 0)}, netlink.NetemQdiscAttrs{Latency: 600_000, Limit: 64})
	if err := f.podNS.Do(func() error { return netlink.QdiscAdd(qdisc) }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.podNS.Do(func() error { return netlink.QdiscDel(qdisc) }) })
	before := readTWPacketStats(t, coll)
	replayTWPacket(t, f, 0, fd, fin)
	waitHandoff(t, func() bool { return readTWPacketStats(t, coll).Stamps > before.Stamps })
	if after := readTWPacketStats(t, coll); after.Tunnel != before.Tunnel {
		t.Fatal("ACK was not actually held before host forwarding")
	}
	// The queued packet has its own nonce and copied original owner. Kernel
	// destruction and a new connection must not reinterpret that old packet.
	reset := append([]byte(nil), fin...)
	binary.BigEndian.PutUint32(reset[38:42], binary.BigEndian.Uint32(reset[38:42])+1)
	reset[47] = 4
	finishTCPChecksums(reset)
	replayTWPacket(t, f, 0, fd, reset)
	waitHandoff(t, func() bool {
		var v timewaitOwner
		return errors.Is(coll.Maps["vtep_tw_owners"].Lookup(owner.Cookie, &v), ebpf.ErrKeyNotExist)
	})
	// Netem preserves the existing skb's scheduled release while subsequent
	// handshakes use zero delay. Verify overtaking rather than assuming it.
	fast := netlink.NewNetem(qdisc.QdiscAttrs, netlink.NetemQdiscAttrs{Limit: 64})
	if err := f.podNS.Do(func() error { return netlink.QdiscChange(fast) }); err != nil {
		t.Fatal(err)
	}
	newClient, newServer := f.connect(t, 1, 48320)
	newOwner := f.owner(t, newServer)
	if newOwner.Cookie == owner.Cookie || newOwner.Peer != wireIP(f.under[1].ip) {
		t.Fatal("replacement inherited TIME-WAIT owner")
	}
	if after := readTWPacketStats(t, coll); after.Tunnel != before.Tunnel {
		t.Fatal("old ACK was released before replacement; queue precondition not established")
	}
	waitHandoff(t, func() bool { return readTWPacketStats(t, coll).Tunnel > before.Tunnel })
	receiveTWACK(t, fd, 48320, binary.BigEndian.Uint32(fin[42:46]), binary.BigEndian.Uint32(fin[38:42])+1)
	if f.owner(t, newServer) != newOwner {
		t.Fatal("delayed ACK changed replacement owner")
	}
	transferHandoff(t, newClient, newServer, "replacement-survives-delayed-old-ACK")
	t.Log("old queued ACK retained its original peer after kernel TIME-WAIT destruction and exact cross-peer tuple reuse")
}

func TestPrivilegedTIMEWAITLostPacketProofCleanup(t *testing.T) {
	tcpModeObject(t, "VTEP_RETURN_TIMEWAIT_PACKET_OBJECT")
	f := newHandoffFixture(t, tcpModeObject(t, "VTEP_RETURN_HANDOFF_OBJECT"))
	coll := attachTIMEWAITPackets(t, f)
	owner, fin, fd := closeTWPacket(t, f, coll, 0, 48330)
	qdisc := netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: f.pod.remote.Attrs().Index,
		Parent: netlink.HANDLE_ROOT, Handle: netlink.MakeHandle(1, 0)}, netlink.NetemQdiscAttrs{Loss: 100, Limit: 64})
	if err := f.podNS.Do(func() error { return netlink.QdiscAdd(qdisc) }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.podNS.Do(func() error { return netlink.QdiscDel(qdisc) }) })
	before := readTWPacketStats(t, coll)
	replayTWPacket(t, f, 0, fd, fin)
	waitHandoff(t, func() bool { return readTWPacketStats(t, coll).Stamps > before.Stamps })
	key, err := coll.Maps["cilium_vtep_tw_proof4"].NextKeyBytes(nil)
	if err != nil || key == nil {
		t.Fatalf("lost packet left no outstanding proof: %v", err)
	}
	// Expiry reclaims a lost packet's proof, never the live TIME-WAIT owner.
	time.Sleep(10*time.Second + 50*time.Millisecond)
	if ret, _, err := coll.Programs["tw_collect_proofs"].Test(make([]byte, 64)); err != nil || ret != 0 {
		t.Fatalf("proof collection: ret=%d err=%v", ret, err)
	}
	if value, err := coll.Maps["cilium_vtep_tw_proof4"].LookupBytes(key); err != nil || value != nil {
		t.Fatalf("expired lost-packet proof survived collection: value=%v err=%v", value != nil, err)
	}
	var record timewaitOwner
	if err := coll.Maps["vtep_tw_owners"].Lookup(owner.Cookie, &record); err != nil || record.Owner != owner {
		t.Fatalf("packet collection affected kernel-incarnation ownership: %+v %v", record, err)
	}
	if after := readTWPacketStats(t, coll); after.Tunnel != before.Tunnel {
		t.Fatal("netem loss precondition was not established")
	}
	t.Log("expired lost-packet proof reclaimed independently of surviving kernel TIME-WAIT owner")
}
