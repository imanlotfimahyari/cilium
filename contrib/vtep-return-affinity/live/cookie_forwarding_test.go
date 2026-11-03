// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/datapath/vtep/returnaffinity"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type cookieForwardStats struct{ Issued, Bound, Rejected, Pressure uint64 }

func cookieForwardingFixture(t *testing.T, mapped bool) (*handoffFixture, *ebpf.Collection) {
	t.Helper()
	f := newHandoffListenerFixture(t, tcpModeObject(t, "VTEP_RETURN_COOKIE_CORE_OBJECT"), mapped)
	spec, err := ebpf.LoadCollectionSpec(tcpModeObject(t, "VTEP_RETURN_COOKIE_RUNTIME_OBJECT"))
	if err != nil {
		t.Fatal(err)
	}
	if err := returnaffinity.ConfigureTimewaitTarget(spec); err != nil {
		t.Fatal(err)
	}
	if err := spec.Variables["vtep_queue_cookie"].Set(f.cookie); err != nil {
		t.Fatal(err)
	}
	replacements := map[string]*ebpf.Map{}
	for name, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
		if existing := f.collection.Maps[name]; existing != nil && !strings.HasPrefix(name, ".") {
			replacements[name] = existing
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements})
	if err != nil {
		t.Fatalf("cookie runtime verifier: %+v", err)
	}
	t.Cleanup(coll.Close)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("cookie producer counters: %+v", readCookieForwardStats(t, coll))
		}
	})
	// Release/child hooks precede issuance. No managed agent is simulated here.
	for _, name := range []string{"vtep_tw_destroy", "tw_packet_release", "tw_ack_exit", "tw_packet_created", "vtep_tw_transfer", "tw_ack_enter", "ck_child_created", "ck_synack_created"} {
		l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		t.Cleanup(func() { l.Close() })
	}
	if err := f.attachments["handoff_before_queue"].Update(coll.Programs["cil_vtep_before_queue"]); err != nil {
		t.Fatal(err)
	}
	if err := f.podNS.Do(func() error {
		l, err := link.AttachTCX(link.TCXOptions{Interface: f.pod.remote.Attrs().Index,
			Program: coll.Programs["cil_vtep_cookie_ingress"], Attach: ebpf.AttachTCXIngress, Anchor: link.Head()})
		if err == nil {
			t.Cleanup(func() { l.Close() })
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.podNS.Do(func() error {
		return os.WriteFile("/proc/sys/net/ipv4/tcp_syncookies", []byte("2"), 0600)
	}); err != nil {
		t.Fatal(err)
	}
	return f, coll
}

func readCookieForwardStats(t *testing.T, coll *ebpf.Collection) cookieForwardStats {
	t.Helper()
	var stats cookieForwardStats
	if err := coll.Maps["vtep_ck_stats"].Lookup(uint32(0), &stats); err != nil {
		t.Fatal(err)
	}
	return stats
}

func TestPrivilegedCookieVXLANForwarding(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("mapped=%v", mapped), func(t *testing.T) {
			f, coll := cookieForwardingFixture(t, mapped)
			before := cookieCounter(t, f.podNS, "SyncookiesRecv")
			clientA, serverA := f.connect(t, 0, 49200)
			clientB, serverB := f.connect(t, 1, 49201)
			ownerA, ownerB := f.owner(t, serverA), f.owner(t, serverB)
			if ownerA.Peer != wireIP(f.under[0].ip) || ownerB.Peer != wireIP(f.under[1].ip) ||
				ownerA.Cookie == ownerB.Cookie || cookieCounter(t, f.podNS, "SyncookiesRecv") < before+2 {
				t.Fatal("kernel cookie handshakes did not bind distinct actual peers")
			}
			stats := readCookieForwardStats(t, coll)
			if stats.Bound != 2 || stats.Issued < 2 || stats.Rejected != 0 || stats.Pressure != 0 {
				t.Fatalf("cookie handoff failed or bypassed its hooks: %+v", stats)
			}
			transferHandoff(t, clientA, serverA, "cookie-peer-A")
			transferHandoff(t, clientB, serverB, "cookie-peer-B")
			clearCoreCT(t, f)
			transferHandoff(t, clientA, serverA, "cookie-peer-A-after-CT-loss")
			transferHandoff(t, clientB, serverB, "cookie-peer-B-after-CT-loss")
			for _, name := range []string{"vtep_ck_child4", "cilium_vtep_ck_ack4", "ck_output_packet"} {
				if name == "vtep_ck_child4" {
					// Proof storage was consumed after immutable owner publication.
					raw, err := serverA.SyscallConn()
					if err != nil {
						t.Fatal(err)
					}
					raw.Control(func(fd uintptr) {
						var proof [56]byte
						err := coll.Maps[name].Lookup(uint32(fd), &proof)
						if err == nil || !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Error("child proof was not consumed", err)
						}
					})
					continue
				}
				if key, err := coll.Maps[name].NextKeyBytes(nil); err != nil || key != nil {
					t.Fatal("cookie transient handoff leaked", name, err)
				}
			}
			// A valid cookie-shaped ACK through another configured peer must
			// fail the post-policy peer check, not borrow A's immutable owner.
			var ledgerKey cookiePeerKey
			var ledgerRecord cookiePeerRecord
			it := coll.Maps["cookie_peer_ledger"].Iterate()
			found := false
			for it.Next(&ledgerKey, &ledgerRecord) {
				if ledgerRecord.Peer == ownerA.Peer {
					found = true
					break
				}
			}
			if err := it.Err(); err != nil || !found {
				t.Fatal("missing consumed cookie history", err)
			}
			fd, err := packetSocket(f.peerNS[1], f.peerVTEP[1])
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			packet := resilienceFrame(f.peerVTEP[1].Attrs().HardwareAddr, f.nodeVTEP.Attrs().HardwareAddr,
				net.ParseIP("203.0.113.9"), f.pod.ip, 49200, 8080, 0x10, nil, nil)
			binary.BigEndian.PutUint32(packet[38:42], ledgerKey.ClientISN+1)
			binary.BigEndian.PutUint32(packet[42:46], ledgerKey.ServerISN+1)
			finishTCPChecksums(packet)
			drops := coreDirectionalDrops(t, f, 134, 1)
			if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: f.peerVTEP[1].Attrs().Index, Halen: 6}); err != nil {
				t.Fatal(err)
			}
			waitHandoff(t, func() bool { return coreDirectionalDrops(t, f, 134, 1) > drops })
			if f.owner(t, serverA) != ownerA || f.owner(t, serverB) != ownerB || readCookieForwardStats(t, coll).Bound != 2 {
				t.Fatal("cross-peer ACK retargeted or republished a socket")
			}
			transferHandoff(t, clientA, serverA, "after-cross-peer-replay")
			transferHandoff(t, clientB, serverB, "other-peer-after-replay")
		})
	}
}

func TestPrivilegedCookieIngressPolicyRejects(t *testing.T) {
	f, coll := cookieForwardingFixture(t, false)
	f.policy(t, 49210, 2) // Deny ingress, permit egress.
	before := readCookieForwardStats(t, coll)
	f.inject(t, 0, 49210, nil)
	time.Sleep(100 * time.Millisecond)
	if after := readCookieForwardStats(t, coll); after != before {
		t.Fatal("denied SYN reached cookie issuance", after)
	}
	if key, err := coll.Maps["cookie_peer_ledger"].NextKeyBytes(nil); err != nil || key != nil {
		t.Fatal("denied ingress created binding evidence", err)
	}
}

func cookieClock(t *testing.T, f *handoffFixture) uint64 {
	t.Helper()
	ret, out, err := f.collection.Programs["handoff_cookie_clock"].Test(make([]byte, 64))
	if err != nil || ret != 1 {
		t.Fatal("cookie jiffies clock sample", ret, err)
	}
	return binary.NativeEndian.Uint64(out[:8])
}

func TestPrivilegedCookieCollision(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("mapped=%v", mapped), func(t *testing.T) {
			f, coll := cookieForwardingFixture(t, mapped)
			client, server := f.connect(t, 0, 49220)
			owner := f.owner(t, server)
			fd, err := packetSocketProtocol(f.peerNS[0], f.peerVTEP[0], unix.ETH_P_ALL)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if err := unix.SetNonblock(fd, true); err != nil {
				t.Fatal(err)
			}
			var key cookiePeerKey
			var record cookiePeerRecord
			var collisionPort int
			quarantined := false
			for attempt := range 2 {
				port := 49221 + attempt
				collisionPort = port
				f.inject(t, 0, port, nil)
				var synack []byte
				waitHandoff(t, func() bool {
					var b [2048]byte
					n, _, err := unix.Recvfrom(fd, b[:], 0)
					if errors.Is(err, unix.EAGAIN) {
						return false
					}
					if err != nil {
						t.Fatal(err)
					}
					if n >= 54 && binary.BigEndian.Uint16(b[12:14]) == unix.ETH_P_IP && b[14] == 0x45 && b[23] == unix.IPPROTO_TCP &&
						binary.BigEndian.Uint16(b[34:36]) == 8080 && binary.BigEndian.Uint16(b[36:38]) == uint16(port) && b[47]&0x12 == 0x12 {
						synack = append([]byte(nil), b[:n]...)
						return true
					}
					return false
				})
				key = cookiePeerKey{Namespace: f.cookie, Generation: 1, Local: wireIP(f.pod.ip), Remote: wireIP(net.ParseIP("203.0.113.9")),
					LocalPort: wire16(8080), RemotePort: wire16(uint16(port)), ClientISN: uint32(port) * 100, ServerISN: binary.BigEndian.Uint32(synack[38:42])}
				if err := coll.Maps["cookie_peer_ledger"].Lookup(key, &record); err != nil || record.State != 1 || record.Peer != owner.Peer {
					t.Fatal("raw SYN did not acquire original trusted issuance", record, err)
				}
				before := readCookieForwardStats(t, coll)
				f.inject(t, 1, port, nil) // Same tuple, ISN, MSS and cookie epoch, another peer.
				waitHandoff(t, func() bool {
					a := readCookieForwardStats(t, coll)
					return a.Issued > before.Issued || a.Rejected > before.Rejected
				})
				if err := coll.Maps["cookie_peer_ledger"].Lookup(key, &record); err != nil {
					t.Fatal(err)
				}
				if record.State == 3 {
					quarantined = true
					break
				}
				if cookieClock(t, f)/60000 == record.Epoch {
					t.Fatal("same-epoch competing peer did not quarantine cookie")
				}
				t.Log("kernel cookie epoch changed between SYNs; using a fresh tuple for the collision precondition")
			}
			if !quarantined || record.Peer != owner.Peer {
				t.Fatal("could not establish a real same-cookie collision without overwriting the first peer")
			}
			drops := coreDirectionalDrops(t, f, 134, 1)
			for peer := range 2 {
				ackfd, err := packetSocket(f.peerNS[peer], f.peerVTEP[peer])
				if err != nil {
					t.Fatal(err)
				}
				packet := resilienceFrame(f.peerVTEP[peer].Attrs().HardwareAddr, f.nodeVTEP.Attrs().HardwareAddr,
					net.ParseIP("203.0.113.9"), f.pod.ip, uint16(collisionPort), 8080, 0x10, nil, nil)
				binary.BigEndian.PutUint32(packet[38:42], key.ClientISN+1)
				binary.BigEndian.PutUint32(packet[42:46], key.ServerISN+1)
				finishTCPChecksums(packet)
				err = unix.Sendto(ackfd, packet, 0, &unix.SockaddrLinklayer{Ifindex: f.peerVTEP[peer].Attrs().Index, Halen: 6})
				unix.Close(ackfd)
				if err != nil {
					t.Fatal(err)
				}
			}
			waitHandoff(t, func() bool { return coreDirectionalDrops(t, f, 134, 1) >= drops+2 })
			f.listener.SetDeadline(time.Now().Add(100 * time.Millisecond))
			unexpected, err := f.listener.AcceptTCP()
			if unexpected != nil {
				unexpected.Close()
				t.Fatal("ambiguous cookie reached an application socket")
			}
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() || readCookieForwardStats(t, coll).Bound != 1 || f.owner(t, server) != owner {
				t.Fatal("collision did not reject both ACKs or damaged established ownership", err)
			}
			transferHandoff(t, client, server, "existing-cookie-owner-after-collision")
		})
	}
}

func TestPrivilegedCookieACKPressureAndData(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("mapped=%v", mapped), func(t *testing.T) {
			f, coll := cookieForwardingFixture(t, mapped)
			client, server := f.connect(t, 0, 49230)
			owner := f.owner(t, server)
			unchanged, _ := occupyPressureMap(t, coll.Maps["cilium_vtep_ck_ack4"])
			var pending *net.TCPConn
			if err := f.peerNS[1].Do(func() error {
				d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 49231}}
				c, err := d.Dial("tcp4", "198.51.100.10:8080")
				if err == nil {
					pending = c.(*net.TCPConn)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			defer pending.Close()
			waitHandoff(t, func() bool { return readCookieForwardStats(t, coll).Pressure > 0 })
			f.listener.SetDeadline(time.Now().Add(100 * time.Millisecond))
			unexpected, err := f.listener.AcceptTCP()
			if unexpected != nil {
				unexpected.Close()
				t.Fatal("full ACK-ticket map created an application child")
			}
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() || readCookieForwardStats(t, coll).Bound != 1 {
				t.Fatal("ACK pressure did not refuse ownership", err)
			}
			unchanged()
			transferHandoff(t, client, server, "old-owner-during-cookie-ACK-pressure")
			if ret, _, err := coll.Programs["cil_vtep_collect"].Test(make([]byte, 64)); err != nil || ret != 0 {
				t.Fatal("real cookie collector", ret, err)
			}
			payload := "initial-cookie-ACK-with-application-data"
			pending.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.WriteString(pending, payload); err != nil {
				t.Fatal(err)
			}
			f.listener.SetDeadline(time.Now().Add(3 * time.Second))
			recovered, err := f.listener.AcceptTCP()
			if err != nil {
				t.Fatal("ACK-with-data did not recover after real GC", err)
			}
			defer recovered.Close()
			recovered.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(recovered, buf); err != nil || string(buf) != payload {
				t.Fatal("cookie ACK payload did not reach the bound child", err)
			}
			if f.owner(t, recovered).Peer != wireIP(f.under[1].ip) || f.owner(t, server) != owner || readCookieForwardStats(t, coll).Bound != 2 {
				t.Fatal("ACK-with-data bound the wrong peer or changed an old owner")
			}
			transferHandoff(t, pending, recovered, "cookie-ACK-data-reply-through-peer-B")
		})
	}
}

func cookieTCPInfo(t *testing.T, conn *net.TCPConn) *unix.TCPInfo {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var info *unix.TCPInfo
	var inspectErr error
	if err := raw.Control(func(fd uintptr) { info, inspectErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) }); err != nil {
		t.Fatal(err)
	}
	if inspectErr != nil {
		t.Fatal(inspectErr)
	}
	return info
}

func sendCookieACK(t *testing.T, f *handoffFixture, peer int, key cookiePeerKey) {
	t.Helper()
	fd, err := packetSocket(f.peerNS[peer], f.peerVTEP[peer])
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	packet := resilienceFrame(f.peerVTEP[peer].Attrs().HardwareAddr, f.nodeVTEP.Attrs().HardwareAddr,
		net.ParseIP("203.0.113.9"), f.pod.ip, wire16(key.RemotePort), 8080, 0x10, nil, nil)
	binary.BigEndian.PutUint32(packet[38:42], key.ClientISN+1)
	binary.BigEndian.PutUint32(packet[42:46], key.ServerISN+1)
	finishTCPChecksums(packet)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: f.peerVTEP[peer].Attrs().Index, Halen: 6}); err != nil {
		t.Fatal(err)
	}
}

func TestPrivilegedCookieConsumedReplay(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("mapped=%v", mapped), func(t *testing.T) {
			f, coll := cookieForwardingFixture(t, mapped)
			client, server := f.connect(t, 0, 49260)
			otherClient, otherServer := f.connect(t, 1, 49261)
			owner := f.owner(t, server)
			var key cookiePeerKey
			var record cookiePeerRecord
			it := coll.Maps["cookie_peer_ledger"].Iterate()
			found := false
			for it.Next(&key, &record) {
				if key.RemotePort == wire16(49260) {
					found = true
					break
				}
			}
			if err := it.Err(); err != nil || !found || record.State != 2 {
				t.Fatal("missing consumed real cookie history", record, err)
			}
			before := cookieTCPInfo(t, server).Segs_in
			sendCookieACK(t, f, 0, key)
			waitHandoff(t, func() bool { return cookieTCPInfo(t, server).Segs_in > before })
			if readCookieForwardStats(t, coll).Bound != 2 || f.owner(t, server) != owner {
				t.Fatal("duplicate ACK republished an existing owner")
			}
			if err := client.SetLinger(0); err != nil {
				t.Fatal(err)
			}
			client.Close()
			const tcpStateClose = 7 // Linux TCP_CLOSE.
			waitHandoff(t, func() bool { return cookieTCPInfo(t, server).State == tcpStateClose })
			rejected := readCookieForwardStats(t, coll).Rejected
			received := cookieCounter(t, f.podNS, "SyncookiesRecv")
			sendCookieACK(t, f, 0, key)
			waitHandoff(t, func() bool { return readCookieForwardStats(t, coll).Rejected > rejected })
			f.listener.SetDeadline(time.Now().Add(100 * time.Millisecond))
			unexpected, err := f.listener.AcceptTCP()
			if unexpected != nil {
				unexpected.Close()
				t.Fatal("consumed cookie replay created an unowned replacement child")
			}
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() || cookieCounter(t, f.podNS, "SyncookiesRecv") != received ||
				readCookieForwardStats(t, coll).Bound != 2 || f.owner(t, server) != owner {
				t.Fatal("stale replay entered kernel cookie creation or changed retained ownership", err)
			}
			transferHandoff(t, otherClient, otherServer, "other-live-peer-after-consumed-cookie-replay")
		})
	}
}

func TestPrivilegedCookieLedgerPressureAndRealExpiry(t *testing.T) {
	f, coll := cookieForwardingFixture(t, false)
	var clients, servers [8]*net.TCPConn
	var owners [8]handoffOwner
	for i := range clients {
		clients[i], servers[i] = f.connect(t, i%2, 49240+i)
		owners[i] = f.owner(t, servers[i])
		f.noPending(t)
	}
	saved := map[cookiePeerKey]cookiePeerRecord{}
	var key cookiePeerKey
	var value cookiePeerRecord
	it := coll.Maps["cookie_peer_ledger"].Iterate()
	var maximumExpiry uint64
	for it.Next(&key, &value) {
		if value.State != 2 {
			t.Fatal("expected only consumed real cookie tombstones")
		}
		saved[key] = value
		maximumExpiry = max(maximumExpiry, value.Expires)
	}
	if err := it.Err(); err != nil || len(saved) != 8 || readCookieForwardStats(t, coll).Bound != 8 {
		t.Fatal("did not fill ledger with eight legitimate bound connections", err)
	}
	before := readCookieForwardStats(t, coll)
	err := f.peerNS[1].Do(func() error {
		d := net.Dialer{Timeout: 300 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 49248}}
		c, err := d.Dial("tcp4", "198.51.100.10:8080")
		if c != nil {
			c.Close()
		}
		return err
	})
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || readCookieForwardStats(t, coll).Rejected <= before.Rejected {
		t.Fatal("full real-cookie ledger did not reject the ninth handshake", err)
	}
	collect := func() {
		t.Helper()
		if ret, _, err := coll.Programs["cil_vtep_collect"].Test(make([]byte, 64)); err != nil || ret != 0 {
			t.Fatal("real cookie GC", ret, err)
		}
	}
	// Do not shorten timestamps or delete records to simulate expiry. Wait
	// through the real kernel's two-epoch acceptance window, retaining flows.
	deadline := time.Now().Add(130 * time.Second)
	nextTransfer := time.Time{}
	for cookieClock(t, f) < maximumExpiry {
		collect()
		for k, original := range saved {
			var actual cookiePeerRecord
			err := coll.Maps["cookie_peer_ledger"].Lookup(k, &actual)
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				if cookieClock(t, f) < original.Expires {
					t.Fatal("GC removed a still-valid cookie incarnation")
				}
			} else if err != nil || actual != original {
				t.Fatal("pressure or GC changed a retained cookie peer", err)
			}
		}
		if time.Now().After(nextTransfer) {
			for i := range clients {
				if f.owner(t, servers[i]) != owners[i] {
					t.Fatal("live expiry wait retargeted established ownership")
				}
				transferHandoff(t, clients[i], servers[i], fmt.Sprintf("live-cookie-expiry-peer-%d", i))
			}
			t.Log("real kernel cookie window still active; all eight established flows preserved")
			nextTransfer = time.Now().Add(15 * time.Second)
		}
		if time.Now().After(deadline) {
			t.Fatal("real kernel cookie acceptance window exceeded reviewed bound")
		}
		time.Sleep(200 * time.Millisecond)
	}
	collect()
	if k, err := coll.Maps["cookie_peer_ledger"].NextKeyBytes(nil); err != nil || k != nil {
		t.Fatal("real expired tombstones were not reclaimed", err)
	}
	newClient, newServer := f.connect(t, 1, 49249)
	if f.owner(t, newServer).Peer != wireIP(f.under[1].ip) || readCookieForwardStats(t, coll).Bound != 9 {
		t.Fatal("new cookie admission did not recover through its original peer")
	}
	transferHandoff(t, newClient, newServer, "new-cookie-after-real-window-expiry")
	for i := range clients {
		if f.owner(t, servers[i]) != owners[i] {
			t.Fatal("ledger expiry discarded an established socket owner")
		}
		transferHandoff(t, clients[i], servers[i], "old-cookie-owner-after-ledger-GC")
	}
}

func TestPrivilegedCookiePacketPressure(t *testing.T) {
	f, coll := cookieForwardingFixture(t, false)
	client, server := f.connect(t, 0, 49270)
	owner := f.owner(t, server)
	unchanged, clear := occupyPressureMap(t, coll.Maps["ck_output_packet"])
	err := f.peerNS[1].Do(func() error {
		d := net.Dialer{Timeout: 300 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 49271}}
		c, err := d.Dial("tcp4", "198.51.100.10:8080")
		if c != nil {
			c.Close()
		}
		return err
	})
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || readCookieForwardStats(t, coll).Pressure == 0 {
		t.Fatal("full packet association map allowed an unproved SYN-ACK", err)
	}
	unchanged()
	transferHandoff(t, client, server, "cookie-owner-during-packet-association-pressure")
	clear() // Only disposable fake addresses; actual skb records use release cleanup.
	newClient, newServer := f.connect(t, 1, 49272)
	if f.owner(t, server) != owner || f.owner(t, newServer).Peer != wireIP(f.under[1].ip) {
		t.Fatal("packet pressure recovery changed peer ownership")
	}
	transferHandoff(t, newClient, newServer, "cookie-packet-association-recovered")
}

func TestPrivilegedCookieExistingTupleCannotBorrowPeer(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("mapped=%v", mapped), func(t *testing.T) {
			f, coll := cookieForwardingFixture(t, mapped)
			f.policy(t, 49280, 3)
			keys := [2]cookiePeerKey{}
			for peer := range 2 {
				if err := f.peerNS[peer].Do(func() error {
					l, err := link.AttachTCX(link.TCXOptions{Interface: f.peerVTEP[peer].Attrs().Index,
						Program: f.collection.Programs["handoff_cookie_no_reset"], Attach: ebpf.AttachTCXEgress})
					if err == nil {
						t.Cleanup(func() { l.Close() })
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				fd, err := packetSocketProtocol(f.peerNS[peer], f.peerVTEP[peer], unix.ETH_P_ALL)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fd)
				if err := unix.SetNonblock(fd, true); err != nil {
					t.Fatal(err)
				}
				mss := []byte{2, 4, 2, 24} // MSS 536; peer B requests 1460.
				if peer == 1 {
					mss = []byte{2, 4, 5, 180}
				}
				packet := resilienceFrame(f.peerVTEP[peer].Attrs().HardwareAddr, f.nodeVTEP.Attrs().HardwareAddr,
					net.ParseIP("203.0.113.9"), f.pod.ip, 49280, 8080, 0x02, mss, nil)
				if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: f.peerVTEP[peer].Attrs().Index, Halen: 6}); err != nil {
					t.Fatal(err)
				}
				waitHandoff(t, func() bool {
					var b [2048]byte
					n, _, err := unix.Recvfrom(fd, b[:], 0)
					if errors.Is(err, unix.EAGAIN) {
						return false
					}
					if err != nil {
						t.Fatal(err)
					}
					if n >= 54 && binary.BigEndian.Uint16(b[12:14]) == unix.ETH_P_IP && b[14] == 0x45 && b[23] == unix.IPPROTO_TCP &&
						binary.BigEndian.Uint16(b[34:36]) == 8080 && binary.BigEndian.Uint16(b[36:38]) == 49280 && b[47]&0x12 == 0x12 {
						keys[peer] = cookiePeerKey{Namespace: f.cookie, Generation: 1, Local: wireIP(f.pod.ip), Remote: wireIP(net.ParseIP("203.0.113.9")),
							LocalPort: wire16(8080), RemotePort: wire16(49280), ClientISN: 12345, ServerISN: binary.BigEndian.Uint32(b[38:42])}
						return true
					}
					return false
				})
			}
			if keys[0] == keys[1] {
				t.Fatal("different MSS offers did not establish distinct kernel cookie evidence")
			}
			sendCookieACK(t, f, 0, keys[0])
			f.listener.SetDeadline(time.Now().Add(3 * time.Second))
			server, err := f.listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			owner := f.owner(t, server)
			if owner.Peer != wireIP(f.under[0].ip) || readCookieForwardStats(t, coll).Bound != 1 {
				t.Fatal("first raw kernel cookie did not bind peer A")
			}
			before := readCookieForwardStats(t, coll).Rejected
			fd, err := packetSocket(f.peerNS[1], f.peerVTEP[1])
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			packet := resilienceFrame(f.peerVTEP[1].Attrs().HardwareAddr, f.nodeVTEP.Attrs().HardwareAddr,
				net.ParseIP("203.0.113.9"), f.pod.ip, 49280, 8080, 0x18, nil, []byte("foreign-cookie-ACK-data"))
			binary.BigEndian.PutUint32(packet[38:42], keys[1].ClientISN+1)
			binary.BigEndian.PutUint32(packet[42:46], keys[1].ServerISN+1)
			finishTCPChecksums(packet)
			if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: f.peerVTEP[1].Attrs().Index, Halen: 6}); err != nil {
				t.Fatal(err)
			}
			waitHandoff(t, func() bool { return readCookieForwardStats(t, coll).Rejected > before })
			server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, err = server.Read(make([]byte, 64))
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() || f.owner(t, server) != owner || readCookieForwardStats(t, coll).Bound != 1 {
				t.Fatal("peer B's independently issued cookie borrowed A's established tuple", err)
			}
		})
	}
}
