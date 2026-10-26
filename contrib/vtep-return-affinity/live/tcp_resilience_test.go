// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Construct checksummed wire packets, not CHECKSUM_PARTIAL packet-tap copies.
func resilienceFrame(source, destination net.HardwareAddr, sourceIP, destinationIP net.IP,
	sourcePort, destinationPort uint16, flags byte, options, payload []byte) []byte {
	packet := make([]byte, 54+len(options)+len(payload))
	copy(packet[:6], destination)
	copy(packet[6:12], source)
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
	ip, tcp := packet[14:34], packet[34:]
	ip[0], ip[8], ip[9] = 0x45, 64, unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(packet)-14))
	copy(ip[12:16], sourceIP.To4())
	copy(ip[16:20], destinationIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	binary.BigEndian.PutUint16(tcp[:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], 12345)
	tcp[12], tcp[13] = byte((20+len(options))/4)<<4, flags
	binary.BigEndian.PutUint16(tcp[14:16], 4096)
	copy(tcp[20:], options)
	copy(tcp[20+len(options):], payload)
	pseudo := append([]byte(nil), ip[12:20]...)
	pseudo = append(pseudo, 0, unix.IPPROTO_TCP, byte(len(tcp)>>8), byte(len(tcp)))
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	return packet
}

func TestPrivilegedUnsupportedTCPDoesNotBorrowOwner(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("mapped=%v", mapped), func(t *testing.T) {
			f := newHandoffListenerFixture(t, tcpModeObject(t, "VTEP_RETURN_CORE_OBJECT"), mapped)
			client, server := f.connect(t, 0, 48500)
			owner := f.owner(t, server)
			// A valid SYN with a Fast Open request option and payload must be
			// rejected before a ticket is minted, regardless of listener family.
			fd, err := packetSocket(f.peerNS[1], f.peerVTEP[1])
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			packet := resilienceFrame(f.peerVTEP[1].Attrs().HardwareAddr, f.nodeVTEP.Attrs().HardwareAddr,
				net.ParseIP("203.0.113.9"), f.pod.ip, 48501, 8080, 0x02, []byte{34, 2, 1, 1}, []byte("TFO"))
			before := coreDirectionalDrops(t, f, 134, 1) // DROP_INVALID, ingress.
			if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: f.peerVTEP[1].Attrs().Index, Halen: 6}); err != nil {
				t.Fatal(err)
			}
			waitHandoff(t, func() bool { return coreDirectionalDrops(t, f, 134, 1) > before })
			f.noPending(t)
			// Socketless replies using an established tuple cannot borrow that
			// socket's owner, even after CT is rebuilt for the packet.
			podFD, err := packetSocket(f.podNS, f.pod.remote)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(podFD)
			for _, reply := range []struct {
				flags   byte
				payload []byte
			}{{0x14, nil}, {0x10, nil}, {0x18, []byte("socketless-data")}} {
				packet = resilienceFrame(f.pod.remote.Attrs().HardwareAddr, f.pod.host.Attrs().HardwareAddr,
					f.pod.ip, net.ParseIP("203.0.113.9"), 8080, 48500, reply.flags, nil, reply.payload)
				before = coreDrops(t, f, 134)
				if err := unix.Sendto(podFD, packet, 0, &unix.SockaddrLinklayer{Ifindex: f.pod.remote.Attrs().Index, Halen: 6}); err != nil {
					t.Fatal(err)
				}
				waitHandoff(t, func() bool { return coreDrops(t, f, 134) > before })
			}
			if f.owner(t, server) != owner {
				t.Fatal("unsupported TCP path changed established ownership")
			}
			transferHandoff(t, client, server, "owner-survives-unsupported-paths")
		})
	}
}

// This is a correctness workload under TCG, never a native throughput result.
// Force real packet loss, then allow retransmission through a reordering qdisc
// after CT loss. Check every byte and each immutable socket owner.
func TestPrivilegedCoreLossRecovery(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("mapped=%v", mapped), func(t *testing.T) {
			f := newHandoffListenerFixture(t, tcpModeObject(t, "VTEP_RETURN_CORE_OBJECT"), mapped)
			type flow struct {
				client, server *net.TCPConn
				owner          handoffOwner
				payload        []byte
			}
			var flows []flow
			for i, peer := range []int{0, 1, -1} {
				client, server := f.connect(t, peer, 48510+i)
				flows = append(flows, flow{client, server, f.owner(t, server), bytes.Repeat([]byte{byte('A' + i)}, 64<<10)})
			}
			attrs := netlink.QdiscAttrs{LinkIndex: f.pod.remote.Attrs().Index,
				Parent: netlink.HANDLE_ROOT, Handle: netlink.MakeHandle(1, 0)}
			q := netlink.NewNetem(attrs, netlink.NetemQdiscAttrs{Loss: 100, Limit: 1024})
			if err := f.podNS.Do(func() error { return netlink.QdiscAdd(q) }); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.podNS.Do(func() error { return netlink.QdiscDel(q) }) })
			for _, flow := range flows {
				flow.server.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if n, err := flow.server.Write(flow.payload); err != nil || n != len(flow.payload) {
					t.Fatalf("write workload: %d %v", n, err)
				}
			}
			waitHandoff(t, func() bool {
				var drops uint32
				if err := f.podNS.Do(func() error {
					qs, err := netlink.QdiscList(f.pod.remote)
					for _, current := range qs {
						if current.Attrs().Handle == attrs.Handle && current.Attrs().Statistics != nil && current.Attrs().Statistics.Queue != nil {
							drops += current.Attrs().Statistics.Queue.Drops
						}
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				return drops > 0
			})
			clearCoreCT(t, f)
			recoverQ := netlink.NewNetem(attrs, netlink.NetemQdiscAttrs{Latency: 20_000, Limit: 1024, ReorderProb: 100, Gap: 2})
			if err := f.podNS.Do(func() error { return netlink.QdiscChange(recoverQ) }); err != nil {
				t.Fatal(err)
			}
			for _, flow := range flows {
				flow.client.SetReadDeadline(time.Now().Add(15 * time.Second))
				got := make([]byte, len(flow.payload))
				if _, err := io.ReadFull(flow.client, got); err != nil || !bytes.Equal(got, flow.payload) {
					t.Fatalf("payload lost or delivered to another peer: %v", err)
				}
				if f.owner(t, flow.server) != flow.owner {
					t.Fatal("loss, reordering or CT replacement changed socket ownership")
				}
			}
			f.noPending(t)
		})
	}
}
