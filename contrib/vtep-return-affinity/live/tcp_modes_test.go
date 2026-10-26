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
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/testutils"
)

func tcpModeObject(t *testing.T, variable string) string {
	t.Helper()
	testutils.PrivilegedTest(t)
	if os.Getenv("VTEP_RETURN_ISOLATED_VM") != "1" {
		t.Skip("TCP modes require the isolated VM")
	}
	object := os.Getenv(variable)
	if object == "" {
		t.Skip("supply " + variable + " to the VM")
	}
	return object
}

func TestPrivilegedMappedIPv4Handoff(t *testing.T) {
	for _, variable := range []string{"VTEP_RETURN_HANDOFF_OBJECT", "VTEP_RETURN_CORE_OBJECT"} {
		t.Run(variable, func(t *testing.T) {
			f := newHandoffListenerFixture(t, tcpModeObject(t, variable), true)
			for i, peer := range []int{0, 1, -1} {
				client, server := f.connect(t, peer, 48000+i)
				owner := f.owner(t, server)
				if peer >= 0 && (owner.Origin != 2 || owner.Peer != wireIP(f.under[peer].ip)) {
					t.Fatal("mapped listener lost the exact peer")
				}
				if peer < 0 && (owner.Origin != 1 || owner.Peer != 0) {
					t.Fatal("mapped listener lost native ownership")
				}
				transferHandoff(t, client, server, "mapped-IPv4")
			}
			f.noPending(t)
		})
	}
}

// Forced cookie mode is intentionally unsupported until a kernel-validated
// child-to-admission handoff exists. Ensure it never guesses a prefix/peer,
// even while another peer's established connection is alive.
func TestPrivilegedSYNcookiesFailClosed(t *testing.T) {
	for _, variable := range []string{"VTEP_RETURN_HANDOFF_OBJECT", "VTEP_RETURN_CORE_OBJECT"} {
		for _, mapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mapped=%v", variable, mapped), func(t *testing.T) {
				syncookiesFailClosed(t, variable, mapped)
			})
		}
	}
}

func syncookiesFailClosed(t *testing.T, variable string, mapped bool) {
	t.Helper()
	f := newHandoffListenerFixture(t, tcpModeObject(t, variable), mapped)
	client, server := f.connect(t, 0, 48100)
	owner := f.owner(t, server)
	if err := f.podNS.Do(func() error { return os.WriteFile("/proc/sys/net/ipv4/tcp_syncookies", []byte("2"), 0600) }); err != nil {
		t.Fatal(err)
	}
	f.policy(t, 48101, 3)
	before := f.counts(t)
	cookiesBefore := syncookiesSent(t, f)
	err := f.peerNS[1].Do(func() error {
		d := net.Dialer{Timeout: 300 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 48101}}
		c, err := d.Dial("tcp4", "198.51.100.10:8080")
		if c != nil {
			c.Close()
		}
		return err
	})
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("unsupported cookie handshake did not fail closed: %v", err)
	}
	after := f.counts(t)
	if syncookiesSent(t, f) <= cookiesBefore {
		t.Fatal("kernel did not actually enter SYN-cookie mode")
	}
	if after.SynAckDrop <= before.SynAckDrop {
		t.Fatal("cookie SYNACK did not reach and fail ownership enforcement")
	}
	if f.owner(t, server) != owner {
		t.Fatal("cookie handshake changed an established owner")
	}
	transferHandoff(t, client, server, "existing-flow-survives-cookie-rejection")
}

func syncookiesSent(t *testing.T, f *handoffFixture) uint64 {
	t.Helper()
	var sent uint64
	if err := f.podNS.Do(func() error {
		b, err := os.ReadFile("/proc/thread-self/net/netstat")
		if err != nil {
			return err
		}
		lines := strings.Split(string(b), "\n")
		for i := 0; i+1 < len(lines); i++ {
			names, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
			if len(names) == 0 || names[0] != "TcpExt:" || len(names) != len(values) {
				continue
			}
			for col, name := range names {
				if name == "SyncookiesSent" {
					sent, err = strconv.ParseUint(values[col], 10, 64)
					return err
				}
			}
		}
		return errors.New("kernel did not expose SyncookiesSent")
	}); err != nil {
		t.Fatal(err)
	}
	return sent
}

// Reproduce a real kernel TIME-WAIT ACK, including a retransmitted peer FIN.
// A retained application FD is not the socket used for this reply. Until an
// incarnation-safe handoff is implemented, it must drop rather than borrow a
// replacement connection's owner or use the overlapping client prefix.
func TestPrivilegedTIMEWAITRepliesFailClosed(t *testing.T) {
	f := newHandoffFixture(t, tcpModeObject(t, "VTEP_RETURN_HANDOFF_OBJECT"))
	const port = 48150
	client, server := f.connect(t, 0, port)
	owner := f.owner(t, server)
	defer func() {
		if t.Failed() {
			t.Logf("TIME-WAIT counters: %+v", f.counts(t))
			f.podNS.Do(func() error {
				data, _ := os.ReadFile("/proc/thread-self/net/snmp")
				t.Logf("TCP kernel counters: %s", data)
				return nil
			})
		}
	}()
	// Outgoing frames are delivered to ETH_P_ALL packet taps.
	fd, err := packetSocketProtocol(f.peerNS[0], f.peerVTEP[0], unix.ETH_P_ALL)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
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
		found := false
		if err := f.podNS.Do(func() error {
			data, err := os.ReadFile("/proc/thread-self/net/tcp")
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 4 || fields[3] != "06" {
					continue
				}
				remote := strings.Split(fields[2], ":")
				if len(remote) == 2 {
					p, _ := strconv.ParseUint(remote[1], 16, 16)
					found = found || p == port
				}
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return found
	})
	var fin []byte
	waitHandoff(t, func() bool {
		b := make([]byte, 2048)
		n, _, err := unix.Recvfrom(fd, b, 0)
		if errors.Is(err, unix.EAGAIN) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		if n < 54 || b[14]>>4 != 4 || binary.BigEndian.Uint16(b[34:36]) != port || b[47]&1 == 0 {
			return false
		}
		fin = append([]byte(nil), b[:n]...)
		return true
	})
	before := f.counts(t)
	// Packet taps see CHECKSUM_PARTIAL before offload. Replaying those bytes
	// verbatim would test checksum rejection, not TIME-WAIT. Finalize both.
	ip := fin[14:]
	ihl := int(ip[0]&15) * 4
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:ihl]))
	tcp := ip[ihl:total]
	tcp[16], tcp[17] = 0, 0
	pseudo := append([]byte(nil), ip[12:20]...)
	pseudo = append(pseudo, 0, unix.IPPROTO_TCP, byte(len(tcp)>>8), byte(len(tcp)))
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	if err := unix.Sendto(fd, fin, 0, &unix.SockaddrLinklayer{Ifindex: f.peerVTEP[0].Attrs().Index, Halen: 6, Protocol: wire16(unix.ETH_P_IP)}); err != nil {
		t.Fatal(err)
	}
	waitHandoff(t, func() bool { return f.counts(t).ReplyDrop > before.ReplyDrop })
	if f.owner(t, server) != owner {
		t.Fatal("TIME-WAIT replaced the retained FD owner")
	}
	replacementClient, replacementServer := f.connect(t, 1, port+1)
	if f.owner(t, replacementServer).Peer != wireIP(f.under[1].ip) {
		t.Fatal("another peer inherited TIME-WAIT ownership")
	}
	transferHandoff(t, replacementClient, replacementServer, "new-flow-after-TIME-WAIT")
}
