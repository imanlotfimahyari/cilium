// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/netns"
	testns "github.com/cilium/cilium/pkg/testutils/netns"
)

type cookieChildMarker struct {
	Namespace, Cookie     uint64
	ClientISN, ServerISN  uint32
	Local, Remote         uint32
	LocalPort, RemotePort uint16
	Family, Reserved      uint16
}

type cookieChildObservation struct {
	Created, Established, Missing, Errors uint64
	Marker                                cookieChildMarker
}

type cookieChildNetwork struct {
	router, pod *netns.NetNS
	veth        fixtureLink
	listener    *net.TCPListener
	cookie      uint64
}

func newCookieChildNetwork(t *testing.T, mapped bool) *cookieChildNetwork {
	t.Helper()
	f := &cookieChildNetwork{router: testns.NewNetNS(t), pod: testns.NewNetNS(t)}
	if err := f.router.Do(func() error {
		var err error
		f.veth, err = makeLink("cookie-pod", "198.51.100.1/24", "198.51.100.10/24", f.pod)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.pod.Do(func() error {
		var err error
		f.cookie, err = netns.GetNetNSCookie()
		if err != nil {
			return err
		}
		for name, value := range map[string]string{"tcp_syncookies": "0", "tcp_timestamps": "0"} {
			if err := os.WriteFile("/proc/sys/net/ipv4/"+name, []byte(value), 0600); err != nil {
				return err
			}
		}
		if mapped {
			lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
				var optionErr error
				if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0) }); err != nil {
					return err
				}
				return optionErr
			}}
			listener, err := lc.Listen(context.Background(), "tcp6", "[::]:8080")
			if err == nil {
				f.listener = listener.(*net.TCPListener)
			}
			return err
		}
		f.listener, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: f.veth.ip, Port: 8080})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.listener.Close() })
	return f
}

func (f *cookieChildNetwork) connect(t *testing.T, port int) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	var client *net.TCPConn
	if err := f.router.Do(func() error {
		dialer := net.Dialer{Timeout: 3 * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: port},
			Control: func(_, _ string, raw syscall.RawConn) error {
				var optionErr error
				if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1) }); err != nil {
					return err
				}
				return optionErr
			}}
		conn, err := dialer.Dial("tcp4", "198.51.100.10:8080")
		if err == nil {
			client = conn.(*net.TCPConn)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	f.listener.SetDeadline(time.Now().Add(3 * time.Second))
	server, err := f.listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return client, server
}

func cookieCounter(t *testing.T, ns *netns.NetNS, name string) uint64 {
	t.Helper()
	var result uint64
	if err := ns.Do(func() error {
		data, err := os.ReadFile("/proc/thread-self/net/netstat")
		if err != nil {
			return err
		}
		lines := strings.Split(string(data), "\n")
		for i := 0; i+1 < len(lines); i++ {
			names, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
			if len(names) == 0 || names[0] != "TcpExt:" || len(names) != len(values) {
				continue
			}
			for col, metric := range names {
				if metric == name {
					result, err = strconv.ParseUint(values[col], 10, 64)
					return err
				}
			}
		}
		return fmt.Errorf("kernel did not expose %s", name)
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

// A context-slot mismatch must fail before the tracing program is loaded.
func checkCookieChildABI(t *testing.T) {
	t.Helper()
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	var fn *btf.Func
	if err := kernel.TypeByName("tcp_get_cookie_sock", &fn); err != nil {
		t.Fatal(err)
	}
	ptr := func(typ btf.Type, name string) bool {
		pointer, ok := btf.UnderlyingType(typ).(*btf.Pointer)
		if !ok {
			return false
		}
		structure, ok := btf.UnderlyingType(pointer.Target).(*btf.Struct)
		return ok && structure.Name == name
	}
	proto, ok := btf.UnderlyingType(fn.Type).(*btf.FuncProto)
	if !ok || len(proto.Params) != 4 || !ptr(proto.Return, "sock") {
		t.Fatal("unreviewed tcp_get_cookie_sock return slot or prototype")
	}
	for i, name := range []string{"sock", "sk_buff", "request_sock", "dst_entry"} {
		if !ptr(proto.Params[i].Type, name) {
			t.Fatalf("unreviewed tcp_get_cookie_sock argument %d", i)
		}
	}
}

func TestPrivilegedSYNcookieChildEvidence(t *testing.T) {
	object := tcpModeObject(t, "VTEP_RETURN_COOKIE_OBJECT")
	checkCookieChildABI(t)
	for _, mapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("mapped=%v", mapped), func(t *testing.T) {
			f := newCookieChildNetwork(t, mapped)
			var stat unix.Stat_t
			if err := unix.Fstat(f.pod.FD(), &stat); err != nil {
				t.Fatal(err)
			}
			spec, err := ebpf.LoadCollectionSpec(object)
			if err != nil {
				t.Fatal(err)
			}
			for name, value := range map[string]any{"cookie_probe_inum": uint32(stat.Ino), "cookie_probe_namespace": f.cookie} {
				if err := spec.Variables[name].Set(value); err != nil {
					t.Fatal(err)
				}
			}
			spec.Programs["cookie_child_established"].Type = ebpf.SockOps
			spec.Programs["cookie_child_established"].AttachType = ebpf.AttachCGroupSockOps
			coll, err := ebpf.NewCollection(spec)
			if err != nil {
				t.Fatalf("load cookie child probe: %+v", err)
			}
			defer coll.Close()
			tracing, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs["cookie_child_created"]})
			if err != nil {
				t.Fatal(err)
			}
			defer tracing.Close()
			sockops, err := link.AttachCgroup(link.CgroupOptions{Path: "/sys/fs/cgroup", Attach: ebpf.AttachCGroupSockOps, Program: coll.Programs["cookie_child_established"]})
			if err != nil {
				t.Fatal(err)
			}
			defer sockops.Close()
			observations, markers := coll.Maps["cookie_child_observations"], coll.Maps["cookie_child_markers"]
			observation := func(t *testing.T, port uint32) cookieChildObservation {
				t.Helper()
				var record cookieChildObservation
				if err := observations.Lookup(port, &record); err != nil || record.Errors != 0 {
					t.Fatalf("cookie child evidence: %+v, error=%v", record, err)
				}
				return record
			}
			readMarker := func(t *testing.T, conn *net.TCPConn) (cookieChildMarker, error) {
				t.Helper()
				raw, err := conn.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var marker cookieChildMarker
				var readErr error
				if err := raw.Control(func(fd uintptr) {
					readErr = markers.Lookup(uint32(fd), &marker)
					if readErr == nil {
						cookie, err := unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
						if err != nil || cookie == 0 || cookie != marker.Cookie {
							t.Errorf("accepted socket cookie mismatch: marker=%+v actual=%d error=%v", marker, cookie, err)
						}
					}
				}); err != nil {
					t.Fatal(err)
				}
				return marker, readErr
			}
			t.Run("normal_handshake_has_no_cookie_marker", func(t *testing.T) {
				client, server := f.connect(t, 48200)
				if _, err := readMarker(t, server); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("normal handshake acquired cookie evidence: %v", err)
				}
				record := observation(t, 48200)
				if record.Created != 0 || record.Established != 0 || record.Missing != 1 {
					t.Fatalf("normal-handshake control did not exercise passive callback: %+v", record)
				}
				transferHandoff(t, client, server, "normal-control")
			})
			if err := f.pod.Do(func() error { return os.WriteFile("/proc/sys/net/ipv4/tcp_syncookies", []byte("2"), 0600) }); err != nil {
				t.Fatal(err)
			}
			before := cookieCounter(t, f.pod, "SyncookiesRecv")
			client, server := f.connect(t, 48201)
			marker, err := readMarker(t, server)
			if err != nil {
				t.Fatalf("cookie child lacked socket-local evidence: %v; counters=%+v", err, observation(t, 48201))
			}
			t.Run("validated_child_precedes_passive_callback", func(t *testing.T) {
				record := observation(t, 48201)
				family := uint16(unix.AF_INET)
				if mapped {
					family = unix.AF_INET6
				}
				if cookieCounter(t, f.pod, "SyncookiesRecv") <= before || record.Created != 1 || record.Established != 1 || record.Missing != 0 || record.Marker != marker ||
					marker.Namespace != f.cookie || marker.Local != wireIP(f.veth.ip) || marker.Remote != wireIP(net.ParseIP("198.51.100.1")) ||
					marker.LocalPort != 8080 || marker.RemotePort != 48201 || marker.Family != family || marker.Reserved != 0 {
					t.Fatalf("invalid or unordered kernel cookie-child evidence: marker=%+v observation=%+v", marker, record)
				}
				transferHandoff(t, client, server, "kernel-cookie-child")
			})
			t.Run("invalid_cookie_ACK_has_no_child_evidence", func(t *testing.T) {
				fd, err := packetSocket(f.router, f.veth.host)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fd)
				packet := resilienceFrame(f.veth.host.Attrs().HardwareAddr, f.veth.remote.Attrs().HardwareAddr,
					net.ParseIP("198.51.100.1"), f.veth.ip, 48202, 8080, 0x10, nil, nil)
				binary.BigEndian.PutUint32(packet[42:46], 0x12345678)
				finishTCPChecksums(packet)
				failedBefore := cookieCounter(t, f.pod, "SyncookiesFailed")
				if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: f.veth.host.Attrs().Index, Halen: 6}); err != nil {
					t.Fatal(err)
				}
				waitHandoff(t, func() bool { return cookieCounter(t, f.pod, "SyncookiesFailed") > failedBefore })
				var record cookieChildObservation
				if err := observations.Lookup(uint32(48202), &record); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("invalid cookie ACK reached child evidence: %+v, %v", record, err)
				}
				if now, err := readMarker(t, server); err != nil || now != marker {
					t.Fatal("invalid ACK changed existing socket evidence")
				}
				transferHandoff(t, client, server, "after-invalid-cookie-ACK")
			})
			t.Run("unselected_namespace_with_identical_tuple_is_ignored", func(t *testing.T) {
				other := newCookieChildNetwork(t, mapped)
				if err := other.pod.Do(func() error { return os.WriteFile("/proc/sys/net/ipv4/tcp_syncookies", []byte("2"), 0600) }); err != nil {
					t.Fatal(err)
				}
				otherClient, otherServer := other.connect(t, 48201)
				if cookieCounter(t, other.pod, "SyncookiesRecv") == 0 {
					t.Fatal("unselected namespace did not use kernel SYN cookies")
				}
				if _, err := readMarker(t, otherServer); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("unselected namespace acquired selected evidence: %v", err)
				}
				if now := observation(t, 48201); now.Created != 1 || now.Established != 1 || now.Marker != marker {
					t.Fatalf("unselected namespace changed selected evidence: %+v", now)
				}
				transferHandoff(t, otherClient, otherServer, "unselected-cookie-child")
			})
			t.Run("tuple_reuse_keeps_old_FD_evidence", func(t *testing.T) {
				if err := client.SetLinger(0); err != nil {
					t.Fatal(err)
				}
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
				server.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, err := server.Read(make([]byte, 1)); !errors.Is(err, unix.ECONNRESET) {
					t.Fatalf("client reset was not processed: %v", err)
				}
				replacementClient, replacementServer := f.connect(t, 48201)
				replacement, err := readMarker(t, replacementServer)
				if err != nil || replacement.Cookie == marker.Cookie || replacement.Namespace != marker.Namespace ||
					replacementClient.LocalAddr().String() != client.LocalAddr().String() || replacementServer.LocalAddr().String() != server.LocalAddr().String() {
					t.Fatalf("tuple reuse did not create independent socket evidence: old=%+v new=%+v error=%v", marker, replacement, err)
				}
				if old, err := readMarker(t, server); err != nil || old != marker {
					t.Fatal("replacement changed the old socket's retained evidence")
				}
				record := observation(t, 48201)
				if record.Created != 2 || record.Established != 2 || record.Missing != 0 || record.Marker != replacement {
					t.Fatalf("replacement evidence not independently published: %+v", record)
				}
				transferHandoff(t, replacementClient, replacementServer, "reused-cookie-tuple")
			})
		})
	}
}
