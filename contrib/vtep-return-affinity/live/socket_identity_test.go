// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/testutils"
	testns "github.com/cilium/cilium/pkg/testutils/netns"
)

type socketOwner struct {
	Cookie   uint64
	Peer     uint32
	Reserved uint32
}

type packetEvidence struct {
	Packets, WithSocket, WithStorage, Cookie uint64
	Peer, Reserved                           uint32
}

type socketEvidence struct {
	EstablishedCookie, CloseWait, Closed, Errors uint64
	At                                           [3]packetEvidence
}

// The cgroup programs attach at the guest's root, so running this experiment
// requires an explicit isolated-VM marker as well as PRIVILEGED_TESTS.
// It is a capability test, not a production affinity implementation.
func TestPrivilegedSocketIdentity(t *testing.T) {
	testutils.PrivilegedTest(t)
	if os.Getenv("VTEP_RETURN_ISOLATED_VM") != "1" {
		t.Skip("root cgroup probe requires the isolated privileged_vm.py guest")
	}
	object := os.Getenv("VTEP_RETURN_SOCKET_OBJECT")
	if object == "" {
		t.Skip("supply --socket-object to privileged_vm.py")
	}
	router, podNS := testns.NewNetNS(t), testns.NewNetNS(t)
	var pod fixtureLink
	if err := router.Do(func() error {
		var err error
		pod, err = makeLink("sock-pod", "198.51.100.1/24", "198.51.100.10/24", podNS)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	for name, settings := range map[string]struct {
		typeID ebpf.ProgramType
		attach ebpf.AttachType
	}{
		"socket_identity_established": {ebpf.SockOps, ebpf.AttachCGroupSockOps},
		"socket_identity_cgroup":      {ebpf.CGroupSKB, ebpf.AttachCGroupInetEgress},
		"socket_identity_pod":         {ebpf.SchedCLS, ebpf.AttachTCXEgress},
		"socket_identity_host":        {ebpf.SchedCLS, ebpf.AttachTCXIngress},
	} {
		program := spec.Programs[name]
		if program == nil {
			t.Fatalf("missing probe program %s", name)
		}
		program.Type, program.AttachType = settings.typeID, settings.attach
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load socket probe: %+v", err)
	}
	defer coll.Close()
	for _, settings := range []struct {
		name   string
		attach ebpf.AttachType
	}{
		{"socket_identity_established", ebpf.AttachCGroupSockOps},
		{"socket_identity_cgroup", ebpf.AttachCGroupInetEgress},
	} {
		attached, err := link.AttachCgroup(link.CgroupOptions{Path: "/sys/fs/cgroup",
			Attach: settings.attach, Program: coll.Programs[settings.name]})
		if err != nil {
			t.Fatal(err)
		}
		defer attached.Close()
	}
	if err := podNS.Do(func() error {
		attached, err := link.AttachTCX(link.TCXOptions{Interface: pod.remote.Attrs().Index,
			Program: coll.Programs["socket_identity_pod"], Attach: ebpf.AttachTCXEgress})
		if err == nil {
			t.Cleanup(func() { attached.Close() })
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := router.Do(func() error {
		attached, err := link.AttachTCX(link.TCXOptions{Interface: pod.host.Attrs().Index,
			Program: coll.Programs["socket_identity_host"], Attach: ebpf.AttachTCXIngress})
		if err == nil {
			t.Cleanup(func() { attached.Close() })
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var listener *net.TCPListener
	if err := podNS.Do(func() error {
		var err error
		listener, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: pod.ip, Port: 8080})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerA, peerB := wireIP(net.ParseIP("192.0.2.2")), wireIP(net.ParseIP("192.0.2.6"))
	admissions, observations, owners := coll.Maps["socket_admissions"],
		coll.Maps["socket_observations"], coll.Maps["socket_owners"]
	for port, peer := range map[uint32]uint32{45000: peerA, 45001: peerB} {
		if err := admissions.Update(port, peer, ebpf.UpdateNoExist); err != nil {
			t.Fatal(err)
		}
	}

	connect := func(t *testing.T, port int) (*net.TCPConn, *net.TCPConn) {
		t.Helper()
		var client *net.TCPConn
		if err := router.Do(func() error {
			dialer := net.Dialer{Timeout: 2 * time.Second,
				LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: port},
				Control: func(_, _ string, raw syscall.RawConn) error {
					var optionErr error
					if err := raw.Control(func(fd uintptr) {
						optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
					}); err != nil {
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
		listener.SetDeadline(time.Now().Add(2 * time.Second))
		server, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { server.Close() })
		return client, server
	}
	readOwner := func(t *testing.T, conn *net.TCPConn) socketOwner {
		t.Helper()
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var owner socketOwner
		var cookie uint64
		var readErr error
		if err := raw.Control(func(fd uintptr) {
			cookie, readErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
			if readErr == nil {
				readErr = owners.Lookup(uint32(fd), &owner)
			}
		}); err != nil {
			t.Fatal(err)
		}
		if readErr != nil || cookie == 0 || owner.Cookie != cookie || owner.Peer == 0 || owner.Reserved != 0 {
			t.Fatalf("socket-owned evidence missing: owner=%+v cookie=%d error=%v", owner, cookie, readErr)
		}
		return owner
	}
	readObservation := func(t *testing.T, port uint32) socketEvidence {
		t.Helper()
		var evidence socketEvidence
		if err := observations.Lookup(port, &evidence); err != nil {
			t.Fatal(err)
		}
		if evidence.Errors != 0 {
			t.Fatalf("BPF storage/callback errors: %+v", evidence)
		}
		return evidence
	}
	transfer := func(t *testing.T, client, server *net.TCPConn, payload string) {
		t.Helper()
		server.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.WriteString(server, payload); err != nil {
			t.Fatal(err)
		}
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(client, buf); err != nil || string(buf) != payload {
			t.Fatalf("application transfer: %v", err)
		}
	}
	checkPath := func(t *testing.T, port uint32, owner socketOwner) {
		t.Helper()
		evidence := readObservation(t, port)
		if evidence.EstablishedCookie != owner.Cookie {
			t.Fatal("sockops identity does not match the accepted socket")
		}
		for stage, name := range []string{"cgroup egress", "pod TC egress", "host TC ingress"} {
			at := evidence.At[stage]
			if at.Packets == 0 {
				t.Fatalf("no application packets observed at %s", name)
			}
			if at.Cookie != owner.Cookie || at.Peer != owner.Peer {
				t.Fatalf("wrong socket ownership at %s: %+v", name, at)
			}
			if at.WithStorage != at.Packets || at.WithSocket != at.Packets {
				t.Fatalf("%s lost the originating socket: %+v", name, at)
			}
			t.Logf("%s: application packets=%d socket=%t matching storage=%t",
				name, at.Packets, at.WithSocket > 0, at.WithStorage > 0)
		}
	}

	firstClient, firstServer := connect(t, 45000)
	firstOwner := readOwner(t, firstServer)
	secondClient, secondServer := connect(t, 45001)
	secondOwner := readOwner(t, secondServer)
	if firstOwner.Cookie == secondOwner.Cookie || firstOwner.Peer != peerA || secondOwner.Peer != peerB {
		t.Fatal("concurrent connections do not have independent identities and peers")
	}
	t.Run("real_socket_identity_across_hooks", func(t *testing.T) {
		transfer(t, firstClient, firstServer, "socket-evidence-A")
		checkPath(t, 45000, firstOwner)
		transfer(t, secondClient, secondServer, "socket-evidence-B")
		checkPath(t, 45001, secondOwner)
	})
	t.Run("remote_FIN_does_not_end_reply_ownership", func(t *testing.T) {
		if err := firstClient.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		firstServer.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := firstServer.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatalf("expected remote half-close: n=%d error=%v", n, err)
		}
		if readObservation(t, 45000).CloseWait == 0 || readOwner(t, firstServer) != firstOwner {
			t.Fatal("half-close lost ownership or did not trigger TCP-state evidence")
		}
		transfer(t, firstClient, firstServer, "reply-after-remote-FIN")
		checkPath(t, 45000, firstOwner)
	})
	t.Run("admission_changes_do_not_retarget_existing_socket", func(t *testing.T) {
		if err := admissions.Update(uint32(45000), peerB, ebpf.UpdateExist); err != nil {
			t.Fatal(err)
		}
		transfer(t, firstClient, firstServer, "reply-keeps-original-peer")
		checkPath(t, 45000, firstOwner)
		if readOwner(t, firstServer) != firstOwner {
			t.Fatal("changed admission data retargeted an existing socket")
		}
	})
	t.Run("reused_tuple_has_new_socket_and_peer", func(t *testing.T) {
		if err := firstClient.SetLinger(0); err != nil {
			t.Fatal(err)
		}
		if err := firstClient.Close(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for readObservation(t, 45000).Closed == 0 {
			if time.Now().After(deadline) {
				t.Fatal("no TCP_CLOSE callback after client reset")
			}
			time.Sleep(time.Millisecond)
		}
		// Keep the old server FD open: CLOSED and socket destruction are
		// different events. A new socket must not inherit its peer record.
		if readOwner(t, firstServer) != firstOwner {
			t.Fatal("closed socket ownership unexpectedly changed")
		}
		newClient, newServer := connect(t, 45000)
		newOwner := readOwner(t, newServer)
		if newOwner.Cookie == firstOwner.Cookie || newOwner.Cookie == secondOwner.Cookie || newOwner.Peer != peerB {
			t.Fatal("tuple reuse inherited an old identity or peer")
		}
		if firstServer.RemoteAddr().String() != newServer.RemoteAddr().String() ||
			firstServer.LocalAddr().String() != newServer.LocalAddr().String() {
			t.Fatal("the test did not actually reuse the same four-tuple")
		}
		transfer(t, newClient, newServer, "reply-from-reused-tuple")
		// Only compare the latest observations; packet counters include the
		// previous incarnation, but cookies/peers must describe the new one.
		checkPath(t, 45000, newOwner)
		if readOwner(t, firstServer) != firstOwner {
			t.Fatal("replacement changed the still-referenced old socket")
		}
		t.Log("same four-tuple: distinct live socket objects, independent peer records")
	})
}
