// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
	testns "github.com/cilium/cilium/pkg/testutils/netns"
)

type controllerNamespace struct {
	r    EndpointRegistration
	ns   *netns.NetNS
	host netlink.Link
}

func TestPrivilegedPreQueueOnlyStampsSYNACKs(t *testing.T) {
	testutils.PrivilegedTest(t)
	object := os.Getenv("VTEP_RETURN_RUNTIME_OBJECT")
	if object == "" {
		t.Skip("supply the runtime BPF object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	if err := ConfigureTimewaitTarget(spec); err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	for _, tc := range []struct {
		name  string
		proto uint16
		flags byte
		want  uint32
	}{
		{"ARP", 0x0806, 0, 0},
		{"application_data", 0x0800, 0x18, 0},
		{"active_connect_SYN", 0x0800, 0x02, 0},
		{"SYNACK_without_approved_request", 0x0800, 0x12, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := make([]byte, 64)
			packet[12], packet[13] = byte(tc.proto>>8), byte(tc.proto)
			if tc.proto == 0x0800 {
				packet[14], packet[23], packet[46], packet[47] = 0x45, 6, 0x50, tc.flags
			}
			got, _, err := coll.Programs["cil_vtep_before_queue"].Test(packet)
			if err != nil || got != tc.want {
				t.Fatalf("pre-queue verdict %d, want %d: %v", got, tc.want, err)
			}
		})
	}
}

func newControllerNamespace(t *testing.T, name string) controllerNamespace {
	t.Helper()
	ns := testns.NewNetNS(t)
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "-p"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	host, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netlink.LinkDel(host) })
	peer, err := netlink.LinkByName(name + "-p")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(peer, ns.FD()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ns")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", ns.FD()), path, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Unmount(path, unix.MNT_DETACH); os.Remove(path) })
	var cookie uint64
	if err := ns.Do(func() error {
		var err error
		cookie, err = netns.GetNetNSCookie()
		if err != nil {
			return err
		}
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		return netlink.LinkSetUp(lo)
	}); err != nil {
		t.Fatal(err)
	}
	return controllerNamespace{r: EndpointRegistration{Cookie: cookie, HostInterface: name,
		HostIfindex: host.Attrs().Index, NamespacePath: path, ContainerInterface: name + "-p"}, ns: ns, host: host}
}

func TestPrivilegedSocketControllerLifecycle(t *testing.T) {
	testutils.PrivilegedTest(t)
	if os.Getenv("VTEP_RETURN_ISOLATED_VM") != "1" {
		t.Skip("node sockops test requires the isolated VM")
	}
	object := os.Getenv("VTEP_RETURN_RUNTIME_OBJECT")
	if object == "" {
		t.Skip("supply --runtime-object to privileged_vm.py")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(privilegedPinPath(t))
	c := NewController(nil, ControllerConfig{Enabled: true, Journal: filepath.Join(t.TempDir(), "journal"), Pins: filepath.Join(dir, "runtime"), Cgroup: "/sys/fs/cgroup"})
	c.ConfigurePeers([]Peer{{Address: [4]byte{192, 0, 2, 2}, MAC: [6]byte{2, 0, 0, 0, 0, 2}}})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.InitializeRuntime(spec); err != nil {
		t.Fatalf("runtime: %+v", err)
	}
	if err := c.Readiness(); err != nil {
		t.Fatalf("initialized runtime is not ready: %v", err)
	}
	t.Run("listeners_must_follow_CNI_commit", func(t *testing.T) {
		early := newControllerNamespace(t, "vtep-early")
		var listener *net.TCPListener
		if err := early.ns.Do(func() error {
			var err error
			listener, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if err := c.Prepare(early.r); err == nil {
			t.Fatal("selected a namespace with an existing TCP listener")
		}
		if _, ok := c.journal.Namespaces[early.r.Cookie]; ok {
			t.Fatal("rejected namespace acquired membership")
		}
	})
	n := newControllerNamespace(t, "vtep-ctrl")
	if err := c.Prepare(n.r); err != nil {
		t.Fatal(err)
	}
	var raw [24]byte
	if err := c.bundle.maps[SocketControlMap].Lookup(n.r.Cookie, &raw); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal("readiness published before endpoint commit")
	}
	if err := c.Commit(n.r.Cookie); err != nil {
		t.Fatal(err)
	}
	var listener *net.TCPListener
	if err := n.ns.Do(func() error {
		var err error
		listener, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	// Real TCP hand-off is checked by the separate agent-process suite.
	ownerID := socketMapID(t, c.bundle.maps[SocketOwnerMap])
	c.Close()
	restored := NewController(nil, c.cfg)
	restored.ConfigurePeers(c.peers)
	t.Cleanup(func() { restored.Close() })
	if err := restored.Start(); err != nil {
		t.Fatal(err)
	}
	if err := restored.InitializeRuntime(spec); err != nil {
		t.Fatalf("warm runtime: %+v", err)
	}
	if socketMapID(t, restored.bundle.maps[SocketOwnerMap]) != ownerID {
		t.Fatal("agent restore replaced canonical socket storage")
	}
	if err := restored.Prepare(n.r); err != nil {
		t.Fatal(err)
	}
	if err := restored.Commit(n.r.Cookie); err != nil {
		t.Fatal(err)
	}
	if err := restored.Retire(n.r.Cookie); err != nil {
		t.Fatal(err)
	}
	if err := restored.Prepare(n.r); err == nil {
		t.Fatal("retired cookie was reopened")
	}
	if err := restored.bundle.maps[SocketControlMap].Lookup(n.r.Cookie, &raw); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal("retired namespace remained ready")
	}
	listener.Close()
	if err := netlink.LinkDel(n.host); err != nil {
		t.Fatal(err)
	}
	if err := unix.Unmount(n.r.NamespacePath, unix.MNT_DETACH); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(n.r.NamespacePath); err != nil {
		t.Fatal(err)
	}
	replacement := newControllerNamespace(t, "vtep-ctrl")
	if replacement.r.Cookie == n.r.Cookie {
		t.Fatal("replacement reused the old namespace")
	}
	if err := restored.Prepare(replacement.r); err != nil {
		t.Fatal(err)
	}
	if err := restored.Commit(replacement.r.Cookie); err != nil {
		t.Fatal(err)
	}
	if err := restored.Retire(replacement.r.Cookie); err != nil {
		t.Fatal(err)
	}
	restored.Close()
	cfg := restored.cfg
	cfg.Enabled = false
	off := NewController(nil, cfg)
	if err := off.Start(); !errors.Is(err, ErrSocketRollbackRequiresQuiescence) {
		t.Fatalf("disable allowed a retained namespace: %v", err)
	}
	netlink.LinkDel(replacement.host)
	unix.Unmount(replacement.r.NamespacePath, unix.MNT_DETACH)
	os.Remove(replacement.r.NamespacePath)
	if err := off.Start(); err != nil {
		t.Fatal(err)
	}
	if err := off.ValidateLegacyNamespace(n.r.Cookie); err == nil {
		t.Fatal("disabled mode permitted old selected sockets to use ordinary routing")
	}
	if err := off.ValidateLegacyNamespace(replacement.r.Cookie + 1); err != nil {
		t.Fatal("fresh namespace could not use ordinary routing", err)
	}
	off.Close()
	if _, err := os.Stat(cfg.Pins); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("drained disable retained socket attachments")
	}
}
