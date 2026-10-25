// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
	testns "github.com/cilium/cilium/pkg/testutils/netns"
)

type handoffControl struct {
	Generation, TTL uint64
	Phase, Reserved uint32
}
type handoffKey struct{ Namespace, Token uint64 }
type handoffFlow struct {
	Pod, Client         uint32
	PodPort, ClientPort uint16
	Sequence            uint32
}
type handoffTicket struct {
	Generation, Expires, RequestCookie uint64
	Peer, Origin                       uint32
	Flow                               handoffFlow
}
type handoffOwner struct {
	Namespace, Generation, Cookie uint64
	Peer, Origin                  uint32
}
type handoffCounts struct {
	Admitted, IngressDenied, Untrusted, AdmissionFailed                         uint64
	Assigned, AssignmentFailed, Tunnel, Native, ReplyDrop, SynAckDrop, DataDrop uint64
}
type handoffFixture struct {
	rootTest                *testing.T
	collection              *ebpf.Collection
	spec                    *ebpf.CollectionSpec
	attachments             map[string]link.Link
	cleanup                 func(func())
	core                    bool
	router, podNS, nativeNS *netns.NetNS
	peerNS                  [2]*netns.NetNS
	pod, native             fixtureLink
	under                   [2]fixtureLink
	nodeVTEP                netlink.Link
	peerVTEP                [2]netlink.Link
	cookie                  uint64
	listener                *net.TCPListener
}

func newHandoffNetwork(t *testing.T) *handoffFixture {
	t.Helper()
	f := &handoffFixture{rootTest: t, cleanup: t.Cleanup, attachments: make(map[string]link.Link), router: testns.NewNetNS(t), podNS: testns.NewNetNS(t),
		nativeNS: testns.NewNetNS(t), peerNS: [2]*netns.NetNS{testns.NewNetNS(t), testns.NewNetNS(t)}}
	err := f.router.Do(func() error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(lo); err != nil {
			return err
		}
		f.pod, err = makeLink("h-pod", "198.51.100.1/24", "198.51.100.10/24", f.podNS)
		if err != nil {
			return err
		}
		f.native, err = makeLink("h-native", "203.0.113.1/24", "203.0.113.10/24", f.nativeNS)
		if err != nil {
			return err
		}
		for i, addresses := range [][2]string{{"192.0.2.1/30", "192.0.2.2/30"}, {"192.0.2.5/30", "192.0.2.6/30"}} {
			f.under[i], err = makeLink(fmt.Sprintf("h-peer%d", i), addresses[0], addresses[1], f.peerNS[i])
			if err != nil {
				return err
			}
		}
		if err := netlink.LinkAdd(&netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "h-vtep"}, FlowBased: true, Port: 8472}); err != nil {
			return err
		}
		f.nodeVTEP, err = netlink.LinkByName("h-vtep")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(f.nodeVTEP); err != nil {
			return err
		}
		return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, ns := range f.peerNS {
		if err := ns.Do(func() error {
			remote := []string{"192.0.2.1", "192.0.2.5"}[i]
			vxlan := &netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "h-peer-vtep"}, VxlanId: 2,
				VtepDevIndex: f.under[i].remote.Attrs().Index, SrcAddr: f.under[i].ip,
				Group: net.ParseIP(remote), Port: 8472}
			if err := netlink.LinkAdd(vxlan); err != nil {
				return err
			}
			var err error
			f.peerVTEP[i], err = netlink.LinkByName("h-peer-vtep")
			if err != nil {
				return err
			}
			addr, _ := netlink.ParseAddr("203.0.113.9/32")
			if err := netlink.AddrAdd(f.peerVTEP[i], addr); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(f.peerVTEP[i]); err != nil {
				return err
			}
			if err := netlink.RouteAdd(&netlink.Route{LinkIndex: f.peerVTEP[i].Attrs().Index,
				Dst: &net.IPNet{IP: f.pod.ip, Mask: net.CIDRMask(32, 32)}, Scope: netlink.SCOPE_LINK}); err != nil {
				return err
			}
			return netlink.NeighSet(&netlink.Neigh{LinkIndex: f.peerVTEP[i].Attrs().Index, IP: f.pod.ip,
				HardwareAddr: f.nodeVTEP.Attrs().HardwareAddr, State: netlink.NUD_PERMANENT})
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.podNS.Do(func() error {
		var err error
		f.cookie, err = netns.GetNetNSCookie()
		if err != nil {
			return err
		}
		if err := netlink.NeighSet(&netlink.Neigh{LinkIndex: f.pod.remote.Attrs().Index,
			IP: net.ParseIP("198.51.100.1"), HardwareAddr: f.pod.host.Attrs().HardwareAddr, State: netlink.NUD_PERMANENT}); err != nil {
			return err
		}
		return netlink.RouteAdd(&netlink.Route{LinkIndex: f.pod.remote.Attrs().Index, Gw: net.ParseIP("198.51.100.1")})
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.nativeNS.Do(func() error {
		return netlink.RouteAdd(&netlink.Route{LinkIndex: f.native.remote.Attrs().Index, Gw: net.ParseIP("203.0.113.1")})
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func newHandoffFixture(t *testing.T, object string) *handoffFixture {
	t.Helper()
	return newHandoffListenerFixture(t, object, false)
}

func newHandoffListenerFixture(t *testing.T, object string, mapped bool) *handoffFixture {
	t.Helper()
	f := newHandoffNetwork(t)
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	f.core = spec.Programs["cil_from_container"] != nil
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	var podMAC [6]byte
	copy(podMAC[:], f.pod.remote.Attrs().HardwareAddr)
	for name, value := range map[string]any{"handoff_netns_cookie": f.cookie,
		"handoff_pod_ifindex":    uint32(f.pod.host.Attrs().Index),
		"handoff_tunnel_ifindex": uint32(f.nodeVTEP.Attrs().Index), "handoff_pod_mac": podMAC} {
		if err := spec.Variables[name].Set(value); err != nil {
			t.Fatal(err)
		}
	}
	if f.core {
		var address [4]byte
		var routerMAC [8]byte
		copy(address[:], f.pod.ip.To4())
		copy(routerMAC[:], f.pod.host.Attrs().HardwareAddr)
		for name, value := range map[string]any{
			"endpoint_netns_cookie": f.cookie, "endpoint_ipv4": address,
			"interface_ifindex": uint32(f.pod.host.Attrs().Index), "interface_mac": routerMAC,
			"enable_vtep": true, "enable_bpf_routing": true, "enable_bpf_host_routing": true,
			"tunnel_protocol": uint8(1),
			"security_label":  uint32(1234),
			"vtep_mask":       wireIP(net.ParseIP("255.255.255.0")),
		} {
			if err := spec.Variables["__config_"+name].Set(value); err != nil {
				t.Fatalf("configure %s: %v", name, err)
			}
		}
	}
	for name, p := range spec.Programs {
		if name == "handoff_socket" {
			p.Type, p.AttachType = ebpf.SockOps, ebpf.AttachCGroupSockOps
		} else if name == "handoff_before_queue" || name == "handoff_from_host" {
			p.Type, p.AttachType = ebpf.SchedCLS, ebpf.AttachTCXEgress
		} else {
			p.Type, p.AttachType = ebpf.SchedCLS, ebpf.AttachTCXIngress
		}
		if strings.HasPrefix(name, "handoff_") {
			p.SectionName += "/entry"
		}
	}
	f.spec = spec.Copy()
	var commit func() error
	f.collection, commit, err = bpf.LoadCollection(slog.New(slog.NewTextHandler(io.Discard, nil)), spec, nil)
	if err != nil {
		t.Fatalf("load hand-off programs: %+v", err)
	}
	t.Cleanup(f.collection.Close)
	f.setControl(t, 30*time.Second)
	if err := f.collection.Maps["cilium_vtep_nonce4"].Update(f.cookie, uint64(0), ebpf.UpdateNoExist); err != nil {
		t.Fatal(err)
	}
	for i := range f.peerNS {
		f.trustPeer(t, i)
	}
	if f.core {
		// Deliberately cover both external and native clients with the legacy
		// route. Explicit native ownership must bypass it, including after CT loss.
		var value [16]byte // vtep_value includes trailing alignment padding.
		copy(value[:6], f.peerVTEP[0].Attrs().HardwareAddr)
		copy(value[8:], f.under[0].ip.To4())
		if err := f.collection.Maps["cilium_vtep_map"].Update(wireIP(net.ParseIP("203.0.113.0")), value, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	attached, err := link.AttachCgroup(link.CgroupOptions{Path: "/sys/fs/cgroup", Attach: ebpf.AttachCGroupSockOps,
		Program: f.collection.Programs["handoff_socket"]})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { attached.Close() })
	f.attachments["handoff_socket"] = attached
	if err := f.podNS.Do(func() error {
		l, err := link.AttachTCX(link.TCXOptions{Interface: f.pod.remote.Attrs().Index,
			Program: f.collection.Programs["handoff_before_queue"], Attach: ebpf.AttachTCXEgress})
		if err == nil {
			t.Cleanup(func() { l.Close() })
			f.attachments["handoff_before_queue"] = l
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.router.Do(func() error {
		for _, entry := range []struct {
			name  string
			iface netlink.Link
		}{
			{"handoff_from_overlay", f.nodeVTEP}, {"handoff_from_native", f.native.host}, {"handoff_from_pod", f.pod.host},
		} {
			l, err := link.AttachTCX(link.TCXOptions{Interface: entry.iface.Attrs().Index,
				Program: f.collection.Programs[entry.name], Attach: ebpf.AttachTCXIngress})
			if err != nil {
				return err
			}
			t.Cleanup(func() { l.Close() })
			f.attachments[entry.name] = l
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.podNS.Do(func() error {
		var err error
		if mapped {
			lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
				var optionErr error
				if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0) }); err != nil {
					return err
				}
				return optionErr
			}}
			listener, listenErr := lc.Listen(context.Background(), "tcp6", "[::]:8080")
			err = listenErr
			if err == nil {
				f.listener = listener.(*net.TCPListener)
			}
		} else {
			f.listener, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: f.pod.ip, Port: 8080})
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.listener.Close() })
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *handoffFixture) warmReload(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("/sys/fs/bpf", "vtep-socket-reload-")
	if err != nil {
		t.Fatal(err)
	}
	f.cleanup(func() { os.RemoveAll(dir) })
	// Fixture objects intentionally omit optional production maps. Preserve all
	// of their actual maps; the complete versioned agent graph is tested by the
	// controller lifecycle suite rather than invented here.
	ids := make(map[string]ebpf.MapID)
	for name, m := range f.collection.Maps {
		info, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		ids[name], _ = info.ID()
		if err := m.Pin(filepath.Join(dir, fmt.Sprintf("%x", name))); err != nil {
			t.Fatal(err)
		}
	}
	f.collection.Close()
	replacements := make(map[string]*ebpf.Map)
	for name, id := range ids {
		m, err := ebpf.LoadPinnedMap(filepath.Join(dir, fmt.Sprintf("%x", name)), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		info, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		if actual, _ := info.ID(); actual != id {
			t.Fatalf("%s changed map identity", name)
		}
		replacements[name] = m
	}
	// Exercise Cilium's actual collection loader, including the replacements
	// that prevent automatic map recreation on a compatible program reload.
	next, commit, err := bpf.LoadCollection(slog.New(slog.NewTextHandler(io.Discard, nil)), f.spec,
		&bpf.CollectionOptions{CollectionOptions: ebpf.CollectionOptions{MapReplacements: replacements}})
	if err != nil {
		t.Fatalf("reload using Cilium loader: %+v", err)
	}
	f.cleanup(next.Close)
	for name, attached := range f.attachments {
		if err := attached.Update(next.Programs[name]); err != nil {
			t.Fatalf("replace %s without detaching: %v", name, err)
		}
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	f.collection = next
}

func (f *handoffFixture) setControl(t *testing.T, ttl time.Duration) {
	t.Helper()
	if err := f.collection.Maps["cilium_vtep_sock_ctl4"].Update(f.cookie,
		handoffControl{Generation: 1, TTL: uint64(ttl), Phase: 1}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}
func (f *handoffFixture) trustPeer(t *testing.T, i int) {
	t.Helper()
	var value [8]byte
	copy(value[:], f.peerVTEP[i].Attrs().HardwareAddr)
	if err := f.collection.Maps["cilium_vtep_peers4"].Update(wireIP(f.under[i].ip), value, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}
func (f *handoffFixture) policy(t *testing.T, port uint32, flags uint32) {
	t.Helper()
	if f.core {
		// Match Cilium's wildcard identity/protocol/port entry in each
		// direction. Individual test connections use separate client ports.
		for direction := uint8(0); direction < 2; direction++ {
			key := struct {
				Prefix, Identity    uint32
				Direction, Protocol uint8
				Port                uint16
			}{Prefix: 40, Direction: direction}
			var value [12]byte
			if flags&(1<<direction) == 0 {
				value[2] = 1 // policy_entry.deny
			}
			if err := f.collection.Maps["cilium_policy"].Update(key, value, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	if err := f.collection.Maps["handoff_policy"].Update(port, flags, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}

func TestPrivilegedCiliumCoreHandoff(t *testing.T) {
	testutils.PrivilegedTest(t)
	if os.Getenv("VTEP_RETURN_ISOLATED_VM") != "1" {
		t.Skip("root cgroup integration requires the isolated VM")
	}
	object := os.Getenv("VTEP_RETURN_CORE_OBJECT")
	if object == "" {
		t.Skip("supply --core-object to privileged_vm.py")
	}
	f := newHandoffFixture(t, object)
	if !f.core {
		t.Fatal("the supplied object does not contain Cilium endpoint entrypoints")
	}
	aClient, aServer := f.connect(t, 0, 46000)
	bClient, bServer := f.connect(t, 1, 46001)
	aOwner, bOwner := f.owner(t, aServer), f.owner(t, bServer)
	t.Run("actual_Cilium_policy_CT_and_VXLAN_return_path", func(t *testing.T) {
		if aOwner.Peer != wireIP(f.under[0].ip) || bOwner.Peer != wireIP(f.under[1].ip) {
			t.Fatal("Cilium policy path assigned the wrong outer peer")
		}
		transferHandoff(t, aClient, aServer, "core-peer-A")
		transferHandoff(t, bClient, bServer, "core-peer-B")
		f.noPending(t)
	})
	t.Run("restart_and_link_replacement_with_established_Cilium_CT", func(t *testing.T) {
		f.warmReload(t)
		if f.owner(t, aServer) != aOwner || f.owner(t, bServer) != bOwner {
			t.Fatal("Cilium reload changed socket ownership")
		}
		transferHandoff(t, aClient, aServer, "core-A-after-reload")
		transferHandoff(t, bClient, bServer, "core-B-after-reload")
		client, server := f.connect(t, 1, 46002)
		transferHandoff(t, client, server, "core-new-handshake-after-reload")
		f.noPending(t)
	})
	t.Run("native_owner_bypasses_overlapping_legacy_VTEP_prefix", func(t *testing.T) {
		client, server := f.connect(t, -1, 46004)
		if owner := f.owner(t, server); owner.Origin != 1 || owner.Peer != 0 {
			t.Fatal("native ingress inherited the legacy VTEP prefix")
		}
		transferHandoff(t, client, server, "native-core-route")
	})
	t.Run("CT_loss_does_not_retarget_established_socket_owners", func(t *testing.T) {
		for _, name := range []string{"cilium_ct4_global", "cilium_ct_any4_global"} {
			m := f.collection.Maps[name]
			if m == nil {
				t.Fatalf("missing actual Cilium CT map %s", name)
			}
			for {
				key, err := m.NextKeyBytes(nil)
				if err != nil {
					t.Fatal(err)
				}
				if key == nil {
					break
				}
				if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatal(err)
				}
			}
		}
		transferHandoff(t, aClient, aServer, "core-A-after-CT-loss")
		transferHandoff(t, bClient, bServer, "core-B-after-CT-loss")
		if f.owner(t, aServer) != aOwner || f.owner(t, bServer) != bOwner {
			t.Fatal("CT recreation changed immutable socket ownership")
		}
	})
	t.Run("local_host_TCP_probe_uses_explicit_host_delivery", func(t *testing.T) {
		f.policy(t, 46005, 3)
		key := bpf.NewEndpointKey(netip.MustParseAddr("198.51.100.1"), 0)
		if err := f.collection.Maps["cilium_lxc"].Update(key, lxcmap.EndpointInfo{Flags: 1}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		defer f.collection.Maps["cilium_lxc"].Delete(key)
		var attached link.Link
		if err := f.router.Do(func() error {
			var err error
			attached, err = link.AttachTCX(link.TCXOptions{Interface: f.pod.host.Attrs().Index,
				Program: f.collection.Programs["handoff_from_host"], Attach: ebpf.AttachTCXEgress})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		defer attached.Close()
		capture, captureErr := packetSocketProtocol(f.podNS, f.pod.remote, unix.ETH_P_ALL)
		if captureErr != nil {
			t.Fatal(captureErr)
		}
		defer unix.Close(capture)
		unix.SetNonblock(capture, true)
		var client *net.TCPConn
		if err := f.router.Do(func() error {
			d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 46005}}
			c, err := d.Dial("tcp4", "198.51.100.10:8080")
			if err == nil {
				client = c.(*net.TCPConn)
			}
			return err
		}); err != nil {
			var debug struct {
				Error, SYNResult                                     int32
				Operation, Family                                    uint32
				SavedToken                                           uint64
				SavedLocal, SavedRemote, ContextLocal, ContextRemote uint32
			}
			f.collection.Maps["handoff_diagnostics"].Lookup(uint32(0), &debug)
			f.dumpCoreStatus(t)
			for n := 0; n < 12; n++ {
				b := make([]byte, 256)
				size, addr, captureErr := unix.Recvfrom(capture, b, 0)
				if captureErr != nil {
					break
				}
				t.Logf("host probe pod packet type=%v bytes=%x", addr, b[:size])
			}
			t.Fatalf("host probe: %v; counters=%+v diagnostics=%+v", err, f.counts(t), debug)
		}
		defer client.Close()
		f.listener.SetDeadline(time.Now().Add(3 * time.Second))
		server, err := f.listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		if owner := f.owner(t, server); owner.Origin != 1 || owner.Peer != 0 {
			t.Fatal("host probe was not natively owned")
		}
		transferHandoff(t, client, server, "kubelet-style-host-probe")
	})
	t.Run("actual_ingress_deny_does_not_create_admission", func(t *testing.T) {
		f.policy(t, 46003, 2)
		var before, after uint64
		if err := f.collection.Maps["cilium_vtep_nonce4"].Lookup(f.cookie, &before); err != nil {
			t.Fatal(err)
		}
		err := f.peerNS[0].Do(func() error {
			dialer := net.Dialer{Timeout: 150 * time.Millisecond,
				LocalAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 46003}}
			c, err := dialer.Dial("tcp4", "198.51.100.10:8080")
			if c != nil {
				c.Close()
			}
			return err
		})
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("policy denied connection did not time out: %v", err)
		}
		if err := f.collection.Maps["cilium_vtep_nonce4"].Lookup(f.cookie, &after); err != nil || after != before {
			t.Fatalf("denied ingress allocated an admission: %d -> %d (%v)", before, after, err)
		}
		f.noPending(t)
	})
}
func (f *handoffFixture) counts(t *testing.T) handoffCounts {
	t.Helper()
	var value handoffCounts
	if err := f.collection.Maps["handoff_stats"].Lookup(uint32(0), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func (f *handoffFixture) dumpCoreStatus(t *testing.T) {
	t.Helper()
	if m := f.collection.Maps["cilium_metrics"]; m != nil {
		it := m.Iterate()
		var key []byte
		var values []struct{ Count, Bytes uint64 }
		for it.Next(&key, &values) {
			var count uint64
			for _, v := range values {
				count += v.Count
			}
			if count > 0 {
				t.Logf("core metric key=%x packets=%d", key, count)
			}
		}
	}
	f.podNS.Do(func() error {
		data, _ := os.ReadFile("/proc/thread-self/net/snmp")
		t.Logf("pod kernel counters: %s", data)
		return nil
	})
}
func waitHandoff(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("hand-off condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
func (f *handoffFixture) pending(t *testing.T) (int, int) {
	t.Helper()
	var key handoffKey
	var ticket handoffTicket
	var request struct {
		Ticket handoffTicket
		Nonce  uint64
	}
	a, b := 0, 0
	it := f.collection.Maps["cilium_vtep_admit4"].Iterate()
	for it.Next(&key, &ticket) {
		a++
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	it = f.collection.Maps["cilium_vtep_req4"].Iterate()
	for it.Next(&key, &request) {
		b++
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return a, b
}
func (f *handoffFixture) noPending(t *testing.T) {
	t.Helper()
	if a, b := f.pending(t); a != 0 || b != 0 {
		t.Fatalf("handshake state leaked: admissions=%d requests=%d", a, b)
	}
}
func (f *handoffFixture) collect(t *testing.T) {
	t.Helper()
	ret, err := f.collection.Programs["handoff_collect"].Run(&ebpf.RunOptions{Data: make([]byte, 64)})
	if err != nil || ret != 0 {
		t.Fatalf("collect: retval=%d error=%v", ret, err)
	}
}
func (f *handoffFixture) owner(t *testing.T, conn *net.TCPConn) handoffOwner {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var owner handoffOwner
	var cookie uint64
	var readErr error
	if err := raw.Control(func(fd uintptr) {
		cookie, readErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		if readErr == nil {
			readErr = f.collection.Maps["cilium_vtep_sock4"].Lookup(uint32(fd), &owner)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if readErr != nil || cookie == 0 || owner.Cookie != cookie || owner.Namespace != f.cookie || owner.Generation != 1 {
		t.Fatalf("invalid socket binding: %+v error=%v", owner, readErr)
	}
	return owner
}
func (f *handoffFixture) connect(t *testing.T, peer, port int) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	if f.collection != nil {
		f.policy(t, uint32(port), 3)
	}
	ns, source := f.nativeNS, "203.0.113.10"
	if peer >= 0 {
		ns, source = f.peerNS[peer], "203.0.113.9"
	}
	var client *net.TCPConn
	if err := ns.Do(func() error {
		dialer := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source), Port: port},
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
		if f.collection == nil {
			t.Fatalf("TCP connect via peer %d: %v", peer, err)
		}
		f.dumpCoreStatus(t)
		t.Fatalf("TCP connect via peer %d: %v; counters=%+v", peer, err, f.counts(t))
	}
	cleanup := t.Cleanup
	if f.collection == nil {
		cleanup = f.cleanup
	}
	cleanup(func() { client.Close() })
	f.listener.SetDeadline(time.Now().Add(3 * time.Second))
	server, err := f.listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	cleanup(func() { server.Close() })
	if !server.RemoteAddr().(*net.TCPAddr).IP.Equal(net.ParseIP(source)) ||
		!client.RemoteAddr().(*net.TCPAddr).IP.Equal(f.pod.ip) {
		t.Fatal("inner client/pod addresses were translated")
	}
	return client, server
}
func transferHandoff(t *testing.T, client, server *net.TCPConn, payload string) {
	t.Helper()
	server.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(server, payload); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != payload {
		t.Fatalf("TCP application transfer: %v", err)
	}
}
func (f *handoffFixture) inject(t *testing.T, peer, port int, sourceMAC net.HardwareAddr) {
	t.Helper()
	ns, iface, sourceIP, destination := f.nativeNS, f.native.remote, f.native.ip, f.native.host.Attrs().HardwareAddr
	if peer >= 0 {
		ns, iface, sourceIP, destination = f.peerNS[peer], f.peerVTEP[peer], net.ParseIP("203.0.113.9").To4(), f.nodeVTEP.Attrs().HardwareAddr
	}
	fd, err := packetSocket(ns, iface)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if sourceMAC == nil {
		sourceMAC = iface.Attrs().HardwareAddr
	}
	packet := make([]byte, 54)
	copy(packet[:6], destination)
	copy(packet[6:12], sourceMAC)
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
	ip, tcp := packet[14:34], packet[34:]
	ip[0], ip[8], ip[9] = 0x45, 64, unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(ip[2:4], 40)
	copy(ip[12:16], sourceIP)
	copy(ip[16:20], f.pod.ip)
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	binary.BigEndian.PutUint16(tcp[:2], uint16(port))
	binary.BigEndian.PutUint16(tcp[2:4], 8080)
	binary.BigEndian.PutUint32(tcp[4:8], uint32(port)*100)
	tcp[12], tcp[13] = 0x50, 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 4096)
	pseudo := append([]byte{}, ip[12:20]...)
	pseudo = append(pseudo, 0, unix.IPPROTO_TCP, 0, 20)
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: iface.Attrs().Index, Halen: 6}); err != nil {
		t.Fatal(err)
	}
}

func TestPrivilegedSocketHandoff(t *testing.T) {
	testutils.PrivilegedTest(t)
	if os.Getenv("VTEP_RETURN_ISOLATED_VM") != "1" {
		t.Skip("root cgroup integration requires the isolated VM")
	}
	object := os.Getenv("VTEP_RETURN_HANDOFF_OBJECT")
	if object == "" {
		t.Skip("supply --handoff-object to privileged_vm.py")
	}
	f := newHandoffFixture(t, object)
	firstClient, firstServer := f.connect(t, 0, 45000)
	secondClient, secondServer := f.connect(t, 1, 45001)
	firstOwner, secondOwner := f.owner(t, firstServer), f.owner(t, secondServer)
	if firstOwner.Peer != wireIP(f.under[0].ip) || secondOwner.Peer != wireIP(f.under[1].ip) ||
		firstOwner.Origin != 2 || secondOwner.Origin != 2 || firstOwner.Cookie == secondOwner.Cookie {
		t.Fatal("wrong tunnel-to-socket bindings")
	}
	t.Run("real_VXLAN_ingress_assigns_independent_sockets_and_reclaims_tickets", func(t *testing.T) {
		f.noPending(t)
		transferHandoff(t, firstClient, firstServer, "reply-through-peer-A")
		transferHandoff(t, secondClient, secondServer, "reply-through-peer-B")
		if f.counts(t).AssignmentFailed != 0 {
			t.Fatalf("assignment errors: %+v", f.counts(t))
		}
	})
	t.Run("warm_restart_and_program_reload_preserve_live_socket_owners", func(t *testing.T) {
		f.warmReload(t)
		if f.owner(t, firstServer) != firstOwner || f.owner(t, secondServer) != secondOwner {
			t.Fatal("reload changed established ownership")
		}
		transferHandoff(t, firstClient, firstServer, "peer-A-after-controller-restart")
		transferHandoff(t, secondClient, secondServer, "peer-B-after-controller-restart")
		client, server := f.connect(t, 0, 45003)
		transferHandoff(t, client, server, "new-handshake-after-program-reload")
		f.noPending(t)
	})
	t.Run("native_ingress_is_explicitly_owned", func(t *testing.T) {
		client, server := f.connect(t, -1, 45002)
		owner := f.owner(t, server)
		if owner.Origin != 1 || owner.Peer != 0 {
			t.Fatal("native traffic inherited a tunnel")
		}
		transferHandoff(t, client, server, "native-route")
		f.noPending(t)
	})
	t.Run("half_close_keeps_socket_ownership_without_ticket", func(t *testing.T) {
		if err := firstClient.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		firstServer.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := firstServer.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatalf("half-close: %d %v", n, err)
		}
		transferHandoff(t, firstClient, firstServer, "reply-after-FIN-without-flow-record")
		if f.owner(t, firstServer) != firstOwner {
			t.Fatal("half-close changed ownership")
		}
		f.noPending(t)
	})
	t.Run("policy_denied_and_untrusted_SYN_create_no_ticket", func(t *testing.T) {
		f.policy(t, 45100, 0)
		before := f.counts(t)
		f.inject(t, 0, 45100, nil)
		waitHandoff(t, func() bool { return f.counts(t).IngressDenied > before.IngressDenied })
		f.policy(t, 45101, 3)
		if err := f.collection.Maps["cilium_vtep_peers4"].Delete(wireIP(f.under[1].ip)); err != nil {
			t.Fatal(err)
		}
		f.inject(t, 1, 45101, nil)
		waitHandoff(t, func() bool { return f.counts(t).Untrusted > before.Untrusted })
		f.trustPeer(t, 1)
		f.noPending(t)
	})
	t.Run("forged_Ethernet_token_does_not_grant_a_tunnel_peer", func(t *testing.T) {
		f.setControl(t, 200*time.Millisecond)
		f.policy(t, 45103, 3)
		before := f.counts(t)
		f.inject(t, -1, 45103, net.HardwareAddr{2, 0, 0, 0, 0, 1})
		waitHandoff(t, func() bool { return f.counts(t).Admitted > before.Admitted })
		var key handoffKey
		var ticket handoffTicket
		it := f.collection.Maps["cilium_vtep_admit4"].Iterate()
		if !it.Next(&key, &ticket) || key.Token == 1 || ticket.Peer != 0 || ticket.Origin != 1 || ticket.Flow.ClientPort != wire16(45103) {
			t.Fatal("a workload-supplied MAC became trusted peer evidence")
		}
		time.Sleep(250 * time.Millisecond)
		f.collect(t)
		f.noPending(t)
		f.setControl(t, 30*time.Second)
	})
	t.Run("pod_initiated_TCP_has_explicit_native_ownership", func(t *testing.T) {
		f.policy(t, 46000, 3)
		var listener *net.TCPListener
		if err := f.nativeNS.Do(func() error {
			var err error
			listener, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: f.native.ip, Port: 46000})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		var podConn *net.TCPConn
		if err := f.podNS.Do(func() error {
			conn, err := (&net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: f.pod.ip}}).Dial("tcp4", "203.0.113.10:46000")
			if err == nil {
				podConn = conn.(*net.TCPConn)
			}
			return err
		}); err != nil {
			t.Fatalf("pod-initiated TCP: %v; counters=%+v", err, f.counts(t))
		}
		defer podConn.Close()
		listener.SetDeadline(time.Now().Add(3 * time.Second))
		nativeConn, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer nativeConn.Close()
		owner := f.owner(t, podConn)
		if owner.Origin != 1 || owner.Peer != 0 {
			t.Fatal("outbound socket was not explicitly native")
		}
		transferHandoff(t, nativeConn, podConn, "pod-initiated-native-output")
		if !nativeConn.RemoteAddr().(*net.TCPAddr).IP.Equal(f.pod.ip) {
			t.Fatal("pod source address was translated")
		}
		f.noPending(t)
	})
	t.Run("existing_owner_cannot_override_egress_policy", func(t *testing.T) {
		client, server := f.connect(t, 0, 45102)
		f.policy(t, 45102, 1)
		before := f.counts(t)
		if _, err := server.Write([]byte("denied-reply")); err != nil {
			t.Fatal(err)
		}
		waitHandoff(t, func() bool { return f.counts(t).ReplyDrop > before.ReplyDrop })
		client.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		if _, err := client.Read(make([]byte, 32)); err == nil {
			t.Fatal("policy-denied reply arrived")
		}
		client.SetLinger(0)
		client.Close()
		server.Close()
		f.noPending(t)
	})
	t.Run("active_endpoint_churn_and_cross_peer_tuple_reuse", func(t *testing.T) {
		seen := map[uint64]bool{}
		for i := range 24 { // More completed handshakes than the eight-slot maps.
			client, server := f.connect(t, i%2, 45004)
			owner := f.owner(t, server)
			if seen[owner.Cookie] || owner.Peer != wireIP(f.under[i%2].ip) {
				t.Fatal("tuple reuse inherited ownership")
			}
			seen[owner.Cookie] = true
			transferHandoff(t, client, server, fmt.Sprintf("generation-%d", i))
			f.noPending(t)
			client.SetLinger(0)
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			server.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := server.Read(make([]byte, 1)); err == nil {
				t.Fatal("client reset was not observed")
			}
			// Keep the CLOSED server FD alive until test cleanup. Its storage
			// must remain independent from later sockets reusing the tuple.
			if f.owner(t, server) != owner {
				t.Fatal("closed socket binding changed")
			}
		}
		transferHandoff(t, secondClient, secondServer, "long-lived-flow-after-churn")
	})
	t.Run("queued_old_SYNACK_drops_after_handoff_and_tuple_reuse", func(t *testing.T) {
		var qdisc netlink.Qdisc
		if err := f.podNS.Do(func() error {
			qdisc = netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: f.pod.remote.Attrs().Index,
				Parent: netlink.HANDLE_ROOT, Handle: netlink.MakeHandle(1, 0)},
				netlink.NetemQdiscAttrs{Latency: 1_000_000, Limit: 64, Duplicate: 100, ReorderProb: 100, Gap: 2})
			return netlink.QdiscAdd(qdisc)
		}); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if qdisc != nil {
				if err := f.podNS.Do(func() error { return netlink.QdiscDel(qdisc) }); err != nil {
					t.Error(err)
				}
			}
		}()
		started := time.Now()
		oldClient, oldServer := f.connect(t, 0, 45005)
		if time.Since(started) > 500*time.Millisecond {
			t.Fatal("no immediate SYN-ACK copy; queue test did not establish its precondition")
		}
		oldOwner := f.owner(t, oldServer)
		f.noPending(t)
		oldClient.SetLinger(0)
		if err := oldClient.Close(); err != nil {
			t.Fatal(err)
		}
		oldServer.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := oldServer.Read(make([]byte, 1)); err == nil {
			t.Fatal("old connection did not reset")
		}
		newClient, newServer := f.connect(t, 1, 45005)
		newOwner := f.owner(t, newServer)
		if oldOwner.Cookie == newOwner.Cookie || newOwner.Peer != wireIP(f.under[1].ip) {
			t.Fatal("queued tuple reuse inherited ownership")
		}
		f.noPending(t)
		before := f.counts(t)
		time.Sleep(1200 * time.Millisecond)
		after := f.counts(t)
		if after.SynAckDrop <= before.SynAckDrop || after.Tunnel != before.Tunnel {
			t.Fatalf("queued SYN-ACKs did not fail closed: before=%+v after=%+v", before, after)
		}
		if f.owner(t, oldServer) != oldOwner || f.owner(t, newServer) != newOwner {
			t.Fatal("queue changed socket ownership")
		}
		if err := f.podNS.Do(func() error { return netlink.QdiscDel(qdisc) }); err != nil {
			t.Fatal(err)
		}
		qdisc = nil
		// Test an actual delayed data skb, not Netem's orphaned duplicate.
		// Read only after closing the server FD: delivery then proves that
		// queued output still uses the original socket's peer ownership.
		if err := f.podNS.Do(func() error {
			qdisc = netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: f.pod.remote.Attrs().Index,
				Parent: netlink.HANDLE_ROOT, Handle: netlink.MakeHandle(1, 0)},
				netlink.NetemQdiscAttrs{Latency: 250_000, Limit: 64})
			return netlink.QdiscAdd(qdisc)
		}); err != nil {
			t.Fatal(err)
		}
		const payload = "queued-data-after-FD-close"
		newServer.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(newServer, payload); err != nil {
			t.Fatal(err)
		}
		if err := newServer.Close(); err != nil {
			t.Fatal(err)
		}
		newClient.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(newClient, buf); err != nil || string(buf) != payload {
			t.Fatalf("queued output did not retain its socket ownership after FD close: %v", err)
		}
		if err := f.podNS.Do(func() error { return netlink.QdiscDel(qdisc) }); err != nil {
			t.Fatal(err)
		}
		qdisc = nil
		transferHandoff(t, secondClient, secondServer, "long-lived-flow-after-queue-test")
	})
	t.Run("pending_pressure_and_expiry_do_not_affect_established_sockets", func(t *testing.T) {
		f.setControl(t, time.Second)
		for i := range 8 {
			f.policy(t, uint32(45200+i), 3)
			f.inject(t, 0, 45200+i, nil)
		}
		waitHandoff(t, func() bool { a, _ := f.pending(t); return a == 8 })
		before := f.counts(t)
		f.policy(t, 45208, 3)
		f.inject(t, 0, 45208, nil)
		waitHandoff(t, func() bool { return f.counts(t).AdmissionFailed > before.AdmissionFailed })
		transferHandoff(t, secondClient, secondServer, "existing-flow-during-pressure")
		time.Sleep(1100 * time.Millisecond)
		f.collect(t)
		f.noPending(t)
		transferHandoff(t, firstClient, firstServer, "existing-half-closed-flow-after-GC")
		f.setControl(t, 30*time.Second)
	})
	t.Run("nonce_saturation_rejects_new_admissions_without_wrap", func(t *testing.T) {
		const maximum = uint64(1<<46) - 1
		if err := f.collection.Maps["cilium_vtep_nonce4"].Update(f.cookie, maximum, ebpf.UpdateExist); err != nil {
			t.Fatal(err)
		}
		before := f.counts(t)
		f.policy(t, 45300, 3)
		f.inject(t, 0, 45300, nil)
		waitHandoff(t, func() bool { return f.counts(t).AdmissionFailed > before.AdmissionFailed })
		var actual uint64
		if err := f.collection.Maps["cilium_vtep_nonce4"].Lookup(f.cookie, &actual); err != nil || actual != maximum {
			t.Fatal("nonce counter wrapped")
		}
		f.noPending(t)
		transferHandoff(t, secondClient, secondServer, "existing-flow-after-nonce-saturation")
	})
	t.Run("missing_socket_owner_never_becomes_native", func(t *testing.T) {
		raw, err := firstServer.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var deleteErr error
		if err := raw.Control(func(fd uintptr) { deleteErr = f.collection.Maps["cilium_vtep_sock4"].Delete(uint32(fd)) }); err != nil || deleteErr != nil {
			t.Fatalf("delete owner: %v %v", err, deleteErr)
		}
		before := f.counts(t)
		firstServer.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if _, err := firstServer.Write([]byte("unknown-owner")); err != nil {
			t.Fatal(err)
		}
		waitHandoff(t, func() bool { return f.counts(t).ReplyDrop > before.ReplyDrop })
		firstClient.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		if _, err := firstClient.Read(make([]byte, 32)); err == nil {
			t.Fatal("unowned reply arrived")
		}
	})
	t.Run("missing_readiness_blocks_even_a_retained_owner", func(t *testing.T) {
		if err := f.collection.Maps["cilium_vtep_sock_ctl4"].Delete(f.cookie); err != nil {
			t.Fatal(err)
		}
		before := f.counts(t)
		secondServer.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if _, err := secondServer.Write([]byte("unready-endpoint")); err != nil {
			t.Fatal(err)
		}
		waitHandoff(t, func() bool { return f.counts(t).ReplyDrop > before.ReplyDrop })
		secondClient.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		if _, err := secondClient.Read(make([]byte, 32)); err == nil {
			t.Fatal("unready reply arrived")
		}
	})
}
