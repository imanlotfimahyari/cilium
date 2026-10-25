// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/maps/ipcache"
)

// Use actual VXLAN metadata with a Cilium workload identity/VNI and an IP-cache
// node mapping, alongside an external WORLD/VNI-2 peer sharing the client IP.
// This exercises the real endpoint policy/CT/return path with permissive test
// policy, not Kubernetes/CNI or isolation between overlapping network tenants.
func TestPrivilegedNativeClusterAndExternalVTEPCoexist(t *testing.T) {
	f := newHandoffFixture(t, tcpModeObject(t, "VTEP_RETURN_CORE_OBJECT"))
	if err := f.collection.Maps["cilium_vtep_peers4"].Delete(wireIP(f.under[0].ip)); err != nil {
		t.Fatal(err)
	}
	if err := f.peerNS[0].Do(func() error {
		if err := netlink.LinkDel(f.peerVTEP[0]); err != nil {
			return err
		}
		v := &netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "h-peer-vtep"},
			VxlanId: 1234, VtepDevIndex: f.under[0].remote.Attrs().Index, SrcAddr: f.under[0].ip,
			Group: net.ParseIP("192.0.2.1"), Port: 8472}
		if err := netlink.LinkAdd(v); err != nil {
			return err
		}
		var err error
		f.peerVTEP[0], err = netlink.LinkByName("h-peer-vtep")
		if err != nil {
			return err
		}
		addr, _ := netlink.ParseAddr("203.0.113.9/32")
		if err := netlink.AddrAdd(f.peerVTEP[0], addr); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(f.peerVTEP[0]); err != nil {
			return err
		}
		receiver, err := link.AttachTCX(link.TCXOptions{Interface: f.peerVTEP[0].Attrs().Index,
			Program: f.collection.Programs["handoff_remote_receive"], Attach: ebpf.AttachTCXIngress})
		if err != nil {
			return err
		}
		t.Cleanup(func() { receiver.Close() })
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: f.peerVTEP[0].Attrs().Index,
			Dst: &net.IPNet{IP: f.pod.ip, Mask: net.CIDRMask(32, 32)}, Scope: netlink.SCOPE_LINK}); err != nil {
			return err
		}
		return netlink.NeighSet(&netlink.Neigh{LinkIndex: f.peerVTEP[0].Attrs().Index, IP: f.pod.ip,
			HardwareAddr: f.nodeVTEP.Attrs().HardwareAddr, State: netlink.NUD_PERMANENT})
	}); err != nil {
		t.Fatal(err)
	}
	key := ipcache.NewKey(netip.MustParsePrefix("203.0.113.9/32"), 0)
	value := ipcache.NewValue(1234, netip.MustParseAddr("192.0.2.2"), 0, 0)
	if err := f.collection.Maps["cilium_ipcache_v2"].Update(key, value, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	capture, err := packetSocketProtocol(f.peerNS[0], f.under[0].remote, unix.ETH_P_ALL)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(capture)
	unix.SetNonblock(capture, true)
	defer func() {
		if !t.Failed() {
			return
		}
		for n := 0; n < 12; n++ {
			b := make([]byte, 256)
			size, _, err := unix.Recvfrom(capture, b, 0)
			if err != nil {
				break
			}
			t.Logf("cluster peer underlay packet: %x", b[:size])
		}
	}()
	clusterClient, clusterServer := f.connect(t, 0, 48200)
	externalClient, externalServer := f.connect(t, 1, 48201)
	if owner := f.owner(t, clusterServer); owner.Origin != 1 || owner.Peer != 0 {
		t.Fatal("Cilium overlay acquired an external peer")
	}
	if owner := f.owner(t, externalServer); owner.Origin != 2 || owner.Peer != wireIP(f.under[1].ip) {
		t.Fatal("external VTEP lost its exact peer")
	}
	transferHandoff(t, clusterClient, clusterServer, "native-Cilium-overlay")
	transferHandoff(t, externalClient, externalServer, "external-VTEP-same-client-address")
	f.noPending(t)
}
