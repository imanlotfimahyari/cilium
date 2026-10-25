// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package live contains isolated real-kernel socket, endpoint and agent tests.
package live

import (
	"encoding/binary"
	"net"

	"github.com/cilium/cilium/pkg/netns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type fixtureLink struct {
	host, remote netlink.Link
	ip           net.IP
}

// Called in the isolated router namespace. No host networking is modified.
func makeLink(name, localCIDR, remoteCIDR string, ns *netns.NetNS) (fixtureLink, error) {
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "-r"}
	if err := netlink.LinkAdd(veth); err != nil {
		return fixtureLink{}, err
	}
	host, err := netlink.LinkByName(name)
	if err != nil {
		return fixtureLink{}, err
	}
	remote, err := netlink.LinkByName(name + "-r")
	if err != nil {
		return fixtureLink{}, err
	}
	addr, err := netlink.ParseAddr(localCIDR)
	if err != nil {
		return fixtureLink{}, err
	}
	if err := netlink.AddrAdd(host, addr); err != nil {
		return fixtureLink{}, err
	}
	if err := netlink.LinkSetUp(host); err != nil {
		return fixtureLink{}, err
	}
	if err := netlink.LinkSetNsFd(remote, ns.FD()); err != nil {
		return fixtureLink{}, err
	}
	var remoteIP net.IP
	err = ns.Do(func() error {
		remote, err = netlink.LinkByName(name + "-r")
		if err != nil {
			return err
		}
		addr, err := netlink.ParseAddr(remoteCIDR)
		if err != nil {
			return err
		}
		remoteIP = addr.IP.To4()
		if err := netlink.AddrAdd(remote, addr); err != nil {
			return err
		}
		return netlink.LinkSetUp(remote)
	})
	if err != nil {
		return fixtureLink{}, err
	}
	if err := netlink.NeighSet(&netlink.Neigh{LinkIndex: host.Attrs().Index,
		IP: remoteIP, HardwareAddr: remote.Attrs().HardwareAddr, State: netlink.NUD_PERMANENT}); err != nil {
		return fixtureLink{}, err
	}
	return fixtureLink{host, remote, remoteIP}, nil
}

func packetSocket(ns *netns.NetNS, iface netlink.Link) (int, error) {
	return packetSocketProtocol(ns, iface, unix.ETH_P_IP)
}

func packetSocketProtocol(ns *netns.NetNS, iface netlink.Link, protocol uint16) (int, error) {
	fd := -1
	err := ns.Do(func() error {
		var err error
		fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(wire16(protocol)))
		if err != nil {
			return err
		}
		return unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Attrs().Index, Protocol: wire16(protocol)})
	})
	if err != nil && fd >= 0 {
		unix.Close(fd)
	}
	return fd, err
}

func wire16(n uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], n)
	return binary.NativeEndian.Uint16(b[:])
}

func wireIP(ip net.IP) uint32 { return binary.NativeEndian.Uint32(ip.To4()) }

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}
