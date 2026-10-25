// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/netns"
)

func inspectNamespace(r EndpointRegistration, fresh bool) (int, error) {
	host, err := netlink.LinkByName(r.HostInterface)
	if err != nil {
		return 0, err
	}
	veth, ok := host.(*netlink.Veth)
	if !ok || host.Attrs().Index != r.HostIfindex {
		return 0, fmt.Errorf("return affinity requires the registered host veth")
	}
	peerIndex, err := netlink.VethPeerIndex(veth)
	if err != nil {
		return 0, err
	}
	ns, err := netns.OpenPinned(r.NamespacePath)
	if err != nil {
		return 0, err
	}
	defer ns.Close()
	err = ns.Do(func() error {
		cookie, err := netns.GetNetNSCookie()
		if err != nil {
			return err
		}
		if cookie != r.Cookie {
			return fmt.Errorf("CNI namespace cookie changed")
		}
		peer, err := netlink.LinkByName(r.ContainerInterface)
		if err != nil {
			return err
		}
		if peer.Type() != "veth" || peer.Attrs().Index != peerIndex {
			return fmt.Errorf("CNI interface is not the registered veth peer")
		}
		if fresh {
			// A retry must not retrofit listeners that predate the sockops
			// hook. CNI ADD ordering prevents application startup racing this
			// check. thread-self follows the OS thread switched by ns.Do.
			for _, path := range []string{"/proc/thread-self/net/tcp", "/proc/thread-self/net/tcp6"} {
				data, err := os.ReadFile(path)
				if missing(err) && strings.HasSuffix(path, "tcp6") {
					continue
				}
				if err != nil {
					return err
				}
				if len(strings.Split(strings.TrimSpace(string(data)), "\n")) > 1 {
					return fmt.Errorf("fresh CNI namespace already has TCP sockets; replace the pod before selecting affinity")
				}
			}
		}
		return nil
	})
	return peerIndex, err
}

func (c *Controller) queuePath(cookie uint64) string {
	return filepath.Join(c.cfg.Pins, "queues", strconv.FormatUint(cookie, 10))
}

func (c *Controller) installQueue(m membership) error {
	ns, err := netns.OpenPinned(m.NamespacePath)
	if err != nil {
		return err
	}
	defer ns.Close()
	spec := c.spec.Copy()
	for name := range spec.Programs {
		if name != "cil_vtep_before_queue" {
			delete(spec.Programs, name)
		}
	}
	if err := spec.Variables["vtep_queue_cookie"].Set(m.Cookie); err != nil {
		return err
	}
	replacements, err := c.bundle.MapReplacements(spec)
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements})
	if err != nil {
		return err
	}
	defer coll.Close()
	if err := os.MkdirAll(filepath.Dir(c.queuePath(m.Cookie)), 0700); err != nil {
		return err
	}
	err = ns.Do(func() error {
		if l, err := link.LoadPinnedLink(c.queuePath(m.Cookie), nil); err == nil {
			defer l.Close()
			return l.Update(coll.Programs["cil_vtep_before_queue"])
		} else if !missing(err) {
			return err
		}
		l, err := link.AttachTCX(link.TCXOptions{Interface: m.QueueIfindex,
			Program: coll.Programs["cil_vtep_before_queue"], Attach: ebpf.AttachTCXEgress,
			Anchor: link.Head()})
		if err != nil {
			return err
		}
		defer l.Close()
		return l.Pin(c.queuePath(m.Cookie))
	})
	if err == nil {
		c.queuesLoaded[m.Cookie] = true
	}
	return err
}

func (c *Controller) checkQueue(m membership) error {
	index, err := inspectNamespace(m.EndpointRegistration, false)
	if err != nil {
		return err
	}
	if index != m.QueueIfindex {
		return fmt.Errorf("CNI veth peer was replaced")
	}
	l, err := link.LoadPinnedLink(c.queuePath(m.Cookie), nil)
	if err != nil {
		return fmt.Errorf("restore pre-queue link: %w", err)
	}
	defer l.Close()
	info, err := l.Info()
	if err != nil {
		return err
	}
	tcx := info.TCX()
	if tcx == nil || int(tcx.Ifindex) != index || ebpf.AttachType(tcx.AttachType) != ebpf.AttachTCXEgress {
		return fmt.Errorf("pre-queue link identity changed")
	}
	return nil
}

func (c *Controller) validateRestoredLinks() error {
	l, err := link.LoadPinnedLink(filepath.Join(c.cfg.Pins, "sockops"), nil)
	if err != nil {
		return fmt.Errorf("restore node sockops link: %w", err)
	}
	defer l.Close()
	info, err := l.Info()
	if err != nil {
		return err
	}
	if cg := info.Cgroup(); cg == nil || ebpf.AttachType(cg.AttachType) != ebpf.AttachCGroupSockOps {
		return fmt.Errorf("node sockops link identity changed")
	}
	for cookie, m := range c.journal.Namespaces {
		if m.Phase == "retired" {
			if err := drained(m); err != nil {
				if err := c.checkRetiredGuard(m); err != nil {
					return err
				}
			}
			continue
		}
		if err := drained(m); err == nil {
			if err := c.retireControl(cookie); err != nil {
				return err
			}
			m.Phase = "retired"
			c.journal.Namespaces[cookie] = m
			if err := writeJournal(c.cfg.Journal, c.journal); err != nil {
				return err
			}
			for _, name := range []string{SocketControlMap, SocketNonceMap} {
				if err := c.bundle.maps[name].Delete(cookie); err != nil && err != ebpf.ErrKeyNotExist {
					return err
				}
			}
			continue
		}
		if m.Phase != "ready" {
			return fmt.Errorf("incomplete namespace setup; replace the selected pod")
		}
		if err := c.checkControl(cookie); err != nil {
			return err
		}
		if err := c.checkQueue(m); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) checkRetiredGuard(m membership) error {
	path := filepath.Join(c.cfg.Pins, "retired", strconv.FormatUint(m.Cookie, 10))
	l, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		return fmt.Errorf("retired endpoint lost its routing guard: %w", err)
	}
	defer l.Close()
	info, err := l.Info()
	if err != nil {
		return err
	}
	if tcx := info.TCX(); tcx == nil || int(tcx.Ifindex) != m.HostIfindex || ebpf.AttachType(tcx.AttachType) != ebpf.AttachTCXIngress {
		return fmt.Errorf("retired endpoint guard identity changed")
	}
	return nil
}

func (c *Controller) collectRetiredLinks() error {
	next := c.journal
	next.Namespaces = maps.Clone(c.journal.Namespaces)
	next.Retired = append([]cookieRange(nil), c.journal.Retired...)
	changed := false
	for cookie, m := range c.journal.Namespaces {
		if m.Phase != "retired" || drained(m) != nil {
			continue
		}
		for _, path := range []string{c.queuePath(cookie), filepath.Join(c.cfg.Pins, "retired", strconv.FormatUint(cookie, 10))} {
			if err := os.Remove(path); err != nil && !missing(err) {
				return err
			}
		}
		// Physical drain permits discarding interface/path metadata, never
		// the exact cookie tombstone. Publish compressed history atomically.
		next.rememberRetired(cookie)
		delete(next.Namespaces, cookie)
		changed = true
	}
	if changed {
		if err := writeJournal(c.cfg.Journal, next); err != nil {
			return err
		}
		c.journal = next
		for cookie := range c.queuesLoaded {
			if next.retired(cookie) {
				delete(c.queuesLoaded, cookie)
			}
		}
	}
	return nil
}

func (c *Controller) installRetiredGuard(m membership) error {
	iface, err := netlink.LinkByName(m.HostInterface)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return nil
		}
		return err
	}
	if iface.Attrs().Index != m.HostIfindex {
		return nil
	} // Old device is gone.
	path := filepath.Join(c.cfg.Pins, "retired", strconv.FormatUint(m.Cookie, 10))
	if l, err := link.LoadPinnedLink(path, nil); err == nil {
		l.Close()
		return c.checkRetiredGuard(m)
	} else if !missing(err) {
		return err
	}
	if c.retired == nil {
		return fmt.Errorf("retirement guard is not loaded")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	l, err := link.AttachTCX(link.TCXOptions{Interface: m.HostIfindex, Program: c.retired,
		Attach: ebpf.AttachTCXIngress, Anchor: link.Head()})
	if err != nil {
		return err
	}
	defer l.Close()
	return l.Pin(path)
}
