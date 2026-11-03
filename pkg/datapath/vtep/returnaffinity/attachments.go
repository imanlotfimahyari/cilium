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
	"golang.org/x/sys/unix"

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

func (c *Controller) cookieIngressPath(cookie uint64) string {
	return filepath.Join(c.cfg.Pins, "cookie_ingress", strconv.FormatUint(cookie, 10))
}

type queueIdentity struct {
	Link    link.ID
	Program ebpf.ProgramID
}

func (c *Controller) installQueue(m membership) error {
	ns, err := netns.OpenPinned(m.NamespacePath)
	if err != nil {
		return err
	}
	defer ns.Close()
	spec := c.spec.Copy()
	for name := range spec.Programs {
		if name != "cil_vtep_before_queue" && name != "cil_vtep_cookie_ingress" {
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
	// Both directions are installed before publishing namespace readiness.
	// Preserve link identities on restart; never detach a live guard to update it.
	for _, hook := range []struct {
		path, program string
		attach        ebpf.AttachType
	}{
		{c.cookieIngressPath(m.Cookie), "cil_vtep_cookie_ingress", ebpf.AttachTCXIngress},
		{c.queuePath(m.Cookie), "cil_vtep_before_queue", ebpf.AttachTCXEgress},
	} {
		if err := os.MkdirAll(filepath.Dir(hook.path), 0700); err != nil {
			return err
		}
		if err := ns.Do(func() error {
			l, err := link.LoadPinnedLink(hook.path, nil)
			if err == nil {
				defer l.Close()
				if err := l.Update(coll.Programs[hook.program]); err != nil {
					return err
				}
			} else {
				if !missing(err) {
					return err
				}
				l, err = link.AttachTCX(link.TCXOptions{Interface: m.QueueIfindex, Program: coll.Programs[hook.program], Attach: hook.attach, Anchor: link.Head()})
				if err != nil {
					return err
				}
				defer l.Close()
				if err := l.Pin(hook.path); err != nil {
					return err
				}
			}
			info, err := l.Info()
			if err != nil {
				return err
			}
			c.queueIdentities[hook.path] = queueIdentity{info.ID, info.Program}
			return nil
		}); err != nil {
			return err
		}
	}
	c.queuesLoaded[m.Cookie] = true
	return nil
}

func (c *Controller) checkQueue(m membership) error {
	index, err := inspectNamespace(m.EndpointRegistration, false)
	if err != nil {
		return err
	}
	if index != m.QueueIfindex {
		return fmt.Errorf("CNI veth peer was replaced")
	}
	for _, hook := range []struct {
		path, program string
		attach        ebpf.AttachType
		required      []string
	}{
		{c.queuePath(m.Cookie), "cil_vtep_before_queue", ebpf.AttachTCXEgress, []string{CookiePacketMap, CookieLedgerMap, SocketControlMap}},
		{c.cookieIngressPath(m.Cookie), "cil_vtep_cookie_ingress", ebpf.AttachTCXIngress, []string{CookieACKMap, CookieLedgerMap, SocketOwnerMap, SocketControlMap}},
	} {
		if err := c.checkQueueHook(m.Cookie, index, hook.path, hook.program, hook.attach, hook.required); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) checkQueueHook(cookie uint64, index int, path, program string, attach ebpf.AttachType, required []string) error {
	l, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		return fmt.Errorf("restore %s link: %w", program, err)
	}
	defer l.Close()
	info, err := l.Info()
	if err != nil {
		return err
	}
	tcx := info.TCX()
	if tcx == nil || int(tcx.Ifindex) != index || ebpf.AttachType(tcx.AttachType) != attach {
		return fmt.Errorf("%s link attachment changed", program)
	}
	if expected, ok := c.queueIdentities[path]; ok && expected != (queueIdentity{info.ID, info.Program}) {
		return fmt.Errorf("%s managed link identity changed", program)
	}
	p, err := ebpf.NewProgramFromID(info.Program)
	if err != nil {
		return err
	}
	defer p.Close()
	pi, err := p.Info()
	if err != nil {
		return err
	}
	if pi.Type != ebpf.SchedCLS || (pi.Name != program && pi.Name != program[:15]) {
		return fmt.Errorf("%s program identity changed", program)
	}
	ids, ok := pi.MapIDs()
	if !ok {
		return fmt.Errorf("%s map identities unavailable", program)
	}
	canonical := make(map[ebpf.MapID]string)
	for name, m := range c.bundle.maps {
		mi, err := m.Info()
		if err != nil {
			return err
		}
		id, ok := mi.ID()
		if !ok {
			return fmt.Errorf("canonical map identity unavailable")
		}
		canonical[id] = name
	}
	seen := make(map[string]bool)
	constants := 0
	for _, id := range ids {
		if name, ok := canonical[id]; ok {
			seen[name] = true
			continue
		}
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return err
		}
		mi, err := m.Info()
		var namespace uint64
		if err == nil {
			err = m.Lookup(uint32(0), &namespace)
		}
		m.Close()
		if err != nil {
			return fmt.Errorf("%s unknown map binding: %w", program, err)
		}
		frozen := mi.Frozen()
		if mi.Type != ebpf.Array || mi.KeySize != 4 || mi.ValueSize != 8 || mi.MaxEntries != 1 ||
			mi.Flags&unix.BPF_F_RDONLY_PROG == 0 || !frozen || namespace != cookie {
			return fmt.Errorf("%s namespace constant or canonical map binding changed", program)
		}
		constants++
	}
	if constants != 1 {
		return fmt.Errorf("%s namespace constant unavailable", program)
	}
	for _, name := range required {
		if !seen[name] {
			return fmt.Errorf("%s missing canonical map %s", program, name)
		}
	}
	if _, known := c.queueIdentities[path]; !known {
		// On warm restore, map shape and attachment alone do not prove the
		// surviving guard still implements the reviewed packet path. Compare
		// relocated code against a candidate bound to this exact namespace.
		if c.spec == nil {
			return fmt.Errorf("%s missing runtime template", program)
		}
		spec := c.spec.Copy()
		for name := range spec.Programs {
			if name != program {
				delete(spec.Programs, name)
			}
		}
		if err := spec.Variables["vtep_queue_cookie"].Set(cookie); err != nil {
			return err
		}
		replacements, err := c.bundle.MapReplacements(spec)
		if err != nil {
			return err
		}
		candidate, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements})
		if err != nil {
			return err
		}
		defer candidate.Close()
		ci, err := candidate.Programs[program].Info()
		if err != nil {
			return err
		}
		if pi.Tag != ci.Tag {
			return fmt.Errorf("%s restored code changed; drain with the previous binary", program)
		}
		c.queueIdentities[path] = queueIdentity{info.ID, info.Program}
	}
	return nil
}

func (c *Controller) checkManagedQueues() error {
	for _, m := range c.journal.Namespaces {
		if m.Phase == "ready" && drained(m) != nil {
			if err := c.checkQueue(m); err != nil {
				return err
			}
		}
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
		for _, path := range []string{c.queuePath(cookie), c.cookieIngressPath(cookie), filepath.Join(c.cfg.Pins, "retired", strconv.FormatUint(cookie, 10))} {
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
				delete(c.queueIdentities, c.queuePath(cookie))
				delete(c.queueIdentities, c.cookieIngressPath(cookie))
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
