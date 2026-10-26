// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/netns"
)

const SocketCapacity = 4096

type ControllerConfig struct {
	Enabled               bool
	Journal, Pins, Cgroup string
}

// Controller is shared by the agent lifecycle and synchronous endpoint loader.
// Closing descriptors preserves links, maps and readiness across agent restart.
// Only an explicit, verified drain permits a disabled agent to remove pins.
type Controller struct {
	mu                            sync.Mutex
	logger                        *slog.Logger
	cfg                           ControllerConfig
	journal                       socketJournal
	peers                         []Peer
	lease                         *os.File
	bundle                        *SocketBundle
	spec                          *ebpf.CollectionSpec
	collector                     *ebpf.Program
	retired                       *ebpf.Program
	stop                          context.CancelFunc
	done                          chan struct{}
	started, runtimeReady, closed bool
	gcErr                         error
	tracing                       map[string]link.Link
	initializationAttempted       bool
	queuesLoaded                  map[uint64]bool
}

func NewController(logger *slog.Logger, cfg ControllerConfig) *Controller {
	if logger == nil {
		logger = slog.Default()
	}
	return &Controller{logger: logger, cfg: cfg, queuesLoaded: make(map[uint64]bool)}
}

func (c *Controller) Enabled() bool { return c.cfg.Enabled }

// Readiness participates in the agent status API. Endpoint readiness is
// published separately, after its own pre-queue and policy links are committed.
func (c *Controller) Readiness() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cfg.Enabled {
		return nil
	}
	if c.closed || !c.runtimeReady {
		return fmt.Errorf("experimental VXLAN return-affinity runtime is not ready")
	}
	if c.gcErr == nil {
		if err := c.checkTracingPins(); err != nil {
			c.failRuntime(err)
		}
	}
	return c.gcErr
}

func (c *Controller) ConfigurePeers(peers []Peer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return fmt.Errorf("VTEP peer configuration is immutable after startup")
	}
	peers = slices.Clone(peers)
	slices.SortFunc(peers, func(a, b Peer) int { return bytes.Compare(a.Address[:], b.Address[:]) })
	for i, p := range peers {
		if p.Address == [4]byte{} || p.MAC == [6]byte{} || p.MAC[0]&1 != 0 ||
			(i > 0 && p.Address == peers[i-1].Address) {
			return fmt.Errorf("invalid or ambiguous exact VTEP peer")
		}
	}
	c.peers = peers
	return nil
}

func (c *Controller) Start() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrStopped
	}
	if c.started {
		return nil
	}
	if !c.cfg.Enabled {
		if _, err := os.Stat(c.cfg.Journal); missing(err) {
			c.started = true
			return nil
		} else if err != nil {
			return fmt.Errorf("stat VTEP socket journal: %w", err)
		}
	}
	if c.cfg.Enabled && (len(c.peers) == 0 || len(c.peers) > 64) {
		return fmt.Errorf("experimental return affinity requires 1..64 exact configured VXLAN peers")
	}
	if err := os.MkdirAll(filepath.Dir(c.cfg.Journal), 0700); err != nil {
		return err
	}
	c.lease, err = AcquireLease(c.cfg.Journal + ".lock")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			c.lease.Close()
			c.lease = nil
		}
	}()
	// The initial existence check preserves the inert flag-off/no-journal path.
	// A previous owner can publish newer history before we acquire its lease.
	// Never overwrite that history with the pre-lease snapshot.
	j, err := readJournal(c.cfg.Journal)
	if err != nil && (!missing(err) || !c.cfg.Enabled) {
		return fmt.Errorf("read VTEP socket journal after acquiring lease: %w", err)
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	if missingErr := (j.Version == 0); missingErr {
		if entries, err := os.ReadDir(c.cfg.Pins); err == nil && len(entries) > 0 {
			return fmt.Errorf("orphaned VTEP socket pins without a journal; drain before recovery")
		} else if err != nil && !missing(err) {
			return err
		}
		j = socketJournal{Version: journalVersion, BootID: boot, Peers: c.peers, Namespaces: make(map[uint64]membership)}
	}
	if !c.cfg.Enabled {
		// No automatic downgrade of a live namespace. Even a RETIRED entry
		// requires the old namespace binding and host veth to be absent.
		for _, m := range j.Namespaces {
			if err := drained(m); err != nil {
				return fmt.Errorf("%w: %v", ErrSocketRollbackRequiresQuiescence, err)
			}
		}
		if err := c.removeDrainedRuntime(); err != nil {
			return err
		}
		j.Disabled, j.Initialized = true, false
		if j.BootID != boot {
			j.Namespaces = make(map[uint64]membership)
			j.Retired = nil
		} else {
			for cookie := range j.Namespaces {
				j.rememberRetired(cookie)
				delete(j.Namespaces, cookie)
			}
		}
		j.BootID = boot
		c.journal = j
		if err := writeJournal(c.cfg.Journal, j); err != nil {
			return err
		}
		c.started = true
		return nil
	}
	if j.BootID != boot {
		return fmt.Errorf("VTEP socket state belongs to a previous boot; drain and disable before recovery")
	}
	if !j.Disabled && !reflect.DeepEqual(j.Peers, c.peers) {
		return fmt.Errorf("exact VTEP peers changed; drain and disable before reconfiguration")
	}
	if j.Disabled {
		j.Peers, j.Disabled = c.peers, false
	}
	c.journal = j
	if err := writeJournal(c.cfg.Journal, j); err != nil {
		return err
	}
	c.started = true
	return nil
}

// InitializeRuntime runs before the base datapath is attached or endpoints can
// regenerate. It restores the complete bundle before loading any replacement
// program, installs the node sockops hook and starts GC before readiness.
func (c *Controller) InitializeRuntime(spec *ebpf.CollectionSpec) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cfg.Enabled {
		if entries, e := os.ReadDir(c.cfg.Pins); e == nil && len(entries) > 0 {
			return fmt.Errorf("VTEP socket pins survive a disabled configuration; drain before disabling")
		} else if e != nil && !missing(e) {
			return e
		}
		return nil
	}
	if !c.started || c.closed {
		return ErrStopped
	}
	if c.runtimeReady {
		return c.gcErr
	}
	if c.initializationAttempted {
		return fmt.Errorf("runtime initialization previously failed; restart after inspecting preserved state")
	}
	c.initializationAttempted = true
	restore := c.journal.Initialized
	spec = spec.Copy()
	if err := ConfigureTimewaitTarget(spec); err != nil {
		return err
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	var replacements map[string]*ebpf.Map
	if c.journal.Initialized {
		c.bundle, err = OpenSocketBundle(filepath.Join(c.cfg.Pins, "maps"), SocketCapacity)
		if err != nil {
			return err
		}
		defer func() {
			if err != nil {
				c.bundle.Close()
				c.bundle = nil
			}
		}()
		if err := c.validateRestoredLinks(); err != nil {
			return err
		}
		replacements, err = c.bundle.MapReplacements(spec)
		if err != nil {
			return err
		}
	} else if entries, readErr := os.ReadDir(c.cfg.Pins); readErr == nil && len(entries) > 0 {
		return fmt.Errorf("incomplete VTEP initialization; refusing to adopt unknown pins")
	} else if readErr != nil && !missing(readErr) {
		return readErr
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements})
	if err != nil {
		return fmt.Errorf("load VTEP socket runtime: %w", err)
	}
	defer coll.Close()
	if c.bundle == nil {
		c.bundle, err = PinSocketBundle(filepath.Join(c.cfg.Pins, "maps"), SocketCapacity, coll.Maps)
		if err != nil {
			return err
		}
		for _, p := range c.peers {
			var value [8]byte
			copy(value[:], p.MAC[:])
			if err := c.bundle.maps[SocketPeerMap].Update(binary.NativeEndian.Uint32(p.Address[:]), value, ebpf.UpdateNoExist); err != nil {
				return err
			}
		}
		c.journal.Initialized = true
		if err := writeJournal(c.cfg.Journal, c.journal); err != nil {
			return err
		}
	}
	c.spec = spec
	if err := c.installTracing(coll, restore); err != nil {
		return err
	}
	if err := c.installSockops(coll.Programs["cil_vtep_sockops"]); err != nil {
		return err
	}
	c.collector, err = coll.Programs["cil_vtep_collect"].Clone()
	if err != nil {
		return err
	}
	c.retired, err = coll.Programs["cil_vtep_retired"].Clone()
	if err != nil {
		c.collector.Close()
		c.collector = nil
		return err
	}
	if err := c.collectLocked(); err != nil {
		c.collector.Close()
		c.collector = nil
		return err
	}
	c.spec = spec
	ctx, cancel := context.WithCancel(context.Background())
	c.stop, c.done = cancel, make(chan struct{})
	go c.collectLoop(ctx)
	c.runtimeReady = true
	return nil
}

func (c *Controller) installSockops(program *ebpf.Program) error {
	path := filepath.Join(c.cfg.Pins, "sockops")
	l, err := link.LoadPinnedLink(path, nil)
	if err == nil {
		defer l.Close()
		return l.Update(program)
	}
	if !missing(err) {
		return err
	}
	l, err = link.AttachCgroup(link.CgroupOptions{Path: c.cfg.Cgroup,
		Attach: ebpf.AttachCGroupSockOps, Program: program})
	if err != nil {
		return err
	}
	defer l.Close()
	return l.Pin(path)
}

func (c *Controller) collectLocked() error {
	if err := c.checkTracingPins(); err != nil {
		return err
	}
	ret, _, err := c.collector.Test(make([]byte, 64))
	if err != nil {
		return err
	}
	if ret != 0 {
		return fmt.Errorf("VTEP transient collection returned %d", ret)
	}
	return c.collectRetiredLinks()
}

func (c *Controller) collectLoop(ctx context.Context) {
	defer close(c.done)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			c.mu.Lock()
			if err := c.collectLocked(); err != nil {
				c.failRuntime(err)
			}
			c.mu.Unlock()
		}
	}
}

func (c *Controller) MapReplacements(spec *ebpf.CollectionSpec) (map[string]*ebpf.Map, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.runtimeReady || c.closed || c.gcErr != nil {
		return nil, fmt.Errorf("VTEP socket runtime is not ready")
	}
	return c.bundle.MapReplacements(spec)
}

// ValidateLegacyNamespace prevents CNI retries in an old selected namespace
// from silently downgrading its surviving sockets after a coordinated disable.
// A replacement pod must use a fresh namespace cookie even when affinity is off.
func (c *Controller) ValidateLegacyNamespace(cookie uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, selected := c.journal.Namespaces[cookie]
	if selected || c.journal.retired(cookie) {
		return fmt.Errorf("previously selected VTEP namespace requires replacement before ordinary routing")
	}
	return nil
}

func (c *Controller) Prepare(r EndpointRegistration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cfg.Enabled || !c.runtimeReady || c.closed || c.gcErr != nil {
		return fmt.Errorf("VTEP socket runtime is not ready")
	}
	if r.Cookie == 0 || r.HostIfindex == 0 || r.NamespacePath == "" || r.ContainerInterface == "" {
		return fmt.Errorf("incomplete CNI namespace registration")
	}
	if c.journal.retired(r.Cookie) {
		return fmt.Errorf("retired VTEP namespace incarnation cannot be reused")
	}
	if old, ok := c.journal.Namespaces[r.Cookie]; ok {
		if old.EndpointRegistration != r || old.Phase == "retired" {
			return fmt.Errorf("VTEP namespace incarnation cannot be reused")
		}
		if old.Phase == "ready" {
			if err := c.checkQueue(old); err != nil {
				return err
			}
			if !c.queuesLoaded[r.Cookie] {
				return c.installQueue(old)
			}
			return nil
		}
		return fmt.Errorf("incomplete VTEP namespace installation requires pod replacement")
	}
	if len(c.journal.Namespaces)+len(c.journal.Retired) >= maxJournalHistory {
		return fmt.Errorf("VTEP namespace history capacity reached; existing ownership is preserved, new admissions require a coordinated node drain and reboot")
	}
	queueIndex, err := inspectNamespace(r, true)
	if err != nil {
		return err
	}
	m := membership{EndpointRegistration: r, Phase: "preparing", QueueIfindex: queueIndex}
	c.journal.Namespaces[r.Cookie] = m
	if err := writeJournal(c.cfg.Journal, c.journal); err != nil {
		return err
	}
	// The durable PREPARING record precedes nonce/control creation. Neither
	// readiness nor a partially installed namespace may be invented on retry.
	if err := c.bundle.maps[SocketNonceMap].Update(r.Cookie, uint64(0), ebpf.UpdateNoExist); err != nil {
		return err
	}
	if err := c.installQueue(m); err != nil {
		return err
	}
	return nil
}

// Commit is called only after endpoint policy and TC attachments are committed.
// CNI ADD remains blocked until this returns successfully.
func (c *Controller) Commit(cookie uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.runtimeReady || c.closed || c.gcErr != nil {
		return fmt.Errorf("VTEP socket runtime is not ready")
	}
	m, ok := c.journal.Namespaces[cookie]
	if !ok || (m.Phase != "preparing" && m.Phase != "ready") {
		return fmt.Errorf("unprepared VTEP namespace")
	}
	if err := c.checkQueue(m); err != nil {
		return err
	}
	if m.Phase == "ready" {
		return c.checkControl(cookie)
	}
	if err := c.collectLocked(); err != nil {
		return err
	}
	if _, err := inspectNamespace(m.EndpointRegistration, true); err != nil {
		return err
	}
	m.Phase = "ready"
	c.journal.Namespaces[cookie] = m
	if err := writeJournal(c.cfg.Journal, c.journal); err != nil {
		return err
	}
	control := struct {
		Generation, TTL uint64
		Phase, Reserved uint32
	}{cookie, uint64(30 * time.Second), 1, 0}
	return c.bundle.maps[SocketControlMap].Update(cookie, control, ebpf.UpdateNoExist)
}

func (c *Controller) checkControl(cookie uint64) error {
	var control struct {
		Generation, TTL uint64
		Phase, Reserved uint32
	}
	if err := c.bundle.maps[SocketControlMap].Lookup(cookie, &control); err != nil {
		return err
	}
	if control.Generation != cookie || control.Phase != 1 || control.Reserved != 0 || control.TTL == 0 {
		return fmt.Errorf("VTEP namespace readiness was lost; pod replacement required")
	}
	var nonce uint64
	return c.bundle.maps[SocketNonceMap].Lookup(cookie, &nonce)
}

func (c *Controller) retireControl(cookie uint64) error {
	var control struct {
		Generation, TTL uint64
		Phase, Reserved uint32
	}
	if err := c.bundle.maps[SocketControlMap].Lookup(cookie, &control); errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	control.Phase = 2
	return c.bundle.maps[SocketControlMap].Update(cookie, control, ebpf.UpdateExist)
}

func (c *Controller) Retire(cookie uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cfg.Enabled {
		return nil
	}
	if c.closed {
		return ErrStopped
	}
	m, ok := c.journal.Namespaces[cookie]
	if !ok {
		return nil
	}
	if c.bundle == nil {
		return fmt.Errorf("VTEP socket bundle is not restored")
	}
	if m.Phase != "retired" {
		m.Phase = "retiring"
		c.journal.Namespaces[cookie] = m
		if err := writeJournal(c.cfg.Journal, c.journal); err != nil {
			return err
		}
	}
	if err := c.installRetiredGuard(m); err != nil {
		return err
	}
	if err := c.retireControl(cookie); err != nil {
		return err
	}
	m.Phase = "retired"
	c.journal.Namespaces[cookie] = m
	if err := writeJournal(c.cfg.Journal, c.journal); err != nil {
		return err
	}
	// The durable tombstone forbids reopening this cookie even after these
	// bounded kernel entries are removed. Old socket/queued state fails closed.
	for _, name := range []string{SocketControlMap, SocketNonceMap} {
		if err := c.bundle.maps[name].Delete(cookie); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return c.collectLocked()
}

func (c *Controller) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	stop, done := c.stop, c.done
	c.mu.Unlock()
	if stop != nil {
		stop()
		<-done
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	if c.collector != nil {
		err = errors.Join(err, c.collector.Close())
	}
	if c.retired != nil {
		err = errors.Join(err, c.retired.Close())
	}
	for _, l := range c.tracing {
		err = errors.Join(err, l.Close())
	}
	if c.bundle != nil {
		err = errors.Join(err, c.bundle.Close())
	}
	if c.lease != nil {
		err = errors.Join(err, c.lease.Close())
	}
	return err
}

func drained(m membership) error {
	if iface, err := netlink.LinkByName(m.HostInterface); err == nil {
		if iface.Attrs().Index == m.HostIfindex {
			return fmt.Errorf("selected endpoint veth still exists")
		}
	} else {
		var missingLink netlink.LinkNotFoundError
		if !errors.As(err, &missingLink) {
			return err
		}
	}
	if _, err := os.Stat(m.NamespacePath); err == nil {
		ns, err := netns.OpenPinned(m.NamespacePath)
		if err != nil {
			return err
		}
		defer ns.Close()
		var cookie uint64
		if err := ns.Do(func() error { var err error; cookie, err = netns.GetNetNSCookie(); return err }); err != nil {
			return err
		}
		if cookie == m.Cookie {
			return fmt.Errorf("selected namespace binding still exists")
		}
	} else if !missing(err) {
		return err
	}
	return nil
}
