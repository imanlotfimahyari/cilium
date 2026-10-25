// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// Install cleanup before producers. Drain/disable removes in reverse order.
var timewaitHooks = []string{
	"vtep_tw_destroy", "tw_packet_release", "tw_ack_exit",
	"tw_packet_created", "vtep_tw_transfer", "tw_ack_enter",
}

func (c *Controller) tracingPath(name string) string {
	return filepath.Join(c.cfg.Pins, "tracing", name)
}

// Pinned tracing links cannot be atomically updated on the validated kernel.
// Reuse a compatible link rather than detach/reattach across live connections.
// Compare the kernel target, post-relocation bytecode tag and exact map IDs.
func (c *Controller) installTracing(coll *ebpf.Collection, restore bool) error {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("TIME-WAIT requires kernel BTF: %w", err)
	}
	handle, err := btf.FindHandle(func(info *btf.HandleInfo) bool { return info.IsVmlinux() })
	if err != nil {
		return err
	}
	defer handle.Close()
	kinfo, err := handle.Info()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(c.cfg.Pins, "tracing"), 0700); err != nil {
		return err
	}
	c.tracing = make(map[string]link.Link)
	for _, name := range timewaitHooks {
		program := coll.Programs[name]
		spec := c.runtimeProgramSpec(name)
		if program == nil || spec == nil {
			return fmt.Errorf("missing TIME-WAIT tracing program %s", name)
		}
		var l link.Link
		if restore {
			l, err = link.LoadPinnedLink(c.tracingPath(name), nil)
			if err != nil {
				return fmt.Errorf("restore tracing %s: %w", name, err)
			}
			c.tracing[name] = l // Retain FDs, including after a failed initialization.
			var target *btf.Func
			if err := kernel.TypeByName(spec.AttachTo, &target); err != nil {
				return err
			}
			targetID, err := kernel.TypeID(target)
			if err != nil {
				return err
			}
			info, err := l.Info()
			if err != nil {
				return err
			}
			tr := info.Tracing()
			if tr == nil || ebpf.AttachType(tr.AttachType) != spec.AttachType ||
				uint32(tr.TargetBtfId) != uint32(targetID) || tr.TargetObjectId != uint32(kinfo.ID) {
				return fmt.Errorf("TIME-WAIT tracing target changed: %s", name)
			}
			old, err := ebpf.NewProgramFromID(info.Program)
			if err != nil {
				return err
			}
			err = compatibleTracingProgram(old, program)
			old.Close()
			if err != nil {
				return fmt.Errorf("restore %s: %w", name, err)
			}
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: program})
			if err != nil {
				return fmt.Errorf("attach TIME-WAIT %s: %w", name, err)
			}
			c.tracing[name] = l
			if err := l.Pin(c.tracingPath(name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Controller) runtimeProgramSpec(name string) *ebpf.ProgramSpec {
	if c.spec == nil {
		return nil
	}
	return c.spec.Programs[name]
}

func compatibleTracingProgram(old, candidate *ebpf.Program) error {
	a, err := old.Info()
	if err != nil {
		return err
	}
	b, err := candidate.Info()
	if err != nil {
		return err
	}
	am, aok := a.MapIDs()
	bm, bok := b.MapIDs()
	slices.Sort(am)
	slices.Sort(bm)
	if a.Type != ebpf.Tracing || b.Type != ebpf.Tracing || a.Tag != b.Tag ||
		!aok || !bok || !slices.Equal(am, bm) {
		return fmt.Errorf("tracing code or canonical map bindings changed; drain/disable before replacement")
	}
	return nil
}

func (c *Controller) checkTracingPins() error {
	if c.bundle == nil {
		return fmt.Errorf("canonical runtime map bundle is missing")
	}
	if err := c.bundle.checkPins(filepath.Join(c.cfg.Pins, "maps")); err != nil {
		return err
	}
	for _, name := range timewaitHooks {
		held := c.tracing[name]
		if held == nil {
			return fmt.Errorf("missing managed TIME-WAIT hook %s", name)
		}
		pin, err := link.LoadPinnedLink(c.tracingPath(name), nil)
		if err != nil {
			return fmt.Errorf("TIME-WAIT hook pin lost: %s: %w", name, err)
		}
		a, ae := held.Info()
		b, be := pin.Info()
		pin.Close()
		if ae != nil || be != nil || a.ID != b.ID || a.Program != b.Program {
			return fmt.Errorf("managed TIME-WAIT hook identity changed: %s", name)
		}
	}
	return nil
}

func (c *Controller) failRuntime(err error) {
	if c.gcErr == nil {
		c.gcErr = err
	}
	for cookie := range c.journal.Namespaces {
		if retireErr := c.retireControl(cookie); retireErr != nil {
			c.logger.Error("failed to retire selected namespace", "error", retireErr)
		}
	}
	c.logger.Error("VTEP runtime failed; selected namespaces require replacement", "error", err)
}

// Caller has proved all selected namespace bindings and veths drained and owns
// the controller lease. Stop producers before cleanup, then remove the graph.
func (c *Controller) removeDrainedRuntime() error {
	for i := len(timewaitHooks) - 1; i >= 0; i-- {
		if err := os.Remove(c.tracingPath(timewaitHooks[i])); err != nil && !missing(err) {
			return err
		}
	}
	return os.RemoveAll(c.cfg.Pins)
}
