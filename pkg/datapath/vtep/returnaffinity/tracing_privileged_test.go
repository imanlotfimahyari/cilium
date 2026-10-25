// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

func tracingController(t *testing.T) (*Controller, *ebpf.CollectionSpec) {
	t.Helper()
	testutils.PrivilegedTest(t)
	if os.Getenv("VTEP_RETURN_ISOLATED_VM") != "1" {
		t.Skip("isolated VM required")
	}
	object := os.Getenv("VTEP_RETURN_RUNTIME_OBJECT")
	if object == "" {
		t.Skip("supply runtime object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	c := NewController(nil, ControllerConfig{Enabled: true,
		Journal: filepath.Join(t.TempDir(), "journal"),
		Pins:    filepath.Join(filepath.Dir(privilegedPinPath(t)), "runtime"), Cgroup: "/sys/fs/cgroup"})
	c.ConfigurePeers([]Peer{{Address: [4]byte{192, 0, 2, 2}, MAC: [6]byte{2, 0, 0, 0, 0, 2}}})
	t.Cleanup(func() { c.Close() })
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.InitializeRuntime(spec); err != nil {
		t.Fatalf("initialize: %+v", err)
	}
	return c, spec
}

func restoreTracingController(t *testing.T, previous *Controller, spec *ebpf.CollectionSpec) (*Controller, error) {
	t.Helper()
	c := NewController(nil, previous.cfg)
	c.ConfigurePeers(previous.peers)
	t.Cleanup(func() { c.Close() })
	if err := c.Start(); err != nil {
		return c, err
	}
	return c, c.InitializeRuntime(spec)
}

func TestPrivilegedTracingRestartPreservesCompleteGraph(t *testing.T) {
	c, spec := tracingController(t)
	mapIDs := make(map[string]ebpf.MapID)
	linkIDs := make(map[string]link.ID)
	for name, m := range c.bundle.maps {
		mapIDs[name] = socketMapID(t, m)
	}
	for name, l := range c.tracing {
		info, err := l.Info()
		if err != nil {
			t.Fatal(err)
		}
		linkIDs[name] = info.ID
	}
	if len(mapIDs) != 13 || len(linkIDs) != 6 {
		t.Fatalf("incomplete runtime: %d maps, %d hooks", len(mapIDs), len(linkIDs))
	}
	c.Close()
	r, err := restoreTracingController(t, c, spec)
	if err != nil {
		t.Fatalf("restore: %+v", err)
	}
	for name, id := range mapIDs {
		if socketMapID(t, r.bundle.maps[name]) != id {
			t.Fatalf("map replaced: %s", name)
		}
	}
	for name, id := range linkIDs {
		info, err := r.tracing[name].Info()
		if err != nil || info.ID != id {
			t.Fatalf("link replaced: %s: %v", name, err)
		}
	}
	if err := r.Readiness(); err != nil {
		t.Fatal(err)
	}
}

func TestPrivilegedTracingRejectsPartialOrChangedState(t *testing.T) {
	for _, scenario := range append(append([]string(nil), timewaitHooks...), "proof_map", "schema_v1", "changed_code", "wrong_maps") {
		t.Run(scenario, func(t *testing.T) {
			c, spec := tracingController(t)
			var held link.Link
			switch scenario {
			case "proof_map":
				if err := os.Remove(filepath.Join(c.cfg.Pins, "maps", TimewaitProofMap)); err != nil {
					t.Fatal(err)
				}
			case "schema_v1":
				old := currentSocketSchema
				old.Version = 1
				if err := c.bundle.maps[SocketSchemaMap].Update(uint32(0), old, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			case "changed_code":
				spec = spec.Copy()
				spec.Programs[timewaitHooks[0]].Instructions = asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}
			case "wrong_maps":
				other := spec.Copy()
				for _, m := range other.Maps {
					m.Pinning = ebpf.PinNone
				}
				coll, err := ebpf.NewCollection(other)
				if err != nil {
					t.Fatal(err)
				}
				defer coll.Close()
				name := timewaitHooks[0]
				if err := os.Remove(c.tracingPath(name)); err != nil {
					t.Fatal(err)
				}
				held, err = link.AttachTracing(link.TracingOptions{Program: coll.Programs[name]})
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
				if err := held.Pin(c.tracingPath(name)); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Remove(c.tracingPath(scenario)); err != nil {
					t.Fatal(err)
				}
			}
			c.Close()
			r, err := restoreTracingController(t, c, spec)
			if err == nil {
				r.Close()
				t.Fatal("unsafe restoration accepted")
			}
			if scenario == "proof_map" {
				if _, err := os.Stat(filepath.Join(c.cfg.Pins, "maps", TimewaitProofMap)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing map recreated")
				}
			} else if scenario != "schema_v1" && scenario != "changed_code" && scenario != "wrong_maps" {
				if _, err := os.Stat(c.tracingPath(scenario)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing hook recreated")
				}
			}
		})
	}
}

func TestPrivilegedTracingPinLossRevokesReadiness(t *testing.T) {
	c, _ := tracingController(t)
	n := newControllerNamespace(t, "tw-pinloss")
	if err := c.Prepare(n.r); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(n.r.Cookie); err != nil {
		t.Fatal(err)
	}
	name := timewaitHooks[0]
	if err := c.tracing[name].Unpin(); err != nil {
		t.Fatal(err)
	}
	if err := c.Readiness(); err == nil {
		t.Fatal("pin loss left runtime ready")
	}
	if err := c.checkControl(n.r.Cookie); err == nil {
		t.Fatal("pin loss left namespace ready")
	}
	if err := c.tracing[name].Pin(c.tracingPath(name)); err != nil {
		t.Fatal(err)
	}
	if err := c.Readiness(); err == nil {
		t.Fatal("repinning reopened failed runtime")
	}
}

func TestPrivilegedRuntimeMapDamageRevokesReadiness(t *testing.T) {
	for _, scenario := range []string{"proof_pin_lost", "proof_pin_replaced", "schema_changed"} {
		t.Run(scenario, func(t *testing.T) {
			c, _ := tracingController(t)
			n := newControllerNamespace(t, "tw-maploss")
			if err := c.Prepare(n.r); err != nil {
				t.Fatal(err)
			}
			if err := c.Commit(n.r.Cookie); err != nil {
				t.Fatal(err)
			}
			original := c.bundle.maps[TimewaitProofMap]
			if scenario == "schema_changed" {
				bad := currentSocketSchema
				bad.Version++
				if err := c.bundle.maps[SocketSchemaMap].Update(uint32(0), bad, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := original.Unpin(); err != nil {
					t.Fatal(err)
				}
				if scenario == "proof_pin_replaced" {
					var replacement *ebpf.Map
					for _, spec := range socketMapSpecs(SocketCapacity) {
						if spec.Name != TimewaitProofMap {
							continue
						}
						var err error
						replacement, err = ebpf.NewMap(spec)
						if err != nil {
							t.Fatal(err)
						}
					}
					defer replacement.Close()
					if err := replacement.Pin(filepath.Join(c.cfg.Pins, "maps", TimewaitProofMap)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := c.Readiness(); err == nil {
				t.Fatal("map damage left runtime ready")
			}
			if err := c.checkControl(n.r.Cookie); err == nil {
				t.Fatal("map damage left admissions ready")
			}
			// Physical repair must not reopen a namespace whose continuity was
			// lost. Recovery still requires the documented replacement/drain.
			if scenario == "schema_changed" {
				if err := c.bundle.maps[SocketSchemaMap].Update(uint32(0), currentSocketSchema, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			} else {
				if scenario == "proof_pin_replaced" {
					if err := os.Remove(filepath.Join(c.cfg.Pins, "maps", TimewaitProofMap)); err != nil {
						t.Fatal(err)
					}
				}
				if err := original.Pin(filepath.Join(c.cfg.Pins, "maps", TimewaitProofMap)); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Readiness(); err == nil {
				t.Fatal("repair silently reopened the failed runtime")
			}
		})
	}
}
