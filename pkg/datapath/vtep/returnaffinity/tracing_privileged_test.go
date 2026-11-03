// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if err := ConfigureTimewaitTarget(spec); err != nil {
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
	if len(mapIDs) != 18 || len(linkIDs) != 8 {
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
	for _, scenario := range append(append([]string(nil), timewaitHooks...), "proof_map", "schema_v1", "schema_v2", CookieLedgerMap, CookieACKMap, CookieChildMap, CookiePacketMap, CookieStatsMap, "changed_code", "wrong_maps") {
		t.Run(scenario, func(t *testing.T) {
			c, spec := tracingController(t)
			var held link.Link
			switch scenario {
			case "proof_map":
				if err := os.Remove(filepath.Join(c.cfg.Pins, "maps", TimewaitProofMap)); err != nil {
					t.Fatal(err)
				}
			case CookieLedgerMap, CookieACKMap, CookieChildMap, CookiePacketMap, CookieStatsMap:
				if err := os.Remove(filepath.Join(c.cfg.Pins, "maps", scenario)); err != nil {
					t.Fatal(err)
				}
			case "schema_v1", "schema_v2":
				old := currentSocketSchema
				old.Version = 1
				if scenario == "schema_v2" {
					old.Version = 2
				}
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
			if scenario == "proof_map" || scenario == CookieLedgerMap || scenario == CookieACKMap || scenario == CookieChildMap || scenario == CookiePacketMap || scenario == CookieStatsMap {
				name := scenario
				if scenario == "proof_map" {
					name = TimewaitProofMap
				}
				if _, err := os.Stat(filepath.Join(c.cfg.Pins, "maps", name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing map recreated")
				}
			} else if scenario != "schema_v1" && scenario != "schema_v2" && scenario != "changed_code" && scenario != "wrong_maps" {
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

func TestPrivilegedCookieIngressDamageRefusesRestore(t *testing.T) {
	for _, scenario := range []string{"missing", "wrong_maps", "wrong_namespace", "noop", "changed_code"} {
		t.Run(scenario, func(t *testing.T) {
			c, spec := tracingController(t)
			n := newControllerNamespace(t, "ck-restore")
			if err := c.Prepare(n.r); err != nil {
				t.Fatal(err)
			}
			if err := c.Commit(n.r.Cookie); err != nil {
				t.Fatal(err)
			}
			path := c.cookieIngressPath(n.r.Cookie)
			if scenario == "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				other := spec.Copy()
				for name := range other.Programs {
					if name != "cil_vtep_cookie_ingress" {
						delete(other.Programs, name)
					}
				}
				for _, m := range other.Maps {
					m.Pinning = ebpf.PinNone
				}
				cookie := n.r.Cookie
				if scenario == "wrong_namespace" {
					cookie++
				}
				if err := other.Variables["vtep_queue_cookie"].Set(cookie); err != nil {
					t.Fatal(err)
				}
				var replacements map[string]*ebpf.Map
				if scenario != "wrong_maps" {
					var err error
					replacements, err = c.bundle.MapReplacements(other)
					if err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "changed_code" {
					instructions := other.Programs["cil_vtep_cookie_ingress"].Instructions
					prefix := asm.Mov.Imm(asm.R0, 0).WithMetadata(instructions[0].Metadata)
					instructions[0].Metadata = asm.Metadata{}
					other.Programs["cil_vtep_cookie_ingress"].Instructions = append(asm.Instructions{prefix}, instructions...)
				}
				if scenario == "noop" {
					other.Programs["cil_vtep_cookie_ingress"].Instructions = asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}
				}
				coll, err := ebpf.NewCollectionWithOptions(other, ebpf.CollectionOptions{MapReplacements: replacements})
				if err != nil {
					t.Fatal(err)
				}
				defer coll.Close()
				l, err := link.LoadPinnedLink(path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := l.Update(coll.Programs["cil_vtep_cookie_ingress"]); err != nil {
					t.Fatal(err)
				}
				l.Close()
			}
			// Refuse the guard itself before changing controls. A preceding
			// health failure would retire controls and mask this restore check.
			c.Close()
			if _, err := restoreTracingController(t, c, spec); err == nil || !strings.Contains(err.Error(), "cil_vtep_cookie_ingress") {
				t.Fatalf("damaged guard was not explicitly refused on restart: %v", err)
			}
			if scenario == "missing" {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing guard recreated")
				}
			}
		})
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

func TestPrivilegedCookieIngressPinLossRevokesReadiness(t *testing.T) {
	c, _ := tracingController(t)
	n := newControllerNamespace(t, "ck-pinloss")
	if err := c.Prepare(n.r); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(n.r.Cookie); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(c.cookieIngressPath(n.r.Cookie)); err != nil {
		t.Fatal(err)
	}
	if err := c.Readiness(); err == nil {
		t.Fatal("missing cookie ingress left runtime ready")
	}
	if err := c.checkControl(n.r.Cookie); err == nil {
		t.Fatal("missing cookie ingress left namespace ready")
	}
}
