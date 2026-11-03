// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Exercise the actual Cilium loader's reachability/pruning pipeline, not the
// lower-level ebpf loader used by packet fixtures. Runtime-only cookie maps
// must remain owned by the controller without blocking endpoint collection load.
func TestPrivilegedCookieLoaderPrunedReplacements(t *testing.T) {
	testutils.PrivilegedTest(t)
	specs := map[string]*ebpf.MapSpec{
		"used":         {Name: "used", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1},
		"runtime_only": {Name: "runtime_only", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1},
	}
	replacements := make(map[string]*ebpf.Map)
	for n, s := range specs {
		m, err := ebpf.NewMap(s)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		replacements[n] = m
	}
	spec := &ebpf.CollectionSpec{Maps: specs, Programs: map[string]*ebpf.ProgramSpec{
		"entry": {Name: "entry", Type: ebpf.SchedCLS, SectionName: "tc/entry", License: "GPL", Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, 0).WithReference("used").WithSymbol("entry"), asm.Mov.Imm(asm.R0, 0), asm.Return(),
		}},
	}}
	opts := &bpf.CollectionOptions{CollectionOptions: ebpf.CollectionOptions{MapReplacements: replacements}}
	coll, commit, err := bpf.LoadCollection(slog.Default(), spec, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	if coll.Maps["runtime_only"] != nil {
		t.Fatal("unused runtime map was not pruned")
	}
	if coll.Maps["used"] == nil {
		t.Fatal("live map was pruned")
	}
	original, _ := replacements["used"].Info()
	loaded, _ := coll.Maps["used"].Info()
	originalID, _ := original.ID()
	loadedID, _ := loaded.ID()
	if originalID != loadedID {
		t.Fatal("live replacement map was recreated")
	}
	if opts.CollectionOptions.MapReplacements["runtime_only"] != replacements["runtime_only"] {
		t.Fatal("pruning modified caller's canonical descriptor set")
	}
	if err := replacements["runtime_only"].Update(uint32(0), uint32(42), ebpf.UpdateAny); err != nil {
		t.Fatal("unused canonical runtime map was closed")
	}
	replacements["typo"] = replacements["runtime_only"]
	bad, _, err := bpf.LoadCollection(slog.Default(), spec, opts)
	if bad != nil {
		bad.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "replacement map typo not found") {
		t.Fatalf("unknown replacement was silently ignored: %v", err)
	}
}
