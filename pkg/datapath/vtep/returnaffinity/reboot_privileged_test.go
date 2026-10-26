// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/testutils"
)

// Execute prepare and verify in separate, fully powered-off VM boots with only
// a disposable ext4 image carried across them. This validates the controller's
// real boot boundary, not full-agent/Kubernetes rollout or connection recovery.
func TestPrivilegedRebootRecovery(t *testing.T) {
	testutils.PrivilegedTest(t)
	stage := os.Getenv("VTEP_RETURN_RECOVERY_STAGE")
	if os.Getenv("VTEP_RETURN_ISOLATED_VM") != "1" || stage == "" {
		t.Skip("requires two isolated VM boots and a disposable recovery disk")
	}
	object := os.Getenv("VTEP_RETURN_RUNTIME_OBJECT")
	if object == "" {
		t.Fatal("runtime object required")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ControllerConfig{Enabled: true, Journal: "/recovery/journal",
		Pins: "/sys/fs/bpf/vtep-reboot", Cgroup: "/sys/fs/cgroup"}
	peers := []Peer{{Address: [4]byte{192, 0, 2, 2}, MAC: [6]byte{2, 0, 0, 0, 0, 2}}}
	newController := func(enabled bool) *Controller {
		config := cfg
		config.Enabled = enabled
		c := NewController(nil, config)
		if err := c.ConfigurePeers(peers); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	if stage == "prepare" {
		if _, err := os.Stat(cfg.Journal); !os.IsNotExist(err) {
			t.Fatal("prepare requires an unused disposable recovery image")
		}
		c := newController(true)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if err := c.InitializeRuntime(spec); err != nil {
			t.Fatal(err)
		}
		if err := c.Readiness(); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		c.journal.rememberRetired(101)
		err := writeJournal(cfg.Journal, c.journal)
		c.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		// Deliberately preserve initialized pins and an active journal. The
		// next boot must not mistake vanished bpffs objects for unused state.
		return
	}
	if stage != "verify" {
		t.Fatal("unknown recovery stage")
	}
	before, err := os.ReadFile(cfg.Journal)
	if err != nil {
		t.Fatal(err)
	}
	old, err := decodeJournal(before)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := bootID()
	if err != nil || old.BootID == boot || !old.Initialized || old.Disabled || !old.retired(101) {
		t.Fatalf("not a distinct boot with durable active history: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Pins, "maps")); !os.IsNotExist(err) {
		t.Fatal("bpffs unexpectedly survived a real VM power cycle")
	}
	c := newController(true)
	if err := c.Start(); err == nil || !strings.Contains(err.Error(), "previous boot") {
		t.Fatalf("enabled recovery did not refuse lost ownership: %v", err)
	}
	after, err := os.ReadFile(cfg.Journal)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused recovery modified previous-boot history")
	}
	c.Close()
	off := newController(false)
	if err := off.Start(); err != nil {
		t.Fatal(err)
	}
	off.Close()
	j, err := readJournal(cfg.Journal)
	if err != nil || j.BootID != boot || !j.Disabled || j.Initialized || len(j.Retired) != 0 {
		t.Fatalf("drained previous-boot recovery was not durable: %v", err)
	}
	fresh := newController(true)
	if err := fresh.Start(); err != nil {
		t.Fatal(err)
	}
	if err := fresh.InitializeRuntime(spec); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Readiness(); err != nil || len(fresh.bundle.maps) != 13 || len(fresh.tracing) != 6 {
		t.Fatalf("fresh graph could not be installed after explicit recovery: %v", err)
	}
	fresh.Close()
	clean := newController(false)
	if err := clean.Start(); err != nil {
		t.Fatal(err)
	}
}
