// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/testutils"
)

func offlineJournal(t *testing.T) (string, string, socketJournal) {
	t.Helper()
	boot, err := bootID()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	j := socketJournal{Version: journalVersion, BootID: boot, Disabled: true,
		Peers:      []Peer{{Address: [4]byte{192, 0, 2, 2}, MAC: [6]byte{2, 0, 0, 0, 0, 2}}},
		Namespaces: map[uint64]membership{}, Retired: []cookieRange{{10, 12}, {20, 20}, {^uint64(0) - 1, ^uint64(0)}}}
	return filepath.Join(dir, "journal"), filepath.Join(dir, "pins"), j
}

func TestLegacyJournalExportPreservesHistoryAndIsIdempotent(t *testing.T) {
	path, pins, j := offlineJournal(t)
	if err := writeJournal(path, j); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(path)
	if count, err := ExportLegacyJournal(path, pins, true); err != nil || count != 6 {
		t.Fatalf("preflight: count=%d error=%v", count, err)
	}
	afterCheck, _ := os.ReadFile(path)
	if !bytes.Equal(original, afterCheck) {
		t.Fatal("check-only export changed journal")
	}
	if count, err := ExportLegacyJournal(path, pins, false); err != nil || count != 6 {
		t.Fatalf("export: count=%d error=%v", count, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var legacy socketJournal
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	// These are the format checks made by the v8 reader. Retired must be
	// absent: that reader only knows full Namespaces memberships.
	if legacy.Version != 1 || legacy.BootID != j.BootID || legacy.Namespaces == nil || !legacy.Disabled || legacy.Initialized || bytes.Contains(data, []byte(`"Retired"`)) {
		t.Fatal("export is not a disabled version-1 journal")
	}
	if len(legacy.Peers) != len(j.Peers) || legacy.Peers[0] != j.Peers[0] {
		t.Fatal("export changed peer configuration")
	}
	for _, cookie := range []uint64{10, 11, 12, 20, ^uint64(0) - 1, ^uint64(0)} {
		if legacy.Namespaces[cookie] != legacyTombstone(cookie) {
			t.Fatalf("lost cookie %d", cookie)
		}
	}
	current, err := readJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	c := unitController(t, false)
	c.journal = current
	if c.ValidateLegacyNamespace(10) == nil || c.ValidateLegacyNamespace(20) == nil {
		t.Fatal("export allowed old cookies under ordinary routing")
	}
	if c.ValidateLegacyNamespace(13) != nil {
		t.Fatal("export blocked an unrelated gap")
	}
	if count, err := ExportLegacyJournal(path, pins, false); err != nil || count != 6 {
		t.Fatalf("repeated export: %d %v", count, err)
	}
	afterRepeat, _ := os.ReadFile(path)
	if !bytes.Equal(data, afterRepeat) {
		t.Fatal("repeat export changed history")
	}
}

func TestLegacyExportRefusalsLeaveJournalAndPinsUntouched(t *testing.T) {
	for _, scenario := range []string{"active", "initialized", "membership", "pins", "old_boot", "large_range", "unknown_field", "trailing_json", "lease"} {
		t.Run(scenario, func(t *testing.T) {
			path, pins, j := offlineJournal(t)
			switch scenario {
			case "active":
				j.Disabled = false
			case "initialized":
				j.Initialized = true
			case "membership":
				j.Namespaces[30] = membership{EndpointRegistration: EndpointRegistration{Cookie: 30, HostIfindex: 1, NamespacePath: "not-compacted"}, Phase: "retired"}
			case "old_boot":
				j.BootID = "other-boot"
			case "large_range":
				j.Retired = []cookieRange{{1, ^uint64(0)}}
			case "pins":
				if err := os.Mkdir(pins, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(pins, "surviving-link"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeJournal(path, j); err != nil {
				t.Fatal(err)
			}
			if scenario == "unknown_field" {
				b, _ := os.ReadFile(path)
				b = append([]byte(`{"FutureOwnership":true,`), b[1:]...)
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "trailing_json" {
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString(" {}")
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "lease" {
				lease, err := AcquireLease(path + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
			}
			before, _ := os.ReadFile(path)
			if _, err := ExportLegacyJournal(path, pins, false); err == nil {
				t.Fatal("unsafe export accepted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("refused export changed journal")
			}
			if scenario == "pins" {
				b, err := os.ReadFile(filepath.Join(pins, "surviving-link"))
				if err != nil || string(b) != "preserve" {
					t.Fatal("export touched pins")
				}
			}
		})
	}
}

func TestLegacyExportBoundsAndPathValidation(t *testing.T) {
	path, pins, j := offlineJournal(t)
	j.Retired = []cookieRange{{1, maxJournalHistory}}
	if err := writeJournal(path, j); err != nil {
		t.Fatal(err)
	}
	if count, err := ExportLegacyJournal(path, pins, true); err != nil || count != maxJournalHistory {
		t.Fatalf("exact bound: %d %v", count, err)
	}
	j.Retired[0].Last++
	if err := writeJournal(path, j); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportLegacyJournal(path, pins, true); err == nil {
		t.Fatal("export exceeded tombstone bound")
	}
	if _, err := ExportLegacyJournal("relative", pins, false); err == nil {
		t.Fatal("relative path accepted")
	}
	alias := filepath.Join(filepath.Dir(path), "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportLegacyJournal(alias, pins, false); err == nil {
		t.Fatal("symlink journal accepted")
	}
}

func TestControllerReadsJournalOnlyAfterLease(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		c := unitController(t, enabled)
		if err := os.MkdirAll(filepath.Dir(c.cfg.Journal), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.cfg.Journal, []byte("{"), 0600); err != nil {
			t.Fatal(err)
		}
		lease, err := AcquireLease(c.cfg.Journal + ".lock")
		if err != nil {
			t.Fatal(err)
		}
		err = c.Start()
		lease.Close()
		if !errors.Is(err, unix.EWOULDBLOCK) {
			t.Fatalf("controller read state before obtaining lease: %v", err)
		}
		if err := c.Start(); err == nil || !strings.Contains(err.Error(), "after acquiring lease") {
			t.Fatalf("malformed state accepted after lease release: %v", err)
		}
	}
}

func TestPrivilegedLegacyExportReimportsIntoDisabledController(t *testing.T) {
	testutils.PrivilegedTest(t)
	path, pins, j := offlineJournal(t)
	if err := writeJournal(path, j); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportLegacyJournal(path, pins, false); err != nil {
		t.Fatal(err)
	}
	c := NewController(nil, ControllerConfig{Journal: path, Pins: pins, Cgroup: "/sys/fs/cgroup"})
	defer c.Close()
	// This exercises the unchanged v8 physical-drain predicate against the
	// exported retired memberships, and the current agent's v1 reimport.
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.InitializeRuntime(nil); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range []uint64{10, 11, 12, 20, ^uint64(0) - 1, ^uint64(0)} {
		if c.ValidateLegacyNamespace(cookie) == nil {
			t.Fatalf("reimport reopened cookie %d", cookie)
		}
	}
	if err := c.ValidateLegacyNamespace(13); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportLegacyJournal(path, pins, false); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("running disabled controller did not retain its lease: %v", err)
	}
}
