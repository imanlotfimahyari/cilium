// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
)

func unitController(t *testing.T, enabled bool) *Controller {
	t.Helper()
	dir := t.TempDir()
	c := NewController(nil, ControllerConfig{Enabled: enabled, Journal: filepath.Join(dir, "state", "journal"),
		Pins: filepath.Join(dir, "pins"), Cgroup: "/sys/fs/cgroup"})
	if enabled {
		if err := c.ConfigurePeers([]Peer{{Address: [4]byte{192, 0, 2, 2}, MAC: [6]byte{2, 0, 0, 0, 0, 2}}}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestDisabledSocketControllerIsInert(t *testing.T) {
	c := unitController(t, false)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.InitializeRuntime(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(c.cfg.Journal)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("disabled controller wrote state")
	}
	if _, err := os.Stat(c.cfg.Pins); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("disabled controller created pins")
	}
}

func TestSocketJournalRestartLeaseAndPeerChanges(t *testing.T) {
	c := unitController(t, true)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	second := NewController(nil, c.cfg)
	second.ConfigurePeers(c.peers)
	if err := second.Start(); err == nil {
		t.Fatal("second process acquired the controller lease")
	}
	c.Close()
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	second.Close()
	third := NewController(nil, c.cfg)
	third.ConfigurePeers([]Peer{{Address: [4]byte{192, 0, 2, 3}, MAC: [6]byte{2, 0, 0, 0, 0, 3}}})
	if err := third.Start(); err == nil {
		third.Close()
		t.Fatal("live peer configuration could be replaced")
	}
	j, err := readJournal(c.cfg.Journal)
	if err != nil || len(j.Peers) != 1 || j.Peers[0] != c.peers[0] {
		t.Fatalf("journal changed: %+v %v", j, err)
	}
}

func TestPrivilegedSocketDisableRequiresNetworkTeardown(t *testing.T) {
	testutils.PrivilegedTest(t)
	c := unitController(t, true)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	nspath := filepath.Join(t.TempDir(), "namespace")
	if err := os.WriteFile(nspath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	c.journal.Namespaces[10] = membership{EndpointRegistration: EndpointRegistration{
		Cookie: 10, HostInterface: "vtep-not-here", HostIfindex: 999999, NamespacePath: nspath}, Phase: "retired"}
	if err := writeJournal(c.cfg.Journal, c.journal); err != nil {
		t.Fatal(err)
	}
	c.Close()
	cfg := c.cfg
	cfg.Enabled = false
	off := NewController(nil, cfg)
	if err := off.Start(); !errors.Is(err, ErrSocketRollbackRequiresQuiescence) {
		t.Fatalf("retired namespace was treated as drained: %v", err)
	}
	if err := os.Remove(nspath); err != nil {
		t.Fatal(err)
	}
	if err := off.Start(); err != nil {
		t.Fatal(err)
	}
	off.Close()
	j, err := readJournal(cfg.Journal)
	if err != nil || !j.Disabled {
		t.Fatalf("disable was not durable: %+v %v", j, err)
	}
}

func TestSocketJournalRejectsUnknownState(t *testing.T) {
	for _, data := range []string{"{", "{}", `{"Version":99,"BootID":"synthetic","Namespaces":{}}`} {
		c := unitController(t, false)
		os.MkdirAll(filepath.Dir(c.cfg.Journal), 0700)
		os.WriteFile(c.cfg.Journal, []byte(data), 0600)
		if err := c.Start(); err == nil {
			t.Fatal("unknown journal was accepted")
		}
	}
	c := unitController(t, false)
	os.MkdirAll(c.cfg.Pins, 0700)
	os.WriteFile(filepath.Join(c.cfg.Pins, "orphan"), nil, 0600)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.InitializeRuntime(nil); err == nil {
		t.Fatal("disabled loader accepted orphaned socket pins")
	}
	if _, err := os.Stat(filepath.Join(c.cfg.Pins, "orphan")); err != nil {
		t.Fatal("orphaned state was deleted")
	}
}
