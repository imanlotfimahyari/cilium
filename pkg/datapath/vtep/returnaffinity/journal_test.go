// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestRetiredHistoryPreservesExactSet(t *testing.T) {
	j := socketJournal{Version: journalVersion, BootID: "test", Namespaces: map[uint64]membership{}}
	expected := map[uint64]bool{}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		cookie := uint64(rng.IntN(1000) + 1)
		expected[cookie] = true
		j.rememberRetired(cookie)
	}
	// Exercise joining both sides and the uint64 boundary without overflow.
	for _, cookie := range []uint64{2000, 2002, 2001, ^uint64(0), ^uint64(0) - 1} {
		expected[cookie] = true
		j.rememberRetired(cookie)
	}
	for cookie := uint64(0); cookie < 2100; cookie++ {
		if j.retired(cookie) != expected[cookie] {
			t.Fatalf("history changed membership of cookie %d", cookie)
		}
	}
	path := filepath.Join(t.TempDir(), "journal")
	if err := writeJournal(path, j); err != nil {
		t.Fatal(err)
	}
	restored, err := readJournal(path)
	if err != nil || !reflect.DeepEqual(j, restored) {
		t.Fatalf("history changed across restart: %v", err)
	}
}

func TestRetiredHistoryCompressesChurnWithoutBlockingGaps(t *testing.T) {
	var j socketJournal
	for cookie := uint64(1); cookie <= 100000; cookie++ {
		j.rememberRetired(cookie)
	}
	if len(j.Retired) != 1 || !j.retired(100000) || j.retired(100001) {
		t.Fatal("contiguous churn was not compacted exactly")
	}
	j.rememberRetired(100003)
	if j.retired(100002) {
		t.Fatal("history fence blocked an unrelated namespace")
	}
}

func TestJournalMigrationAndMalformedHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	if err := os.WriteFile(path, []byte(`{"Version":1,"BootID":"test","Namespaces":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	j, err := readJournal(path)
	if err != nil || j.Version != journalVersion {
		t.Fatalf("v1 migration: %v", err)
	}
	for _, body := range []string{
		`{"Version":1,"BootID":"test","Namespaces":{},"Retired":[{"First":1,"Last":1}]}`,
		`{"Version":2,"BootID":"test","Namespaces":{},"Retired":[{"First":0,"Last":1}]}`,
		`{"Version":2,"BootID":"test","Namespaces":{},"Retired":[{"First":3,"Last":2}]}`,
		`{"Version":2,"BootID":"test","Namespaces":{},"Retired":[{"First":1,"Last":2},{"First":2,"Last":4}]}`,
		`{"Version":2,"BootID":"test","Namespaces":{"10":{"Cookie":11,"Phase":"ready"}}}`,
		`{"Version":2,"BootID":"test","Namespaces":{"10":{"Cookie":10,"Phase":"unknown"}}}`,
		`{"Version":2,"BootID":"test","Namespaces":{"10":{"Cookie":10,"Phase":"ready"}},"Retired":[{"First":10,"Last":10}]}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readJournal(path); err == nil {
			t.Fatalf("accepted malformed history: %s", body)
		}
	}
}

func TestPrivilegedRetiredCompactionIsDurableAndForbidsLegacyReuse(t *testing.T) {
	testutils.PrivilegedTest(t)
	c := unitController(t, true)
	c.journal = socketJournal{Version: journalVersion, BootID: "test", Namespaces: map[uint64]membership{
		10: {EndpointRegistration: EndpointRegistration{Cookie: 10, HostInterface: "vtep-not-here", HostIfindex: 999999, NamespacePath: filepath.Join(t.TempDir(), "gone")}, Phase: "retired"},
	}}
	if err := c.collectRetiredLinks(); err != nil {
		t.Fatal(err)
	}
	if len(c.journal.Namespaces) != 0 || !c.journal.retired(10) {
		t.Fatal("drained membership was not compacted")
	}
	j, err := readJournal(c.cfg.Journal)
	if err != nil || !j.retired(10) {
		t.Fatalf("tombstone not durable: %v", err)
	}
	if err := c.ValidateLegacyNamespace(10); err == nil {
		t.Fatal("compaction reopened old namespace")
	}
	if err := c.ValidateLegacyNamespace(11); err != nil {
		t.Fatal("compaction blocked unrelated namespace")
	}
}

func TestJournalCapacityRejectsOnlyNewRegistrations(t *testing.T) {
	c := unitController(t, true)
	c.runtimeReady = true
	c.journal.Namespaces = map[uint64]membership{}
	for i := range maxJournalHistory {
		c.journal.rememberRetired(uint64(2*i + 1))
	}
	err := c.Prepare(EndpointRegistration{Cookie: uint64(2*maxJournalHistory + 2), HostIfindex: 1, NamespacePath: "unused", ContainerInterface: "eth0"})
	if err == nil || !strings.Contains(err.Error(), "history capacity") {
		t.Fatalf("capacity did not reject new registration: %v", err)
	}
	if !c.journal.retired(1) || len(c.journal.Retired) != maxJournalHistory {
		t.Fatal("capacity pressure discarded ownership history")
	}
}
