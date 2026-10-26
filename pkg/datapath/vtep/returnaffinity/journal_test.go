// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestJournalRejectsAmbiguousOrFutureStateWithoutRewriting(t *testing.T) {
	for name, body := range map[string]string{
		"future_field":        `{"Version":2,"BootID":"test","Namespaces":{},"FutureOwnership":true}`,
		"nested_future_field": `{"Version":2,"BootID":"test","Namespaces":{"1":{"Cookie":1,"Phase":"retired","FutureOwner":2}}}`,
		"duplicate_history":   `{"Version":2,"BootID":"test","Namespaces":{},"Retired":[{"First":1,"Last":2}],"Retired":[]}`,
		"case_alias":          `{"Version":2,"BootID":"test","Namespaces":{},"namespaces":{}}`,
		"nested_duplicate":    `{"Version":2,"BootID":"test","Namespaces":{},"Retired":[{"First":1,"Last":2,"last":3}]}`,
		"numeric_alias":       `{"Version":2,"BootID":"test","Namespaces":{"01":{"Cookie":1,"Phase":"retired"},"1":{"Cookie":1,"Phase":"retired"}}}`,
		"duplicate_cookie":    `{"Version":2,"BootID":"test","Namespaces":{"1":{"Cookie":1,"Phase":"retired"},"1":{"Cookie":1,"Phase":"ready"}}}`,
		"trailing_object":     `{"Version":2,"BootID":"test","Namespaces":{}} {}`,
		"trailing_garbage":    `{"Version":2,"BootID":"test","Namespaces":{}} x`,
	} {
		t.Run(name, func(t *testing.T) {
			for _, enabled := range []bool{false, true} {
				c := unitController(t, enabled)
				if err := os.MkdirAll(filepath.Dir(c.cfg.Journal), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(c.cfg.Journal, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				if err := c.Start(); err == nil {
					t.Fatal("ambiguous or future history was accepted")
				}
				after, err := os.ReadFile(c.cfg.Journal)
				if err != nil || !bytes.Equal(after, []byte(body)) {
					t.Fatalf("refusal changed durable history: %v", err)
				}
			}
		})
	}
}

func TestJournalReadBoundsPreserveOversizedHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxJournalBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := readJournal(path); err == nil {
		t.Fatal("unbounded recovery input was accepted")
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != maxJournalBytes+1 {
		t.Fatal("oversized recovery input was modified")
	}
	if _, err := readJournal(t.TempDir()); err == nil {
		t.Fatal("directory accepted as a journal")
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readJournal(fifo); err == nil {
		t.Fatal("FIFO accepted as a journal")
	}
}

func BenchmarkJournalRecoveryAtAdmissionCapacity(b *testing.B) {
	j := socketJournal{Version: journalVersion, BootID: "benchmark", Namespaces: map[uint64]membership{}}
	for i := range maxJournalHistory {
		j.rememberRetired(uint64(2*i + 1))
	}
	data, err := json.Marshal(j)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := decodeJournal(data); err != nil {
			b.Fatal(err)
		}
	}
}

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
