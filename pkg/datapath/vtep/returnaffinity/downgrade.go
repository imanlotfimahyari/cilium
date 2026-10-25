// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// legacyDisabledJournal expands compacted history without losing cookie
// membership. Version 1 represents a physically drained namespace as a retired
// membership forever. Index zero cannot identify a live interface; the empty
// namespace path cannot identify a binding. "lo" makes the old drain check
// deterministic without referring to a former interface name that may be reused.
func legacyDisabledJournal(j socketJournal) (socketJournal, error) {
	if !j.Disabled || j.Initialized {
		return socketJournal{}, fmt.Errorf("first drain selected pods and disable using the current feature-aware agent")
	}
	legacy := j
	legacy.Version = 1
	legacy.Retired = nil
	legacy.Namespaces = make(map[uint64]membership)
	for cookie, m := range j.Namespaces {
		// Accept our own previous export, making reruns idempotent. Full
		// memberships must first be drained/compacted by the current agent.
		if m != legacyTombstone(cookie) {
			return socketJournal{}, fmt.Errorf("uncompacted namespace membership remains; complete coordinated disable first")
		}
		legacy.Namespaces[cookie] = m
	}
	if len(legacy.Namespaces) > maxJournalHistory {
		return socketJournal{}, fmt.Errorf("legacy journal export exceeds %d cookie tombstones", maxJournalHistory)
	}
	for _, r := range j.Retired {
		// decodeJournal rejects zero/descending ranges, so span cannot wrap.
		span := r.Last - r.First + 1
		if span > uint64(maxJournalHistory-len(legacy.Namespaces)) {
			return socketJournal{}, fmt.Errorf("legacy journal export exceeds %d cookie tombstones; keep the current binary or complete a coordinated drain, disable and reboot before exporting", maxJournalHistory)
		}
		for cookie := r.First; ; cookie++ {
			legacy.Namespaces[cookie] = legacyTombstone(cookie)
			if cookie == r.Last {
				break
			}
		}
	}
	return legacy, nil
}

func legacyTombstone(cookie uint64) membership {
	return membership{EndpointRegistration: EndpointRegistration{Cookie: cookie, HostInterface: "lo"}, Phase: "retired"}
}

// ExportLegacyJournal checks or atomically rewrites an offline journal in v1
// format. Paths must match the stopped agent's configuration. It takes the same
// lease as the agent, requires a durable disabled/drained state and no pins,
// and preserves all same-boot retired cookies. It never removes pins or history.
// checkOnly performs all validation without rewriting the journal.
func ExportLegacyJournal(journalPath, pinsPath string, checkOnly bool) (int, error) {
	if !filepath.IsAbs(journalPath) || !filepath.IsAbs(pinsPath) {
		return 0, fmt.Errorf("journal and pins paths must be absolute and match the stopped agent configuration")
	}
	info, err := os.Lstat(journalPath)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("journal must be a regular file")
	}
	lease, err := AcquireLease(journalPath + ".lock")
	if err != nil {
		return 0, err
	}
	defer lease.Close()
	data, err := os.ReadFile(journalPath)
	if err != nil {
		return 0, err
	}
	// An export must not discard fields from an unrecognized future extension.
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var strict socketJournal
	if err := decoder.Decode(&strict); err != nil {
		return 0, fmt.Errorf("decode journal for legacy export: %w", err)
	}
	j, err := decodeJournal(data)
	if err != nil {
		return 0, err
	}
	boot, err := bootID()
	if err != nil {
		return 0, err
	}
	if j.BootID != boot {
		return 0, fmt.Errorf("journal belongs to another boot; start the current agent with the feature disabled to reconcile recovery first")
	}
	if entries, err := os.ReadDir(pinsPath); err == nil {
		if len(entries) != 0 {
			return 0, fmt.Errorf("VTEP pins remain; complete coordinated disable first")
		}
	} else if !missing(err) {
		return 0, err
	}
	legacy, err := legacyDisabledJournal(j)
	if err != nil {
		return 0, err
	}
	if !checkOnly {
		if err := writeJournal(journalPath, legacy); err != nil {
			return 0, err
		}
	}
	return len(legacy.Namespaces), nil
}
