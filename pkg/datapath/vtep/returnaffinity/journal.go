// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const journalVersion = 2

// Bound sparse history as well as active registrations. Reaching the bound
// rejects new registrations; it never forgets an old namespace incarnation.
const maxJournalHistory = 8192

type cookieRange struct {
	First uint64
	Last  uint64
}

type Peer struct {
	Address [4]byte
	MAC     [6]byte
}

// EndpointRegistration is captured by the synchronous CNI build. Cookies and
// kernel ifindices are rechecked in the namespace, not trusted as path names.
type EndpointRegistration struct {
	Cookie             uint64
	HostInterface      string
	HostIfindex        int
	NamespacePath      string
	ContainerInterface string
}

type membership struct {
	EndpointRegistration
	Phase        string
	QueueIfindex int
}

type socketJournal struct {
	Version     int
	BootID      string
	Initialized bool
	Disabled    bool
	Peers       []Peer
	Namespaces  map[uint64]membership
	Retired     []cookieRange `json:",omitempty"`
}

func (j socketJournal) retired(cookie uint64) bool {
	i := sort.Search(len(j.Retired), func(i int) bool { return j.Retired[i].Last >= cookie })
	return i < len(j.Retired) && j.Retired[i].First <= cookie
}

// Keep an exact set, not a high-water mark: gaps can contain unrelated live
// namespaces which must remain eligible for ordinary Cilium routing.
func (j *socketJournal) rememberRetired(cookie uint64) {
	i := sort.Search(len(j.Retired), func(i int) bool { return j.Retired[i].Last >= cookie })
	if i < len(j.Retired) && j.Retired[i].First <= cookie {
		return
	}
	left := i > 0 && j.Retired[i-1].Last == cookie-1
	right := i < len(j.Retired) && cookie != ^uint64(0) && j.Retired[i].First == cookie+1
	switch {
	case left && right:
		j.Retired[i-1].Last = j.Retired[i].Last
		j.Retired = append(j.Retired[:i], j.Retired[i+1:]...)
	case left:
		j.Retired[i-1].Last = cookie
	case right:
		j.Retired[i].First = cookie
	default:
		j.Retired = append(j.Retired, cookieRange{})
		copy(j.Retired[i+1:], j.Retired[i:])
		j.Retired[i] = cookieRange{cookie, cookie}
	}
}

func readJournal(path string) (socketJournal, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return socketJournal{}, err
	}
	return decodeJournal(data)
}

func decodeJournal(data []byte) (socketJournal, error) {
	var j socketJournal
	if err := json.Unmarshal(data, &j); err != nil {
		return j, err
	}
	if (j.Version != 1 && j.Version != journalVersion) || j.BootID == "" || j.Namespaces == nil ||
		(j.Version == 1 && len(j.Retired) != 0) {
		return j, fmt.Errorf("unsupported or incomplete VTEP socket journal")
	}
	for i, r := range j.Retired {
		if r.First == 0 || r.Last < r.First || (i > 0 && j.Retired[i-1].Last >= r.First-1) {
			return j, fmt.Errorf("invalid retired namespace history")
		}
	}
	for cookie, m := range j.Namespaces {
		if cookie == 0 || cookie != m.Cookie || j.retired(cookie) ||
			(m.Phase != "preparing" && m.Phase != "ready" && m.Phase != "retiring" && m.Phase != "retired") {
			return j, fmt.Errorf("invalid namespace membership in VTEP socket journal")
		}
	}
	// The next durable write migrates v1. Older binaries reject v2 rather than
	// silently losing compacted history; downgrade still requires drain.
	j.Version = journalVersion
	return j, nil
}

// The fsync/rename journal survives losing all bpffs pins. Missing maps must
// never look like an unused installation after an agent crash or reboot.
func writeJournal(path string, j socketJournal) (err error) {
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".vtep-return-")
	if err != nil {
		return err
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func bootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return string(b), err
}

func missing(err error) bool { return errors.Is(err, os.ErrNotExist) }
