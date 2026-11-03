// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

var ErrStopped = errors.New("VTEP socket-affinity controller is stopped")

// AcquireLease prevents overlapping agent processes from publishing different
// owners for the same pinned runtime. The controller holds it until Close.
func AcquireLease(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another return-state controller owns the lease: %w", err)
	}
	return f, nil
}
