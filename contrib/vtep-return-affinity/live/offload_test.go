// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package live

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The isolated amd64 fixture uses Linux's legacy ethtool_value ioctl to avoid
// installing a userspace utility in the guest. This is test-only ABI code.
func offloadValue(name string, command, value uint32) (uint32, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	data := struct{ Command, Value uint32 }{command, value}
	request := struct {
		Name [unix.IFNAMSIZ]byte
		Data unsafe.Pointer
		Pad  [16]byte
	}{Data: unsafe.Pointer(&data)}
	copy(request.Name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&request)))
	runtime.KeepAlive(&data)
	if errno != 0 {
		return 0, errno
	}
	return data.Value, nil
}

func TestPrivilegedCoreOffloadModes(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		for _, disabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("mapped=%v/disabled=%v", mapped, disabled), func(t *testing.T) {
				f := newHandoffListenerFixture(t, tcpModeObject(t, "VTEP_RETURN_CORE_OBJECT"), mapped)
				if err := f.podNS.Do(func() error {
					for _, commands := range [][2]uint32{{unix.ETHTOOL_GTSO, unix.ETHTOOL_STSO},
						{unix.ETHTOOL_GGSO, unix.ETHTOOL_SGSO}, {unix.ETHTOOL_GGRO, unix.ETHTOOL_SGRO}} {
						if disabled {
							if _, err := offloadValue(f.pod.remote.Attrs().Name, commands[1], 0); err != nil {
								return err
							}
						}
						value, err := offloadValue(f.pod.remote.Attrs().Name, commands[0], 0)
						if err != nil {
							return err
						}
						if disabled && value != 0 {
							return fmt.Errorf("offload remained enabled")
						}
						t.Logf("pod ethtool query %#x enabled=%v", commands[0], value != 0)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				for i, peer := range []int{0, 1, -1} {
					client, server := f.connect(t, peer, 48520+i)
					owner := f.owner(t, server)
					payload := bytes.Repeat([]byte{byte('a' + i)}, 256<<10)
					server.SetWriteDeadline(time.Now().Add(10 * time.Second))
					client.SetReadDeadline(time.Now().Add(10 * time.Second))
					written := make(chan error, 1)
					go func() { _, err := server.Write(payload); written <- err }()
					got := make([]byte, len(payload))
					_, readErr := io.ReadFull(client, got)
					if err := <-written; err != nil || readErr != nil || !bytes.Equal(got, payload) {
						t.Fatalf("offload transfer write=%v read=%v", err, readErr)
					}
					if f.owner(t, server) != owner {
						t.Fatal("offload mode changed return ownership")
					}
				}
				f.noPending(t)
			})
		}
	}
}
