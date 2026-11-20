// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This file was not reviewed by a human before submission

package returnaffinity

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// Cookie timing is an authorization boundary. Do not replace the exact kernel
// configuration with an estimated timer rate or accept an unreviewed kernel.
func ConfigureCookieTargets(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return fmt.Errorf("missing cookie runtime")
	}
	if spec.Programs["ck_synack_created"] == nil && spec.Programs["ck_child_created"] == nil &&
		spec.Programs["ck_synack_hz100"] == nil {
		return nil // Historical objects have no cookie forwarding.
	}
	period, err := CookieEpochPeriod()
	if err != nil {
		return err
	}
	if err := selectCookieProducer(spec, period); err != nil {
		return err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return err
	}
	return validateCookieHookTargets(spec, func(name string) (*btf.Func, error) {
		var fn *btf.Func
		err := kernel.TypeByName(name, &fn)
		return fn, err
	})
}

const cookieEpochSeconds = 60

func reviewedCookieKernelHZ(release, machine string) (int, error) {
	if machine == "x86_64" {
		switch release {
		case "6.8.0-31-generic", "6.12.0-061200-generic":
			return 1000, nil
		case "6.12.115-140.210.amzn2023.x86_64":
			return 100, nil
		}
	}
	return 0, fmt.Errorf("SYN-cookie timing is unreviewed for kernel %q (%q)", release, machine)
}

// CookieEpochPeriod returns an epoch in kernel jiffies, using the reviewed
// running-kernel build and verifying the matching kernel configuration.
func CookieEpochPeriod() (uint64, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return 0, err
	}
	release, machine := unix.ByteSliceToString(uts.Release[:]), unix.ByteSliceToString(uts.Machine[:])
	hz, err := reviewedCookieKernelHZ(release, machine)
	if err != nil {
		return 0, err
	}
	if err := validateCookieKernelHZ(release, hz); err != nil {
		return 0, err
	}
	return uint64(hz) * cookieEpochSeconds, nil
}

func selectCookieProducer(spec *ebpf.CollectionSpec, period uint64) error {
	const primary = "ck_synack_created"
	const hz100 = "ck_synack_hz100"
	producer := spec.Programs[primary]
	switch period {
	case 6000:
		if alternate := spec.Programs[hz100]; alternate != nil {
			producer = alternate
		}
		if producer == nil || producer.Name != hz100 {
			return fmt.Errorf("missing reviewed 100 Hz SYN-ACK producer")
		}
	case 60000:
		if producer == nil || producer.Name == hz100 {
			return fmt.Errorf("missing reviewed 1000 Hz SYN-ACK producer")
		}
	default:
		return fmt.Errorf("unreviewed SYN-cookie epoch period %d", period)
	}
	// Preserve the logical name and pin path. The selected period is an
	// instruction constant, so restoration checks it in the program tag.
	spec.Programs[primary] = producer
	delete(spec.Programs, hz100)
	return nil
}

func validateCookieKernelHZ(release string, hz int) error {
	f, err := os.Open("/proc/config.gz")
	if err == nil {
		defer f.Close()
		reader, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("invalid kernel configuration: %w", err)
		}
		defer reader.Close()
		return requireCookieHZ(reader, hz)
	}
	if !os.IsNotExist(err) {
		return err
	}
	// AL2023 ships the config alongside the kernel in the mounted module
	// tree, rather than in /proc or necessarily in the agent's /boot.
	f, err = os.Open("/lib/modules/" + release + "/config")
	if err == nil {
		defer f.Close()
		return requireCookieHZ(f, hz)
	}
	if !os.IsNotExist(err) {
		return err
	}
	f, err = os.Open("/boot/config-" + release)
	if err != nil {
		return fmt.Errorf("cookie timing requires the running kernel configuration: %w", err)
	}
	defer f.Close()
	return requireCookieHZ(f, hz)
}

func requireCookieHZ(reader io.Reader, hz int) error {
	const limit = 1 << 20
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return err
	}
	if len(data) > limit {
		return fmt.Errorf("oversized kernel configuration")
	}
	expected := "CONFIG_HZ=" + strconv.Itoa(hz)
	found := false
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "CONFIG_HZ=") {
			continue
		}
		if found || line != expected {
			return fmt.Errorf("cookie timing requires exactly one %s", expected)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("missing CONFIG_HZ for cookie timing")
	}
	return nil
}

func validateCookieHookTargets(spec *ebpf.CollectionSpec, lookup func(string) (*btf.Func, error)) error {
	for program, arguments := range map[string][]string{
		"ck_synack_created": {"sock", "dst_entry", "request_sock", "tcp_fastopen_cookie", "", "sk_buff"},
		"ck_child_created":  {"sock", "sk_buff", "request_sock", "dst_entry"},
	} {
		target, result := "tcp_get_cookie_sock", "sock"
		if program == "ck_synack_created" {
			target, result = "tcp_make_synack", "sk_buff"
		}
		p := spec.Programs[program]
		if p == nil || p.Type != ebpf.Tracing || p.AttachType != ebpf.AttachTraceFExit || p.AttachTo != target {
			return fmt.Errorf("missing or unexpected cookie hook %s", program)
		}
		fn, err := lookup(target)
		if err != nil {
			return err
		}
		if fn == nil {
			return fmt.Errorf("missing cookie target: %s", target)
		}
		proto, ok := btf.UnderlyingType(fn.Type).(*btf.FuncProto)
		if !ok || len(proto.Params) != len(arguments) || !pointerToStruct(proto.Return, result) {
			return fmt.Errorf("unreviewed cookie constructor ABI: %s", target)
		}
		for i, name := range arguments {
			if name != "" {
				if !pointerToStruct(proto.Params[i].Type, name) {
					return fmt.Errorf("unreviewed cookie constructor argument %d: %s", i, target)
				}
				continue
			}
			enum, ok := btf.UnderlyingType(proto.Params[i].Type).(*btf.Enum)
			if !ok || enum.Name != "tcp_synack_type" || enum.Size != 4 {
				return fmt.Errorf("unreviewed SYN-ACK kind")
			}
			valid := false
			for _, value := range enum.Values {
				if value.Name == "TCP_SYNACK_COOKIE" && value.Value == 2 {
					valid = true
				}
			}
			if !valid {
				return fmt.Errorf("unreviewed SYN-cookie kind value")
			}
		}
	}
	return nil
}
