// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
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
	if spec.Programs["ck_synack_created"] == nil && spec.Programs["ck_child_created"] == nil {
		return nil // Historical objects have no cookie forwarding.
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return err
	}
	release := unix.ByteSliceToString(uts.Release[:])
	if release != "6.8.0-31-generic" && release != "6.12.0-061200-generic" {
		return fmt.Errorf("SYN-cookie timing is unreviewed for this kernel build")
	}
	if err := validateCookieKernelHZ(release); err != nil {
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

func validateCookieKernelHZ(release string) error {
	f, err := os.Open("/proc/config.gz")
	if err == nil {
		defer f.Close()
		reader, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("invalid kernel configuration: %w", err)
		}
		defer reader.Close()
		return requireCookieHZ(reader)
	}
	if !os.IsNotExist(err) {
		return err
	}
	f, err = os.Open("/boot/config-" + release)
	if err != nil {
		return fmt.Errorf("cookie timing requires the running kernel configuration: %w", err)
	}
	defer f.Close()
	return requireCookieHZ(f)
}

func requireCookieHZ(reader io.Reader) error {
	const limit = 1 << 20
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return err
	}
	if len(data) > limit {
		return fmt.Errorf("oversized kernel configuration")
	}
	found := false
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "CONFIG_HZ=") {
			continue
		}
		if found || line != "CONFIG_HZ=1000" {
			return fmt.Errorf("cookie timing requires exactly one CONFIG_HZ=1000")
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
