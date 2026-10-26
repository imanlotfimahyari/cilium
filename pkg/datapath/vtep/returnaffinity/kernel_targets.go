// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// ConfigureTimewaitTarget selects only the two reviewed publication points.
// Both enter with the live TIME-WAIT object and original full socket, before
// publishing the former. Linux 6.12 combines hashdance and timer scheduling.
// This changes no hook count, ownership maps or packet-path instructions.
// The caller owns spec; use a copy when retaining an unconfigured template.
func ConfigureTimewaitTarget(spec *ebpf.CollectionSpec) error {
	if spec == nil || spec.Programs["vtep_tw_transfer"] == nil {
		return fmt.Errorf("missing TIME-WAIT transfer program")
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("TIME-WAIT requires kernel BTF: %w", err)
	}
	target, err := selectTimewaitTarget(func(name string) (*btf.Func, error) {
		var fn *btf.Func
		err := kernel.TypeByName(name, &fn)
		return fn, err
	})
	if err != nil {
		return err
	}
	program := spec.Programs["vtep_tw_transfer"]
	if program.Type != ebpf.Tracing || program.AttachType != ebpf.AttachTraceFEntry {
		return fmt.Errorf("unexpected TIME-WAIT transfer attachment type")
	}
	program.AttachTo = target
	return validatePacketHookTargets(spec, func(name string) (*btf.Func, error) {
		var fn *btf.Func
		err := kernel.TypeByName(name, &fn)
		return fn, err
	})
}

func pointerToStruct(t btf.Type, name string) bool {
	pointer, ok := btf.UnderlyingType(t).(*btf.Pointer)
	if !ok {
		return false
	}
	structure, ok := btf.UnderlyingType(pointer.Target).(*btf.Struct)
	return ok && structure.Name == name
}

// Raw tracing contexts use argument indexes. In particular, ctx[4] must be
// __ip_make_skb's return value, never a newly added fifth argument. Verify the
// arguments actually read by every producer/cleanup hook before loading it.
func validatePacketHookTargets(spec *ebpf.CollectionSpec, lookup func(string) (*btf.Func, error)) error {
	for program, target := range map[string]string{
		"vtep_tw_destroy": "inet_twsk_free", "tw_packet_release": "skb_release_head_state",
		"tw_packet_created": "__ip_make_skb", "tw_ack_enter": "tcp_v4_send_ack", "tw_ack_exit": "tcp_v4_send_ack",
	} {
		p := spec.Programs[program]
		if p == nil { // The separate lifetime fixture loads only two hooks.
			continue
		}
		if p.AttachTo != target {
			return fmt.Errorf("unexpected TIME-WAIT target: %s", program)
		}
		fn, err := lookup(target)
		if err != nil {
			return err
		}
		if fn == nil {
			return fmt.Errorf("missing TIME-WAIT target: %s", target)
		}
		proto, ok := btf.UnderlyingType(fn.Type).(*btf.FuncProto)
		if !ok {
			return fmt.Errorf("missing TIME-WAIT prototype: %s", target)
		}
		if target == "__ip_make_skb" {
			if len(proto.Params) != 4 || !pointerToStruct(proto.Return, "sk_buff") {
				return fmt.Errorf("unreviewed packet constructor ABI: %s", target)
			}
			for i, name := range []string{"sock", "flowi4", "sk_buff_head", "inet_cork"} {
				if !pointerToStruct(proto.Params[i].Type, name) {
					return fmt.Errorf("unreviewed packet constructor argument: %d", i)
				}
			}
			continue
		}
		if _, ok := btf.UnderlyingType(proto.Return).(*btf.Void); !ok {
			return fmt.Errorf("unreviewed TIME-WAIT return type: %s", target)
		}
		if target == "tcp_v4_send_ack" {
			if (len(proto.Params) != 11 && len(proto.Params) != 12) ||
				!pointerToStruct(proto.Params[0].Type, "sock") || !pointerToStruct(proto.Params[1].Type, "sk_buff") {
				return fmt.Errorf("unreviewed ACK emission ABI")
			}
			for _, param := range proto.Params[2:4] {
				integer, ok := btf.UnderlyingType(param.Type).(*btf.Int)
				if !ok || integer.Size != 4 || integer.Encoding != btf.Unsigned {
					return fmt.Errorf("unreviewed ACK sequence argument")
				}
			}
		} else {
			name := "sk_buff"
			if target == "inet_twsk_free" {
				name = "inet_timewait_sock"
			}
			if len(proto.Params) != 1 || !pointerToStruct(proto.Params[0].Type, name) {
				return fmt.Errorf("unreviewed destruction ABI: %s", target)
			}
		}
	}
	return nil
}

func selectTimewaitTarget(lookup func(string) (*btf.Func, error)) (string, error) {
	for _, name := range []string{"inet_twsk_hashdance", "inet_twsk_hashdance_schedule"} {
		fn, err := lookup(name)
		if errors.Is(err, btf.ErrNotFound) {
			continue
		}
		if err != nil {
			return "", err
		}
		if fn == nil {
			return "", fmt.Errorf("missing TIME-WAIT function type")
		}
		proto, ok := btf.UnderlyingType(fn.Type).(*btf.FuncProto)
		count := 3
		if name == "inet_twsk_hashdance_schedule" {
			count = 4
		}
		if !ok || len(proto.Params) != count {
			return "", fmt.Errorf("unreviewed TIME-WAIT target signature: %s", name)
		}
		if _, ok := btf.UnderlyingType(proto.Return).(*btf.Void); !ok {
			return "", fmt.Errorf("unreviewed TIME-WAIT return type: %s", name)
		}
		for i, expected := range []string{"inet_timewait_sock", "sock", "inet_hashinfo"} {
			if !pointerToStruct(proto.Params[i].Type, expected) {
				return "", fmt.Errorf("unreviewed TIME-WAIT argument %d: %s", i, name)
			}
		}
		if count == 4 {
			timeout, ok := btf.UnderlyingType(proto.Params[3].Type).(*btf.Int)
			if !ok || timeout.Size != 4 || timeout.Encoding != btf.Signed {
				return "", fmt.Errorf("unreviewed TIME-WAIT timeout argument: %s", name)
			}
		}
		return name, nil
	}
	return "", fmt.Errorf("no reviewed TIME-WAIT publication hook in kernel BTF")
}
