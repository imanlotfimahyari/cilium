// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func testTimewaitTarget(scheduled bool) *btf.Func {
	proto := &btf.FuncProto{Return: &btf.Void{}}
	for _, name := range []string{"inet_timewait_sock", "sock", "inet_hashinfo"} {
		proto.Params = append(proto.Params, btf.FuncParam{Type: &btf.Pointer{Target: &btf.Struct{Name: name}}})
	}
	if scheduled {
		proto.Params = append(proto.Params, btf.FuncParam{Type: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}})
	}
	return &btf.Func{Type: proto}
}

func TestPacketConstructorReturnSlotCannotShift(t *testing.T) {
	for _, extraArgument := range []bool{false, true} {
		proto := &btf.FuncProto{Return: &btf.Pointer{Target: &btf.Struct{Name: "sk_buff"}}}
		for _, name := range []string{"sock", "flowi4", "sk_buff_head", "inet_cork"} {
			proto.Params = append(proto.Params, btf.FuncParam{Type: &btf.Pointer{Target: &btf.Struct{Name: name}}})
		}
		if extraArgument {
			proto.Params = append(proto.Params, btf.FuncParam{Type: &btf.Int{Size: 8}})
		}
		spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
			"tw_packet_created": {AttachTo: "__ip_make_skb"},
		}}
		err := validatePacketHookTargets(spec, func(string) (*btf.Func, error) { return &btf.Func{Type: proto}, nil })
		if (err != nil) != extraArgument {
			t.Fatalf("constructor return slot validation: extra=%v error=%v", extraArgument, err)
		}
	}
}

func TestTimewaitTargetRequiresReviewedABI(t *testing.T) {
	for _, name := range []string{"inet_twsk_hashdance", "inet_twsk_hashdance_schedule"} {
		t.Run(name, func(t *testing.T) {
			for _, damage := range []string{"none", "count", "tw_type", "socket_type", "return", "timeout"} {
				if damage == "timeout" && name == "inet_twsk_hashdance" {
					continue
				}
				fn := testTimewaitTarget(name == "inet_twsk_hashdance_schedule")
				proto := fn.Type.(*btf.FuncProto)
				switch damage {
				case "count":
					proto.Params = proto.Params[:2]
				case "tw_type":
					proto.Params[0].Type = &btf.Pointer{Target: &btf.Struct{Name: "sock"}}
				case "socket_type":
					proto.Params[1].Type = &btf.Int{Size: 8}
				case "return":
					proto.Return = &btf.Int{Size: 4}
				case "timeout":
					proto.Params[3].Type = &btf.Int{Size: 8}
				}
				target, err := selectTimewaitTarget(func(candidate string) (*btf.Func, error) {
					if candidate == name {
						return fn, nil
					}
					return nil, btf.ErrNotFound
				})
				if damage == "none" && (err != nil || target != name) {
					t.Fatalf("reviewed target refused: %v", err)
				}
				if damage != "none" && err == nil {
					t.Fatalf("unreviewed %s signature accepted", damage)
				}
			}
		})
	}
	if _, err := selectTimewaitTarget(func(string) (*btf.Func, error) { return nil, btf.ErrNotFound }); err == nil {
		t.Fatal("missing publication point accepted")
	}
}
