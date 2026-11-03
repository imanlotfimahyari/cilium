// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestCookieTimingRequiresExactKernelConfiguration(t *testing.T) {
	for _, config := range []string{"", "CONFIG_HZ=100", "CONFIG_HZ=250", "CONFIG_HZ=1000\nCONFIG_HZ=1000", "CONFIG_HZ=1000x", "# CONFIG_HZ=1000", strings.Repeat("x", (1<<20)+1)} {
		if requireCookieHZ(strings.NewReader(config)) == nil {
			t.Fatal("accepted absent, ambiguous, unreviewed or oversized kernel timing")
		}
	}
	if err := requireCookieHZ(strings.NewReader("# public test configuration\nCONFIG_HZ=1000\nCONFIG_NET=y\n")); err != nil {
		t.Fatal(err)
	}
}

func TestCookieRawContextABIRefusesSlotChanges(t *testing.T) {
	pointer := func(name string) btf.Type { return &btf.Pointer{Target: &btf.Struct{Name: name}} }
	for _, scenario := range []string{"valid", "extra_argument", "wrong_return", "wrong_cookie_enum", "wrong_syn_pointer", "wrong_child_pointer", "missing_program"} {
		t.Run(scenario, func(t *testing.T) {
			makeProto := &btf.FuncProto{Return: pointer("sk_buff"), Params: []btf.FuncParam{
				{Type: pointer("sock")}, {Type: pointer("dst_entry")}, {Type: pointer("request_sock")},
				{Type: pointer("tcp_fastopen_cookie")}, {Type: &btf.Enum{Name: "tcp_synack_type", Size: 4, Values: []btf.EnumValue{{Name: "TCP_SYNACK_COOKIE", Value: 2}}}},
				{Type: pointer("sk_buff")},
			}}
			childProto := &btf.FuncProto{Return: pointer("sock"), Params: []btf.FuncParam{
				{Type: pointer("sock")}, {Type: pointer("sk_buff")}, {Type: pointer("request_sock")}, {Type: pointer("dst_entry")},
			}}
			spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
				"ck_synack_created": {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFExit, AttachTo: "tcp_make_synack"},
				"ck_child_created":  {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFExit, AttachTo: "tcp_get_cookie_sock"},
			}}
			switch scenario {
			case "extra_argument":
				makeProto.Params = append(makeProto.Params, btf.FuncParam{Type: pointer("sock")})
			case "wrong_return":
				makeProto.Return = pointer("sock")
			case "wrong_cookie_enum":
				makeProto.Params[4].Type.(*btf.Enum).Values[0].Value = 1
			case "wrong_syn_pointer":
				makeProto.Params[5].Type = pointer("request_sock")
			case "wrong_child_pointer":
				childProto.Params[1].Type = pointer("request_sock")
			case "missing_program":
				delete(spec.Programs, "ck_child_created")
			}
			err := validateCookieHookTargets(spec, func(name string) (*btf.Func, error) {
				proto := childProto
				if name == "tcp_make_synack" {
					proto = makeProto
				}
				return &btf.Func{Type: proto}, nil
			})
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("ABI decision for %s: %v", scenario, err)
			}
		})
	}
}
