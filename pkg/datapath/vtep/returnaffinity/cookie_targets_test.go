// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This file was not reviewed by a human before submission

package returnaffinity

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestCookieTimingRequiresExactKernelConfiguration(t *testing.T) {
	for _, config := range []string{"", "CONFIG_HZ=100", "CONFIG_HZ=250", "CONFIG_HZ=1000\nCONFIG_HZ=1000", "CONFIG_HZ=1000x", "# CONFIG_HZ=1000", strings.Repeat("x", (1<<20)+1)} {
		if requireCookieHZ(strings.NewReader(config), 1000) == nil {
			t.Fatal("accepted absent, ambiguous, unreviewed or oversized kernel timing")
		}
	}
	if err := requireCookieHZ(strings.NewReader("# public test configuration\nCONFIG_HZ=1000\nCONFIG_NET=y\n"), 1000); err != nil {
		t.Fatal(err)
	}
}

func TestCookieAL2023ProfileRequiresExactReleaseArchitectureAndTiming(t *testing.T) {
	const release = "6.12.115-140.210.amzn2023.x86_64"
	for _, candidate := range []struct {
		release, machine string
		expected         int
	}{
		{release, "x86_64", 100},
		{"6.8.0-31-generic", "x86_64", 1000},
		{"6.12.0-061200-generic", "x86_64", 1000},
		{release, "aarch64", 0},
		{release + "-debug", "x86_64", 0},
		{"6.12.115-140.211.amzn2023.x86_64", "x86_64", 0},
	} {
		hz, err := reviewedCookieKernelHZ(candidate.release, candidate.machine)
		if hz != candidate.expected || (err == nil) != (hz != 0) {
			t.Fatalf("unexpected kernel profile for %v: %d, %v", candidate, hz, err)
		}
	}
	if err := requireCookieHZ(strings.NewReader("CONFIG_HZ_100=y\nCONFIG_HZ=100\n"), 100); err != nil {
		t.Fatal(err)
	}
	for _, config := range []string{"CONFIG_HZ=1000", "CONFIG_HZ=100\nCONFIG_HZ=100", "CONFIG_HZ=100x"} {
		if err := requireCookieHZ(strings.NewReader(config), 100); err == nil {
			t.Fatalf("accepted ambiguous or mismatched AL2023 kernel config: %q", config)
		}
	}
}

func TestCookieProducerSelectionKeepsOneLogicalHook(t *testing.T) {
	for period, expected := range map[uint64]string{60000: "ck_synack_created", 6000: "ck_synack_hz100"} {
		spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
			"ck_synack_created": {Name: "ck_synack_created"},
			"ck_synack_hz100":   {Name: "ck_synack_hz100"},
			"ck_child_created":  {Name: "ck_child_created"},
		}}
		for range 2 {
			if err := selectCookieProducer(spec, period); err != nil {
				t.Fatal(err)
			}
		}
		if len(spec.Programs) != 2 || spec.Programs["ck_synack_created"].Name != expected {
			t.Fatalf("unexpected producer selection for %d: %v", period, spec.Programs)
		}
	}
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"ck_synack_created": {Name: "ck_synack_created"}}}
	if err := selectCookieProducer(spec, 6000); err == nil {
		t.Fatal("accepted the 1000 Hz producer for a 100 Hz kernel")
	}
	if err := selectCookieProducer(spec, 15000); err == nil {
		t.Fatal("accepted an unreviewed epoch")
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
