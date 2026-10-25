// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Offline journal format conversion only. This does not stop or disable Cilium,
// drain workloads, remove BPF pins or validate an older agent binary.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/datapath/vtep/returnaffinity"
)

func main() {
	journal := flag.String("journal", "", "absolute journal path from the stopped agent configuration")
	pins := flag.String("pins", "", "absolute return-affinity pins path from that configuration")
	apply := flag.Bool("apply", false, "atomically write the v1 journal after validation; default checks only")
	flag.Parse()
	count, err := returnaffinity.ExportLegacyJournal(*journal, *pins, !*apply)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	action := "Validated; journal unchanged"
	if *apply {
		action = "Exported version 1 journal"
	}
	fmt.Printf("%s; %d retired namespace cookies preserved\n", action, count)
}
