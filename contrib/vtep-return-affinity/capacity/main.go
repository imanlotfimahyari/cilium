// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Read-only operator diagnostic. No admission, cleanup or recovery actions.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/datapath/vtep/returnaffinity"
)

func main() {
	flags := flag.NewFlagSet("vtep-capacity", flag.ContinueOnError)
	maps := flags.String("maps", "", "existing experimental runtime maps directory (required)")
	if err := flags.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return
		}
		os.Exit(1)
	}
	if *maps == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: vtep-capacity --maps EXISTING_MAP_DIRECTORY")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report := returnaffinity.InspectCapacity(ctx, *maps)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		os.Exit(1)
	}
	if !report.Complete {
		os.Exit(1)
	}
	for _, entry := range report.Maps {
		if entry.AtCapacity {
			os.Exit(2)
		}
	}
}
