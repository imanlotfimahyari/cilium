// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/vtep/returnaffinity"
)

func TestVTEPReturnReadinessGate(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		c := &statusCollector{statusParams: statusParams{VTEPReturnAffinity: returnaffinity.NewController(nil, returnaffinity.ControllerConfig{Enabled: enabled})}}
		c.statusCollector = newCollector(slog.Default(), Config{})
		status := c.GetStatus(false, false).Cilium
		if enabled {
			if status.State != models.StatusStateFailure || !strings.Contains(status.Msg, "return-affinity runtime is not ready") {
				t.Fatalf("uninitialized affinity reported ready: %+v", status)
			}
		} else if status.Msg != "Not all probes executed at least once" {
			t.Fatalf("disabled affinity changed ordinary status: %+v", status)
		}
	}
}
