// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"log/slog"
	"path/filepath"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/option"
)

// Cell owns the socket controller, not the superseded CT/guard experiment.
var Cell = cell.Module("vtep-return-affinity", "Experimental VXLAN socket return affinity",
	cell.Provide(provideController))

func provideController(lc cell.Lifecycle, logger *slog.Logger) *Controller {
	c := NewController(logger, ControllerConfig{
		Enabled: option.Config.EnableExperimentalVTEPReturnAffinity,
		Journal: filepath.Join(option.Config.StateDir, "vtep-return-affinity.json"),
		Pins:    filepath.Join(bpf.CiliumPath(), "vtep-return-affinity"),
		Cgroup:  cgroups.GetCgroupRoot(),
	})
	lc.Append(cell.Hook{OnStart: func(cell.HookContext) error { return c.Start() },
		OnStop: func(cell.HookContext) error { return c.Close() }})
	return c
}
