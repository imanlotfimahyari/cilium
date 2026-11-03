// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/vtep/returnaffinity"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/option"
)

func (l *loader) initializeVTEPReturn(ctx context.Context, cfg *config.Config, tc tunnel.Config) error {
	if l.affinity == nil {
		if option.Config.EnableExperimentalVTEPReturnAffinity {
			return fmt.Errorf("VTEP return-affinity controller is missing")
		}
		return nil
	}
	if !l.affinity.Enabled() {
		return l.affinity.InitializeRuntime(nil)
	}
	if !option.Config.EnableVTEP || !option.Config.EnableIPv4 || option.Config.EnableIPv6 ||
		option.Config.DatapathMode != "veth" || !option.Config.EnableTCX ||
		option.Config.UnsafeDaemonConfigOption.EnableHostLegacyRouting || option.Config.EnableL7Proxy ||
		option.Config.EnableEndpointRoutes || cfg.EnableIPSec || cfg.EnableWireguard ||
		tc.EncapProtocol() != tunnel.VXLAN || tc.UnderlayProtocol() == tunnel.IPv6 {
		return fmt.Errorf("experimental VTEP return affinity requires IPv4-only VXLAN/veth with TCX and BPF host routing; endpoint routes, proxies and encryption are unsupported")
	}
	const source, object = "bpf_vtep_return.c", "bpf_vtep_return.o"
	if err := compileDefault(ctx, l.logger, source, object); err != nil {
		return err
	}
	spec, err := ebpf.LoadCollectionSpec(filepath.Join(option.Config.StateDir, object))
	if err != nil {
		return err
	}
	return l.affinity.InitializeRuntime(spec)
}

func affinityRegistration(ep endpoint.Endpoint) (returnaffinity.EndpointRegistration, error) {
	paths, ok := ep.(interface {
		GetContainerNetnsPath() string
		GetContainerInterfaceName() string
	})
	if !ok || !ep.RequireBPFRouting() || !ep.IPv4Address().IsValid() || ep.IPv6Address().IsValid() {
		return returnaffinity.EndpointRegistration{}, fmt.Errorf("endpoint lacks the required IPv4 veth CNI metadata")
	}
	return returnaffinity.EndpointRegistration{
		Cookie: ep.GetEndpointNetNsCookie(), HostInterface: ep.InterfaceName(), HostIfindex: ep.GetIfIndex(),
		NamespacePath: paths.GetContainerNetnsPath(), ContainerInterface: paths.GetContainerInterfaceName(),
	}, nil
}
