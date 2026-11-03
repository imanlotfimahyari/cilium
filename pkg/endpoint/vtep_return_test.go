// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/common"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	"github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/identity"
)

type affinityHeaderOrchestrator struct{ fakeendpoint.FakeOrchestrator }

func (*affinityHeaderOrchestrator) WriteEndpointConfig(w io.Writer, cfg types.Config) error {
	if cfg.GetOptions() == nil {
		return fmt.Errorf("header snapshot lost the endpoint options")
	}
	if cfg.GetPropertyValue(types.PropertyVTEPReturnAffinity) == true {
		_, err := fmt.Fprintln(w, "#define ENABLE_VTEP_RETURN_SOCKET_AFFINITY 1")
		return err
	}
	return nil
}

func TestAffinityHeaderWithEndpointLocked(t *testing.T) {
	for _, atHostNS := range []bool{false, true} {
		t.Run(fmt.Sprintf("host_namespace_%t", atHostNS), func(t *testing.T) {
			testAffinityHeaderWithEndpointLocked(t, atHostNS)
		})
	}
}

func testAffinityHeaderWithEndpointLocked(t *testing.T, atHostNS bool) {
	s := setupEndpointSuite(t)
	s.orchestrator = &affinityHeaderOrchestrator{}
	ep := s.endpointCreator(t, 256, identity.NumericIdentity(1256), s.createEndpointParams(t))
	dir := t.TempDir()
	ep.unconditionalLock()
	ep.properties[types.PropertyVTEPReturnAffinity] = true
	ep.properties[types.PropertyAtHostNS] = atHostNS
	done := make(chan error, 1)
	go func() { done <- ep.writeHeaderfile(dir) }()
	var err error
	select {
	case err = <-done:
		ep.unlock()
	case <-time.After(2 * time.Second):
		// Release a potential self-deadlock before failing, so the worker and
		// endpoint cleanup cannot be left waiting on this test's lock.
		ep.unlock()
		<-done
		t.Fatal("header generation re-entered the endpoint lock")
	}
	if err != nil {
		t.Fatal(err)
	}
	header, err := os.ReadFile(filepath.Join(dir, common.CHeaderFileName))
	if err != nil || !strings.Contains(string(header), "ENABLE_VTEP_RETURN_SOCKET_AFFINITY 1") {
		t.Fatalf("selected property was lost from the snapshot: %s %v", header, err)
	}
}
