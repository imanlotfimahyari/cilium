// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestWrap(t *testing.T) {
	var (
		realEPBuffer   bytes.Buffer
		templateBuffer bytes.Buffer
	)

	realEP := testutils.NewTestEndpoint(t)
	template := wrap(&realEP)
	cfg := configWriterForTest(t)

	// Write the configuration that should be the same, and verify it is.
	err := cfg.WriteTemplateConfig(&realEPBuffer, &realEP)
	require.NoError(t, err)
	err = cfg.WriteTemplateConfig(&templateBuffer, template)
	require.NoError(t, err)
	require.Equal(t, realEPBuffer.String(), templateBuffer.String())
}

type selectedVTEPEndpoint struct{ testutils.TestEndpoint }

func (*selectedVTEPEndpoint) GetPropertyValue(key string) any {
	if key == endpoint.PropertyVTEPReturnAffinity {
		return true
	}
	return nil
}

func TestVTEPAffinityTemplateIsolation(t *testing.T) {
	plain := testutils.NewTestEndpoint(t)
	selected := &selectedVTEPEndpoint{plain}
	writer := configWriterForTest(t)
	var off, on, template bytes.Buffer
	require.NoError(t, writer.WriteTemplateConfig(&off, &plain))
	require.NoError(t, writer.WriteTemplateConfig(&on, selected))
	require.NoError(t, writer.WriteTemplateConfig(&template, wrap(selected)))
	require.NotContains(t, off.String(), "ENABLE_VTEP_RETURN_SOCKET_AFFINITY")
	require.NotContains(t, off.String(), "ENABLE_VTEP_RETURN_TIMEWAIT_AFFINITY")
	require.Contains(t, on.String(), "#define ENABLE_VTEP_RETURN_SOCKET_AFFINITY 1")
	require.Contains(t, on.String(), "#define ENABLE_VTEP_RETURN_TIMEWAIT_AFFINITY 1")
	require.Equal(t, on.String(), template.String())
	base := datapathHash{}
	first, err := base.hashTemplate(writer, &plain)
	require.NoError(t, err)
	second, err := base.hashTemplate(writer, selected)
	require.NoError(t, err)
	require.NotEqual(t, first, second, "affinity must never reuse an ordinary endpoint template")
}
