package render

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const filename = "trivy-report.html"

func TestRender(t *testing.T) {
	tests := []struct {
		name       string
		goldenPath string
		jsonPath   string
	}{
		{
			name:       "happy all",
			jsonPath:   "testdata/input/happy.json",
			goldenPath: "testdata/golden/happy.html",
		},
		{
			name:       "graph",
			jsonPath:   "testdata/input/graph.json",
			goldenPath: "testdata/golden/graph.html",
		},
		{
			name:       "happy k8s",
			jsonPath:   "testdata/input/happy-k8s.json",
			goldenPath: "testdata/golden/happy-k8s.html",
		},
		{
			name:       "happy empty",
			jsonPath:   "testdata/input/empty.json",
			goldenPath: "testdata/golden/empty.html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			filePath := filepath.Join(cacheDir, filename)

			data, err := os.ReadFile(tt.jsonPath)
			require.NoError(t, err)

			err = Render(filePath, data)
			require.NoError(t, err)

			actual, err := os.ReadFile(filePath)
			require.NoError(t, err)

			expected, err := os.ReadFile(tt.goldenPath)
			require.NoError(t, err)

			assert.Equal(t, expected, actual)
		})
	}
}
