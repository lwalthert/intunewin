package pkg

import (
	"os"
	"path/filepath"
	"testing"
)

// writeContentDir creates a content directory containing a setup file and an
// extra file, so the created archive has to walk more than one entry.
func writeContentDir(t *testing.T, setupFileName string, setupFileContents []byte) string {
	t.Helper()

	dir := t.TempDir()

	setupPath := filepath.Join(dir, setupFileName)
	if err := os.MkdirAll(filepath.Dir(setupPath), 0755); err != nil {
		t.Fatalf("failed to create setup file dir: %v", err)
	}

	if err := os.WriteFile(setupPath, setupFileContents, 0644); err != nil {
		t.Fatalf("failed to write setup file: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("just some extra content"), 0644); err != nil {
		t.Fatalf("failed to write extra file: %v", err)
	}

	return dir
}
