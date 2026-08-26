//go:build windows

package pkg

import (
	"bytes"
	"testing"
)

func TestOpenFile_WindowsRoundTrip(t *testing.T) {
	contentDir := writeContentDir(t, "setup.exe", bytes.Repeat([]byte("hello intunewin, "), 1000))
	outputDir := t.TempDir()

	p, err := NewPackager("TestApp", contentDir, "setup.exe", outputDir).Package()
	if err != nil {
		t.Fatalf("Package() error = %v", err)
	}

	opened, err := OpenFile(p.Path)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer opened.Close()
}
