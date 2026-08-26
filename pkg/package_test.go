package pkg

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestRoundTrip packages a content folder, reopens the resulting .intunewin
// file with OpenFile and extracts it with ExtractContent, then checks that
// the original files come back byte for byte.
func TestRoundTrip(t *testing.T) {
	// Use a payload that is not a multiple of the AES block size so PKCS#7
	// padding has to be added during encryption and stripped during decryption.
	setupContents := bytes.Repeat([]byte("hello intunewin, "), 1000)

	contentDir := writeContentDir(t, "setup.exe", setupContents)
	outputDir := t.TempDir()

	iw, err := PackageIntunewin("TestApp", contentDir, "setup.exe", outputDir)
	if err != nil {
		t.Fatalf("PackageIntunewin() error = %v", err)
	}

	opened, err := OpenFile(iw.Path)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer opened.Close()

	if opened.Name != "TestApp" {
		t.Errorf("opened.Name = %q, want %q", opened.Name, "TestApp")
	}

	extractDir := t.TempDir()
	if err := opened.ExtractContent(extractDir); err != nil {
		t.Fatalf("ExtractContent() error = %v", err)
	}

	extractedZip, err := zip.OpenReader(filepath.Join(extractDir, opened.applicationInfo.FileName))
	if err != nil {
		t.Fatalf("failed to open extracted content archive: %v", err)
	}
	defer extractedZip.Close()

	f, err := extractedZip.Open("setup.exe")
	if err != nil {
		t.Fatalf("extracted archive is missing setup.exe: %v", err)
	}
	defer f.Close()

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("failed to read setup.exe from extracted archive: %v", err)
	}

	if !bytes.Equal(got, setupContents) {
		t.Fatalf("extracted setup.exe contents = %d bytes, want %d bytes matching original", len(got), len(setupContents))
	}
}

// TestOpenFile_TamperedContentFails flips a byte inside the encrypted
// content file after packaging and asserts that OpenFile reports the
// mismatch instead of silently succeeding.
func TestOpenFile_TamperedContentFails(t *testing.T) {
	contentDir := writeContentDir(t, "setup.exe", bytes.Repeat([]byte("a"), 5000))
	outputDir := t.TempDir()

	iw, err := PackageIntunewin("TestApp", contentDir, "setup.exe", outputDir)
	if err != nil {
		t.Fatalf("PackageIntunewin() error = %v", err)
	}

	r, err := zip.OpenReader(iw.Path)
	if err != nil {
		t.Fatalf("failed to open packaged file: %v", err)
	}
	var offset int64
	found := false
	for _, zf := range r.File {
		if zf.Name == contentsDir+outputFileName {
			offset, err = zf.DataOffset()
			if err != nil {
				t.Fatalf("failed to get data offset: %v", err)
			}
			found = true
		}
	}
	r.Close()
	if !found {
		t.Fatalf("content entry %s not found in packaged file", contentsDir+outputFileName)
	}

	raw, err := os.OpenFile(iw.Path, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to reopen packaged file for tampering: %v", err)
	}
	// Flip a byte well inside ciphertext (past the 32 byte HMAC + 16 byte IV header)
	if _, err := raw.WriteAt([]byte{0xFF}, offset+64); err != nil {
		t.Fatalf("failed to tamper with packaged file: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("failed to close tampered file: %v", err)
	}

	if _, err := OpenFile(iw.Path); err == nil {
		t.Fatal("OpenFile() error = nil, want an error for tampered content")
	}
}

func TestOpenFile_InvalidFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nonexistent.intunewin")
	if _, err := OpenFile(missing); err == nil {
		t.Error("OpenFile() error = nil for nonexistent file, want error")
	}

	invalidZip := filepath.Join(t.TempDir(), "corrupt.intunewin")
	if err := os.WriteFile(invalidZip, []byte("not a zip file"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(invalidZip); err == nil {
		t.Error("OpenFile() error = nil for non-zip file, want error")
	}
}

func TestPackage_Close(t *testing.T) {
	// Closing an Package instance with nil reader should not panic
	var uninitialized Package
	if err := uninitialized.Close(); err != nil {
		t.Errorf("uninitialized.Close() error = %v, want nil", err)
	}
}
