package pkg

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// writeContentDir creates a content directory containing a setup file and an
// extra file, so the created archive has to walk more than one entry.
func writeContentDir(t *testing.T, setupFileName string, setupFileContents []byte) string {
	t.Helper()

	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, setupFileName), setupFileContents, 0644); err != nil {
		t.Fatalf("failed to write setup file: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("just some extra content"), 0644); err != nil {
		t.Fatalf("failed to write extra file: %v", err)
	}

	return dir
}

// TestRoundTrip packages a content folder with NewIntunewin, reopens the
// resulting .intunewin file with OpenFile and extracts it with
// ExtractContent, then checks that the original files come back byte for
// byte. This exercises the outer HMAC check in OpenFile and the inner
// SHA-256 verification and PKCS#7 unpadding in decryptContentArchive.
func TestRoundTrip(t *testing.T) {
	// Use a payload that is not a multiple of the AES block size so PKCS#7
	// padding actually has to be added and stripped again.
	setupContents := bytes.Repeat([]byte("hello intunewin, "), 1000)

	contentDir := writeContentDir(t, "setup.exe", setupContents)
	outputDir := t.TempDir()

	iw, err := NewIntunewin("TestApp", contentDir, "setup.exe", outputDir)
	if err != nil {
		t.Fatalf("NewIntunewin() error = %v", err)
	}

	opened, err := OpenFile(iw.Path)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer opened.Close()

	// ExtractContent writes its output relative to the current working
	// directory, so run it from an isolated temp directory.
	extractDir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}
	if err := os.Chdir(extractDir); err != nil {
		t.Fatalf("os.Chdir() error = %v", err)
	}
	defer func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Fatalf("os.Chdir() error = %v", err)
		}
	}()

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
		t.Fatalf("extracted setup.exe contents = %d bytes, want %d bytes matching the original", len(got), len(setupContents))
	}
}

// TestOpenFile_TamperedContentFails flips a byte inside the encrypted
// content file after packaging and asserts that OpenFile reports the
// mismatch instead of silently succeeding. This guards against the outer
// HMAC failure being swallowed.
func TestOpenFile_TamperedContentFails(t *testing.T) {
	contentDir := writeContentDir(t, "setup.exe", bytes.Repeat([]byte("a"), 5000))
	outputDir := t.TempDir()

	iw, err := NewIntunewin("TestApp", contentDir, "setup.exe", outputDir)
	if err != nil {
		t.Fatalf("NewIntunewin() error = %v", err)
	}

	// The content file is stored (not compressed), so its data offset in
	// the zip can be used to flip a byte directly on disk.
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
	// Flip a byte well inside the ciphertext (past the 32 byte HMAC + 16
	// byte IV header) so the outer HMAC check catches the tamper.
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

func TestNewIntunewin_Validation(t *testing.T) {
	contentDir := writeContentDir(t, "setup.exe", []byte("data"))
	outputDir := t.TempDir()

	// Create a setup file in a subdirectory so we can exercise relative paths
	// such as "bin/setup.exe".
	subDir := filepath.Join(contentDir, "bin")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "setup.exe"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		nameArg     string
		contentPath string
		setupFile   string
		outputPath  string
		wantErr     bool
	}{
		{"valid", "TestApp", contentDir, "setup.exe", outputDir, false},
		{"valid relative path", "TestApp", contentDir, "bin/setup.exe", outputDir, false},
		{"blank name", "", contentDir, "setup.exe", outputDir, true},
		{"blank setup file", "TestApp", contentDir, "", outputDir, true},
		{"missing content dir", "TestApp", filepath.Join(contentDir, "nope"), "setup.exe", outputDir, true},
		{"content dir is a file", "TestApp", filepath.Join(contentDir, "setup.exe"), "setup.exe", outputDir, true},
		{"missing output dir", "TestApp", contentDir, "setup.exe", filepath.Join(outputDir, "nope"), true},
		{"setup file not in content dir", "TestApp", contentDir, "other.exe", outputDir, true},
		{"setup file is an absolute path", "TestApp", contentDir, filepath.Dir(contentDir) + "/setup.exe", outputDir, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewIntunewin(tt.nameArg, tt.contentPath, tt.setupFile, tt.outputPath)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewIntunewin() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
