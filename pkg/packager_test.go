package pkg

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPackager_Validation(t *testing.T) {
	contentDir := writeContentDir(t, "setup.exe", []byte("data"))
	outputDir := t.TempDir()

	// Create a setup file in a subdirectory to test relative paths
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
		{"setup file starts with ./", "TestApp", contentDir, filepath.Dir(contentDir) + "./setup.exe", outputDir, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPackager(tt.nameArg, tt.contentPath, tt.setupFile, tt.outputPath)
			_, err := p.Package()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Packager.Package() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPackager_Package(t *testing.T) {
	payload := []byte("packager direct test payload")
	contentDir := writeContentDir(t, "setup.exe", payload)
	outputDir := t.TempDir()

	pr := NewPackager("DirectApp", contentDir, "setup.exe", outputDir)
	p, err := pr.Package()
	if err != nil {
		t.Fatalf("pr.Package() error = %v", err)
	}

	expectedPath := filepath.Join(outputDir, "DirectApp.intunewin")
	if p.Path != expectedPath {
		t.Fatalf("p.Path = %q, want %q", p.Path, expectedPath)
	}
	if p.Name != "DirectApp" {
		t.Fatalf("p.Name = %q, want %q", p.Name, "DirectApp")
	}

	// Calling Close() on an Intunewin object returned by Packager should be a safe no-op
	if err := p.Close(); err != nil {
		t.Fatalf("p.Close() error = %v", err)
	}

	// Verify file exists on disk
	if _, err := os.Stat(expectedPath); err != nil {
		t.Fatalf("stat failed for created archive: %v", err)
	}
}

func TestCreateContentArchive(t *testing.T) {
	contentDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(contentDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(contentDir, "sub")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "file2.txt"), []byte("content2"), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := createContentArchive(contentDir, &buf); err != nil {
		t.Fatalf("createContentArchive() error = %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader() error = %v", err)
	}

	files := make(map[string]string)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("f.Open() error = %v", err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("io.ReadAll() error = %v", err)
		}
		files[f.Name] = string(data)
	}

	if files["file1.txt"] != "content1" {
		t.Errorf("file1.txt = %q, want %q", files["file1.txt"], "content1")
	}
	if files["sub/file2.txt"] != "content2" {
		t.Errorf("sub/file2.txt = %q, want %q", files["sub/file2.txt"], "content2")
	}
}
