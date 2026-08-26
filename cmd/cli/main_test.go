package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_Version(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-v"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(-v) exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "intunewin version") {
		t.Errorf("stdout = %q, want version string", stdout.String())
	}
}

func TestCLI_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-h"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(-h) exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "Usage: intunewin") {
		t.Errorf("stdout = %q, want usage string", stdout.String())
	}
}

func TestCLI_NoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() with no args exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "Usage: intunewin") {
		t.Errorf("stderr = %q, want usage string", stderr.String())
	}
}

func TestCLI_InvalidFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-invalid-flag-xyz"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run(-invalid-flag-xyz) exit code = %d, want 2", code)
	}
}

func TestCLI_MissingPackagingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-c", "some-dir"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() with missing flags exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "missing required arguments") {
		t.Errorf("stderr = %q, want missing arguments error", stderr.String())
	}
}

func TestCLI_ConflictingExtractAndPackageFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-e", "app.intunewin", "-c", "some-dir"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() with conflicting flags exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "cannot specify packaging flags") {
		t.Errorf("stderr = %q, want conflict error", stderr.String())
	}
}

func TestCLI_PackageAndExtract(t *testing.T) {
	contentDir := t.TempDir()
	setupFile := filepath.Join(contentDir, "install.cmd")
	if err := os.WriteFile(setupFile, []byte("echo install"), 0644); err != nil {
		t.Fatal(err)
	}

	outputDir := t.TempDir()

	// 1. Package using reversed flag order
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-s", "install.cmd",
		"-o", outputDir,
		"-c", contentDir,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run(package) exit code = %d, stderr = %s", code, stderr.String())
	}

	expectedPackage := filepath.Join(outputDir, "install.intunewin")
	if _, err := os.Stat(expectedPackage); err != nil {
		t.Fatalf("packaged file %s not found: %v", expectedPackage, err)
	}
	if !strings.Contains(stdout.String(), "Successfully created") {
		t.Errorf("stdout = %q, want success message", stdout.String())
	}

	// 2. Extract with -o
	extractDir := t.TempDir()
	stdout.Reset()
	stderr.Reset()

	code = run([]string{
		"-e", expectedPackage,
		"-o", extractDir,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run(extract) exit code = %d, stderr = %s", code, stderr.String())
	}

	extractedFile := filepath.Join(extractDir, "IntunePackage.intunewin")
	if _, err := os.Stat(extractedFile); err != nil {
		t.Fatalf("extracted payload %s not found: %v", extractedFile, err)
	}
	if !strings.Contains(stdout.String(), "Extracted package to") {
		t.Errorf("stdout = %q, want extract message", stdout.String())
	}

	// 3. Quiet mode packaging
	stdout.Reset()
	stderr.Reset()
	quietOutputDir := t.TempDir()

	code = run([]string{
		"-q",
		"-c", contentDir,
		"-s", "install.cmd",
		"-o", quietOutputDir,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run(quiet package) exit code = %d, stderr = %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("quiet mode produced stdout: %q", stdout.String())
	}
}

func TestCLI_ExtractNonexistent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-e", filepath.Join(t.TempDir(), "nonexistent.intunewin")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run(extract nonexistent) exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "failed to open package") {
		t.Errorf("stderr = %q, want open package error", stderr.String())
	}
}
