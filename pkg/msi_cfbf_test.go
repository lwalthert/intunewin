package pkg

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/lwalthert/intunewin/internal/data"
)

func buildTestMSICFBF(t *testing.T) string {
	t.Helper()
	wixl, err := exec.LookPath("wixl")
	if err != nil {
		t.Skipf("wixl not available: %v", err)
	}

	src := filepath.Join("testdata", "msi", "test.wxs")
	out := filepath.Join(t.TempDir(), "test.msi")

	cmd := exec.Command(wixl, "-o", out, src)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wixl failed: %v\n%s", err, output)
	}
	return out
}

func TestCFBFMSIReader(t *testing.T) {
	msiPath := buildTestMSICFBF(t)

	reader := &cfbfMSIReader{path: msiPath}
	props, err := reader.Read()
	if err != nil {
		t.Fatalf("cfbfMSIReader.Read() error = %v", err)
	}

	t.Logf("Summary: %+v", props.Summary)
	t.Logf("Properties: %+v", props.Properties)
	t.Logf("Database: %+v", props.Database)

	if got := props.Properties["ProductCode"]; got != "{11111111-2222-3333-4444-555555555555}" {
		t.Errorf("ProductCode = %q, want {11111111-2222-3333-4444-555555555555}", got)
	}
	if got := props.Properties["ProductVersion"]; got != "1.2.3.4" {
		t.Errorf("ProductVersion = %q, want 1.2.3.4", got)
	}
	if got := props.Properties["Manufacturer"]; got != "Contoso" {
		t.Errorf("Manufacturer = %q, want Contoso", got)
	}
	if got := props.Summary["Package Code"]; got == "" {
		t.Error("Package Code summary property is empty")
	}

	if len(props.Database.Services) != 1 || props.Database.Services[0] != "TestSvc" {
		t.Errorf("Services = %v, want [TestSvc]", props.Database.Services)
	}
	if got := props.Database.Filesystems["app.txt"]; got != "MainComponent" {
		t.Errorf("Filesystems[app.txt] = %q, want MainComponent", got)
	}
	if got := props.Database.Components["MainComponent"]; got != "INSTALLFOLDER" {
		t.Errorf("Components[MainComponent] = %q, want INSTALLFOLDER", got)
	}
	if got := props.Database.Directories["INSTALLFOLDER"]; got != "ProgramFilesFolder" {
		t.Errorf("Directories[INSTALLFOLDER] = %q, want ProgramFilesFolder", got)
	}

	var info data.MSI
	data.ReadMSI(&info, props)
	if !info.ContainsSystemFolders {
		t.Error("ContainsSystemFolders = false, want true")
	}
	if !info.IncludesServices {
		t.Error("IncludesServices = false, want true")
	}
	if !info.IsMachineInstall {
		t.Error("IsMachineInstall = false, want true")
	}
}

func TestReadMSIStringPoolTruncatedExtendedEntry(t *testing.T) {
	// Header (4 bytes) + extended entry trigger (l=0, ref=1) with no following length bytes
	poolData := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x00, 0x00, 0x01, 0x00, // l=0, ref=1 (extended string entry missing low 16 bits)
	}
	streams := map[string][]byte{
		"_StringPool": poolData,
		"_StringData": []byte("test"),
	}

	_, _, err := readMSIStringPoolFromStreams(streams)
	if err == nil {
		t.Fatal("expected error for truncated extended string entry, got nil")
	}
}
