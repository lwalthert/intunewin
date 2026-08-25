//go:build msitools

package pkg

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/lwalthert/intunewin/internal/data"
)

// buildTestMSI compiles the WiX fixture into an MSI using wixl (shipped with
// msitools). It returns the path to the built MSI, or skips the test if wixl
// is not available.
func buildTestMSI(t *testing.T) string {
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

// TestMSIReader_RealFile validates the msitools reader against a real MSI file
// built from the WiX fixture. It is skipped when wixl is not installed.
func TestMSIReader_RealFile(t *testing.T) {
	msi := buildTestMSI(t)

	reader := &msiReader{path: msi}
	props, err := reader.Read()
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	if got := props.Properties["ProductCode"]; got != "{11111111-2222-3333-4444-555555555555}" {
		t.Errorf("ProductCode = %q", got)
	}
	if got := props.Properties["ProductVersion"]; got != "1.2.3.4" {
		t.Errorf("ProductVersion = %q", got)
	}
	if got := props.Properties["Manufacturer"]; got != "Contoso" {
		t.Errorf("Manufacturer = %q", got)
	}
	if got := props.Summary["Package Code"]; got == "" {
		t.Error("Package Code summary property is empty")
	}

	if len(props.Database.Services) != 1 || props.Database.Services[0] != "TestSvc" {
		t.Errorf("Services = %v", props.Database.Services)
	}
	if got := props.Database.Filesystems["app.txt"]; got != "MainComponent" {
		t.Errorf("Filesystems[app.txt] = %q", got)
	}
	if got := props.Database.Components["MainComponent"]; got != "INSTALLFOLDER" {
		t.Errorf("Components[MainComponent] = %q", got)
	}
	if got := props.Database.Directories["INSTALLFOLDER"]; got != "ProgramFilesFolder" {
		t.Errorf("Directories[INSTALLFOLDER] = %q", got)
	}

	// Feed the collected tables through the interpretation layer and confirm
	// the boolean metadata is derived correctly.
	var info data.MSI
	data.ReadMSI(&info, props)
	if !info.ContainsSystemFolders {
		t.Error("ContainsSystemFolders = false, want true (installs to Program Files)")
	}
	if !info.IncludesServices {
		t.Error("IncludesServices = false, want true")
	}
	if !info.IsMachineInstall {
		t.Error("IsMachineInstall = false, want true (ALLUSERS=1)")
	}
}

// TestMSIReader_MissingFile ensures a missing MSI produces an error rather than
// silently succeeding.
func TestMSIReader_MissingFile(t *testing.T) {
	reader := &msiReader{path: filepath.Join(t.TempDir(), "does-not-exist.msi")}
	if _, err := reader.Read(); err == nil {
		t.Fatal("Read() error = nil, want an error for a missing file")
	}
}
