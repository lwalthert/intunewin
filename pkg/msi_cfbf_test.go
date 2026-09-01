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

func TestParsePropertyValueOverflow(t *testing.T) {
	// VT_LPSTR (type 30) with length 0xFFFFFFFF
	lpstrData := []byte{
		30, 0, 0, 0, // VT_LPSTR
		0xFF, 0xFF, 0xFF, 0xFF, // length 0xFFFFFFFF
		'h', 'e', 'l', 'l', 'o',
	}
	if got := parsePropertyValue(lpstrData); got != "" {
		t.Errorf("parsePropertyValue(VT_LPSTR overflow) = %q, want empty string", got)
	}

	// VT_LPWSTR (type 31) with charCount 0x80000000
	lpwstrData := []byte{
		31, 0, 0, 0, // VT_LPWSTR
		0x00, 0x00, 0x00, 0x80, // charCount 0x80000000 (overflows charCount*2)
		'h', 0, 'i', 0,
	}
	if got := parsePropertyValue(lpwstrData); got != "" {
		t.Errorf("parsePropertyValue(VT_LPWSTR overflow) = %q, want empty string", got)
	}
}

func TestParseSummaryInfoPropOffsetOverflow(t *testing.T) {
	// 48 bytes header + section
	data := make([]byte, 80)
	// Byte order
	data[0] = 0xFE
	data[1] = 0xFF
	// numPropSets = 1
	data[24] = 1
	// setOffset = 48
	data[44] = 48
	// setData: offset 48
	// numProps = 1 (offset 48+4 = 52)
	data[52] = 1
	// prop entry: offset 48+8 = 56
	// pid = 9 (Package Code)
	data[56] = 9
	// propOffset = 0xFFFFFFFF (offset 48+12 = 60)
	data[60] = 0xFF
	data[61] = 0xFF
	data[62] = 0xFF
	data[63] = 0xFF

	val, err := parseSummaryInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "" {
		t.Errorf("parseSummaryInfo(propOffset overflow) = %q, want empty string", val)
	}
}

func TestReadMSITableInt(t *testing.T) {
	tests := []struct {
		name    string
		bytes   []byte
		size    int
		wantVal int
		wantOk  bool
	}{
		{"1-byte NULL", []byte{0x00}, 1, 0, false},
		{"1-byte 0", []byte{0x80}, 1, 0, true},
		{"1-byte 2", []byte{0x82}, 1, 2, true},
		{"1-byte -1", []byte{0x7F}, 1, -1, true},
		{"2-byte NULL", []byte{0x00, 0x00}, 2, 0, false},
		{"2-byte 0", []byte{0x00, 0x80}, 2, 0, true},
		{"2-byte 2 (HKLM root)", []byte{0x02, 0x80}, 2, 2, true},
		{"2-byte -1", []byte{0xFF, 0x7F}, 2, -1, true},
		{"2-byte -2", []byte{0xFE, 0x7F}, 2, -2, true},
		{"4-byte NULL", []byte{0x00, 0x00, 0x00, 0x00}, 4, 0, false},
		{"4-byte 0", []byte{0x00, 0x00, 0x00, 0x80}, 4, 0, true},
		{"4-byte 100", []byte{0x64, 0x00, 0x00, 0x80}, 4, 100, true},
		{"4-byte -1", []byte{0xFF, 0xFF, 0xFF, 0x7F}, 4, -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVal, gotOk := readMSITableInt(tt.bytes, tt.size)
			if gotOk != tt.wantOk || (gotOk && gotVal != tt.wantVal) {
				t.Errorf("readMSITableInt(%v, %d) = (%d, %t), want (%d, %t)", tt.bytes, tt.size, gotVal, gotOk, tt.wantVal, tt.wantOk)
			}
		})
	}
}

func TestReadMSIStringPoolSinglePass(t *testing.T) {
	// Header with 3-byte flag (0x8000 in word 1)
	poolData := []byte{
		0x00, 0x00, 0x00, 0x80, // codepage 0, is3ByteString = true
		0x00, 0x00, 0x00, 0x00, // string 1: empty
		0x05, 0x00, 0x01, 0x00, // string 2: len=5, ref=1
		0x04, 0x00, 0x01, 0x00, // string 3: len=4, ref=1
	}
	dataBytes := []byte("helloworld")

	streams := map[string][]byte{
		"_StringPool": poolData,
		"_StringData": dataBytes,
	}

	pool, is3Byte, err := readMSIStringPoolFromStreams(streams)
	if err != nil {
		t.Fatalf("readMSIStringPoolFromStreams failed: %v", err)
	}
	if !is3Byte {
		t.Error("is3Byte = false, want true")
	}
	// strings: 0="", 1="", 2="hello", 3="worl"
	if len(pool) != 4 {
		t.Fatalf("len(pool) = %d, want 4", len(pool))
	}
	if pool[1] != "" {
		t.Errorf("pool[1] = %q, want empty string", pool[1])
	}
	if pool[2] != "hello" {
		t.Errorf("pool[2] = %q, want \"hello\"", pool[2])
	}
	if pool[3] != "worl" {
		t.Errorf("pool[3] = %q, want \"worl\"", pool[3])
	}
}
