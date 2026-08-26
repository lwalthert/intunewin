package pkg

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	lengths := []int{16, 32, 64}
	for _, l := range lengths {
		key, err := generateKey(l)
		if err != nil {
			t.Fatalf("generateKey(%d) error = %v", l, err)
		}
		if len(key) != l {
			t.Errorf("generateKey(%d) returned %d bytes, want %d", l, len(key), l)
		}
	}
}

func TestDecodeBase64Key(t *testing.T) {
	raw := []byte("secret-key-1234")
	encoded := base64.StdEncoding.EncodeToString(raw)

	decoded, err := decodeBase64Key(encoded)
	if err != nil {
		t.Fatalf("decodeBase64Key() error = %v", err)
	}
	if string(decoded) != string(raw) {
		t.Errorf("decodeBase64Key() = %q, want %q", decoded, raw)
	}

	if _, err := decodeBase64Key("not-valid-base64!!!"); err == nil {
		t.Error("decodeBase64Key() error = nil for invalid base64, want error")
	}
}
