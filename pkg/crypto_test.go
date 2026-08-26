package pkg

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"
)

func TestCrypto_EncryptDecrypt(t *testing.T) {
	iv, err := generateKey(16)
	if err != nil {
		t.Fatalf("generateKey(16) error = %v", err)
	}
	aesKey, err := generateKey(32)
	if err != nil {
		t.Fatalf("generateKey(32) error = %v", err)
	}
	macKey, err := generateKey(32)
	if err != nil {
		t.Fatalf("generateKey(32) error = %v", err)
	}

	var encryptedBuf bytes.Buffer
	enc, err := NewAESCBCEncrypter(&encryptedBuf, sha256.New, iv, aesKey, macKey)
	if err != nil {
		t.Fatalf("NewAESCBCEncrypter error = %v", err)
	}

	plaintext := []byte("this is a block of test data 1234") // 33 bytes, needs padding to 48
	blockSize := enc.Block.BlockSize()
	padding := blockSize - (len(plaintext) % blockSize)
	padded := append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)

	n, err := enc.Write(padded)
	if err != nil {
		t.Fatalf("enc.Write() error = %v", err)
	}
	if n != len(padded) {
		t.Fatalf("enc.Write() wrote %d bytes, want %d", n, len(padded))
	}

	mac := enc.Sum(nil)
	if len(mac) != 32 {
		t.Fatalf("enc.Sum() returned %d bytes, want 32", len(mac))
	}

	// Encrypted buffer has IV (16 bytes) + ciphertext (48 bytes)
	ciphertextWithIV := encryptedBuf.Bytes()
	if len(ciphertextWithIV) != 16+len(padded) {
		t.Fatalf("encrypted buffer length = %d, want %d", len(ciphertextWithIV), 16+len(padded))
	}

	// Decrypt
	var decryptedBuf bytes.Buffer
	dec, err := NewAESCBCDecrypter(&decryptedBuf, iv, aesKey)
	if err != nil {
		t.Fatalf("NewAESCBCDecrypter error = %v", err)
	}

	// Pass only ciphertext (skip IV)
	ciphertextOnly := ciphertextWithIV[16:]
	n, err = dec.Write(ciphertextOnly)
	if err != nil {
		t.Fatalf("dec.Write() error = %v", err)
	}
	if n != len(ciphertextOnly) {
		t.Fatalf("dec.Write() wrote %d bytes, want %d", n, len(ciphertextOnly))
	}

	decryptedPadded := decryptedBuf.Bytes()
	unpadded := decryptedPadded[:len(decryptedPadded)-padding]
	if !bytes.Equal(unpadded, plaintext) {
		t.Fatalf("decrypted text = %q, want %q", unpadded, plaintext)
	}
}

func TestValidateHMAC(t *testing.T) {
	key := []byte("secret-key-for-hmac")
	data := []byte("payload to be validated")

	macHash := hmac.New(sha256.New, key)
	macHash.Write(data)
	mac := macHash.Sum(nil)

	ok, err := ValidateHMAC(bytes.NewReader(data), sha256.New, key, mac)
	if err != nil {
		t.Fatalf("ValidateHMAC() error = %v", err)
	}
	if !ok {
		t.Error("ValidateHMAC() = false, want true for valid MAC")
	}

	// Tampered MAC
	tamperedMAC := append([]byte(nil), mac...)
	tamperedMAC[0] ^= 0xFF
	ok, err = ValidateHMAC(bytes.NewReader(data), sha256.New, key, tamperedMAC)
	if err != nil {
		t.Fatalf("ValidateHMAC() error = %v", err)
	}
	if ok {
		t.Error("ValidateHMAC() = true, want false for tampered MAC")
	}
}

func TestSha256FileHash(t *testing.T) {
	f, err := os.CreateTemp("", "hash-test*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if _, err := f.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}

	hash, err := sha256FileHash(f)
	if err != nil {
		t.Fatalf("sha256FileHash() error = %v", err)
	}

	// base64(sha256("hello world")) = "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
	expected := "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
	if hash != expected {
		t.Errorf("sha256FileHash() = %q, want %q", hash, expected)
	}
}

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
