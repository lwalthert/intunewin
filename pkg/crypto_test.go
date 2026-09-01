package pkg

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"
	"testing"
)

func TestCrypto_EncryptDecrypt(t *testing.T) {
	testSizes := []int{0, 1, 15, 16, 17, 31, 32, 33, 100, 1024, 65536}

	for _, size := range testSizes {
		t.Run(string(rune(size)), func(t *testing.T) {
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

			plaintext := bytes.Repeat([]byte("A"), size)

			var encryptedBuf bytes.Buffer
			enc, err := NewAESCBCEncrypter(&encryptedBuf, sha256.New, iv, aesKey, macKey)
			if err != nil {
				t.Fatalf("NewAESCBCEncrypter error = %v", err)
			}

			// Write in small chunks to test streaming buffering
			chunkSize := 7
			for i := 0; i < len(plaintext); i += chunkSize {
				end := i + chunkSize
				if end > len(plaintext) {
					end = len(plaintext)
				}
				n, err := enc.Write(plaintext[i:end])
				if err != nil {
					t.Fatalf("enc.Write() error = %v", err)
				}
				if n != end-i {
					t.Fatalf("enc.Write() wrote %d bytes, want %d", n, end-i)
				}
			}

			if err := enc.Close(); err != nil {
				t.Fatalf("enc.Close() error = %v", err)
			}

			mac := enc.Sum(nil)
			if len(mac) != 32 {
				t.Fatalf("enc.Sum() returned %d bytes, want 32", len(mac))
			}

			// Encrypted buffer has IV (16 bytes) + padded ciphertext
			ciphertextWithIV := encryptedBuf.Bytes()
			expectedPad := 16 - (size % 16)
			expectedCipherLen := size + expectedPad
			if len(ciphertextWithIV) != 16+expectedCipherLen {
				t.Fatalf("encrypted buffer length = %d, want %d", len(ciphertextWithIV), 16+expectedCipherLen)
			}

			// Decrypt
			var decryptedBuf bytes.Buffer
			dec, err := NewAESCBCDecrypter(&decryptedBuf, iv, aesKey)
			if err != nil {
				t.Fatalf("NewAESCBCDecrypter error = %v", err)
			}

			// Pass only ciphertext (skip IV)
			ciphertextOnly := ciphertextWithIV[16:]
			// Feed in irregular chunk sizes
			for i := 0; i < len(ciphertextOnly); i += 11 {
				end := i + 11
				if end > len(ciphertextOnly) {
					end = len(ciphertextOnly)
				}
				n, err := dec.Write(ciphertextOnly[i:end])
				if err != nil {
					t.Fatalf("dec.Write() error = %v", err)
				}
				if n != end-i {
					t.Fatalf("dec.Write() wrote %d bytes, want %d", n, end-i)
				}
			}

			if err := dec.Close(); err != nil {
				t.Fatalf("dec.Close() error = %v", err)
			}

			if !bytes.Equal(decryptedBuf.Bytes(), plaintext) {
				t.Fatalf("decrypted text mismatch for size %d", size)
			}
		})
	}
}

func TestPKCS7Padding(t *testing.T) {
	blockSize := 16

	// Test padding lengths
	for l := 0; l <= 32; l++ {
		data := make([]byte, l)
		padded := pkcs7Pad(data, blockSize)
		if len(padded)%blockSize != 0 {
			t.Fatalf("padded length %d is not a multiple of %d", len(padded), blockSize)
		}
		expectedPadLen := blockSize - (l % blockSize)
		if len(padded) != l+expectedPadLen {
			t.Fatalf("padded length = %d, want %d", len(padded), l+expectedPadLen)
		}

		unpadded, err := pkcs7Unpad(padded, blockSize)
		if err != nil {
			t.Fatalf("pkcs7Unpad error = %v", err)
		}
		if !bytes.Equal(unpadded, data) {
			t.Fatalf("unpadded data mismatch")
		}
	}

	// Invalid padding test cases
	invalidCases := [][]byte{
		{},        // empty
		{1, 2, 3}, // not block-aligned
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},    // padLen 0
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17},   // padLen > blockSize
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 2}, // mismatched padding bytes
	}
	for i, c := range invalidCases {
		if _, err := pkcs7Unpad(c, blockSize); err == nil {
			t.Errorf("pkcs7Unpad case %d: expected error, got nil", i)
		}
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

func BenchmarkAESCBCEncrypter(b *testing.B) {
	iv := make([]byte, 16)
	aesKey := make([]byte, 32)
	macKey := make([]byte, 32)
	chunk := make([]byte, 32*1024)

	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		enc, err := NewAESCBCEncrypter(io.Discard, sha256.New, iv, aesKey, macKey)
		if err != nil {
			b.Fatal(err)
		}
		for j := 0; j < 10; j++ {
			if _, err := enc.Write(chunk); err != nil {
				b.Fatal(err)
			}
		}
		if err := enc.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAESCBCDecrypter(b *testing.B) {
	iv := make([]byte, 16)
	aesKey := make([]byte, 32)
	macKey := make([]byte, 32)
	chunk := make([]byte, 32*1024)

	var encBuf bytes.Buffer
	enc, err := NewAESCBCEncrypter(&encBuf, sha256.New, iv, aesKey, macKey)
	if err != nil {
		b.Fatal(err)
	}
	for j := 0; j < 10; j++ {
		if _, err := enc.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	if err := enc.Close(); err != nil {
		b.Fatal(err)
	}
	ciphertext := encBuf.Bytes()[16:] // skip IV

	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		dec, err := NewAESCBCDecrypter(io.Discard, iv, aesKey)
		if err != nil {
			b.Fatal(err)
		}
		for offset := 0; offset < len(ciphertext); offset += len(chunk) {
			end := offset + len(chunk)
			if end > len(ciphertext) {
				end = len(ciphertext)
			}
			if _, err := dec.Write(ciphertext[offset:end]); err != nil {
				b.Fatal(err)
			}
		}
		if err := dec.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
