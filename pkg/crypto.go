package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"
	"os"
)

type AESCBCEncrypter struct {
	Block     cipher.Block
	BlockMode cipher.BlockMode
	hash      hash.Hash
	writer    io.Writer
}

func NewAESCBCEncrypter(w io.Writer, h func() hash.Hash, iv, aesKey, macKey []byte) (*AESCBCEncrypter, error) {
	// Create the hmac hash function
	hash := hmac.New(h, macKey)

	// Create a new aes block cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCEncrypter(block, iv)

	// The IV is always written to the start of the file and has to be passed to the hash function as well.
	_, err = w.Write(iv)
	if err != nil {
		return nil, err
	}
	_, err = hash.Write(iv)
	if err != nil {
		return nil, err
	}

	return &AESCBCEncrypter{
		Block:     block,
		BlockMode: blockMode,
		hash:      hash,
		writer:    w,
	}, nil
}

func (bw AESCBCEncrypter) Write(b []byte) (int, error) {
	bw.BlockMode.CryptBlocks(b, b)

	n, err := bw.writer.Write(b)
	if err != nil {
		return n, err
	}
	_, err = bw.hash.Write(b)
	if err != nil {
		return n, err
	}

	return n, nil
}

func (bw AESCBCEncrypter) Sum(b []byte) []byte {
	return bw.hash.Sum(b)
}

type AESCBCDecrypter struct {
	Block     cipher.Block
	BlockMode cipher.BlockMode
	writer    io.Writer
}

func NewAESCBCDecrypter(w io.Writer, iv, aesKey []byte) (*AESCBCDecrypter, error) {
	// Create a new aes block cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)

	return &AESCBCDecrypter{
		Block:     block,
		BlockMode: blockMode,
		writer:    w,
	}, nil
}

func (bw AESCBCDecrypter) Write(b []byte) (int, error) {
	bw.BlockMode.CryptBlocks(b, b)

	n, err := bw.writer.Write(b)
	if err != nil {
		return n, err
	}

	return n, nil
}

// ValidateMAC validates check if the HMAC generated with the data read through r matches the hash passed to the function.
// If they match it returns (true, nil) otherwise it returns (false, nil)
func ValidateHMAC(r io.Reader, h func() hash.Hash, key, suppliedMAC []byte) (bool, error) {
	mac := hmac.New(h, key)

	_, err := io.Copy(mac, r)
	if err != nil {
		return false, err
	}

	expectedMAC := mac.Sum(nil)

	return hmac.Equal(expectedMAC, suppliedMAC), nil
}

func sha256FileHash(input *os.File) (string, error) {
	_, err := input.Seek(0, io.SeekStart)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	_, err = io.Copy(hash, input)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

func decodeBase64Key(input string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func generateKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}
