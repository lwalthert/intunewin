package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
	hash.Write(iv)
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

	_, err := copyInChunks(r, mac)
	if err != nil {
		return false, err
	}

	expectedMAC := mac.Sum(nil)

	return hmac.Equal(expectedMAC, suppliedMAC), nil
}

func sha256FileHash(input *os.File) (string, error) {
	// Go to the beginning of the file
	_, err := input.Seek(0, 0)
	if err != nil {
		return "", err
	}

	hash := sha256.New()

	buf := make([]byte, 0, 2097152)
	for {
		n, err := io.ReadFull(input, buf[:cap(buf)])
		buf = buf[:n]
		if err != nil {
			if err == io.EOF {
				break // Reached end of file
			}
			if err != io.ErrUnexpectedEOF {
				fmt.Fprintln(os.Stderr, err)
				break
			}
		}

		_, err = hash.Write(buf)
		if err != nil {
			return "", err
		}
	}

	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}
