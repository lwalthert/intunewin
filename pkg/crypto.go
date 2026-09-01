package pkg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"hash"
	"io"
	"os"
)

var ErrInvalidPadding = errors.New("invalid PKCS#7 padding")

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, ErrInvalidPadding
	}
	padLen := int(data[length-1])
	if padLen == 0 || padLen > blockSize || padLen > length {
		return nil, ErrInvalidPadding
	}
	for i := length - padLen; i < length; i++ {
		if data[i] != byte(padLen) {
			return nil, ErrInvalidPadding
		}
	}
	return data[:length-padLen], nil
}

type AESCBCEncrypter struct {
	block     cipher.Block
	blockMode cipher.BlockMode
	hash      hash.Hash
	writer    io.Writer
	buffer    []byte
	closed    bool
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
	if _, err := w.Write(iv); err != nil {
		return nil, err
	}
	if _, err := hash.Write(iv); err != nil {
		return nil, err
	}

	return &AESCBCEncrypter{
		block:     block,
		blockMode: blockMode,
		hash:      hash,
		writer:    w,
	}, nil
}

func (enc *AESCBCEncrypter) Write(p []byte) (int, error) {
	if enc.closed {
		return 0, errors.New("write to closed encrypter")
	}
	enc.buffer = append(enc.buffer, p...)
	blockSize := enc.block.BlockSize()

	nBlocks := len(enc.buffer) / blockSize
	if nBlocks > 0 {
		processed := nBlocks * blockSize
		toEncrypt := enc.buffer[:processed]
		enc.blockMode.CryptBlocks(toEncrypt, toEncrypt)
		if _, err := enc.writer.Write(toEncrypt); err != nil {
			return 0, err
		}
		if _, err := enc.hash.Write(toEncrypt); err != nil {
			return 0, err
		}
		rem := copy(enc.buffer, enc.buffer[processed:])
		enc.buffer = enc.buffer[:rem]
	}

	return len(p), nil
}

func (enc *AESCBCEncrypter) Close() error {
	if enc.closed {
		return nil
	}
	enc.closed = true

	padded := pkcs7Pad(enc.buffer, enc.block.BlockSize())
	enc.blockMode.CryptBlocks(padded, padded)
	if _, err := enc.writer.Write(padded); err != nil {
		return err
	}
	if _, err := enc.hash.Write(padded); err != nil {
		return err
	}
	enc.buffer = nil
	return nil
}

func (enc *AESCBCEncrypter) Sum(b []byte) []byte {
	return enc.hash.Sum(b)
}

type AESCBCDecrypter struct {
	block     cipher.Block
	blockMode cipher.BlockMode
	writer    io.Writer
	buffer    []byte
	closed    bool
}

func NewAESCBCDecrypter(w io.Writer, iv, aesKey []byte) (*AESCBCDecrypter, error) {
	// Create a new aes block cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)

	return &AESCBCDecrypter{
		block:     block,
		blockMode: blockMode,
		writer:    w,
	}, nil
}

func (dec *AESCBCDecrypter) Write(p []byte) (int, error) {
	if dec.closed {
		return 0, errors.New("write to closed decrypter")
	}
	dec.buffer = append(dec.buffer, p...)
	blockSize := dec.block.BlockSize()

	// Keep at least one block in the buffer for unpadding during Close()
	if len(dec.buffer) > blockSize {
		nBlocks := (len(dec.buffer) - 1) / blockSize
		processed := nBlocks * blockSize
		toDecrypt := dec.buffer[:processed]
		dec.blockMode.CryptBlocks(toDecrypt, toDecrypt)
		if _, err := dec.writer.Write(toDecrypt); err != nil {
			return 0, err
		}
		rem := copy(dec.buffer, dec.buffer[processed:])
		dec.buffer = dec.buffer[:rem]
	}

	return len(p), nil
}

func (dec *AESCBCDecrypter) Close() error {
	if dec.closed {
		return nil
	}
	dec.closed = true

	if len(dec.buffer) == 0 {
		return errors.New("unexpected end of data: missing final block")
	}
	if len(dec.buffer)%dec.block.BlockSize() != 0 {
		return errors.New("data is not block-aligned")
	}

	dec.blockMode.CryptBlocks(dec.buffer, dec.buffer)
	unpadded, err := pkcs7Unpad(dec.buffer, dec.block.BlockSize())
	if err != nil {
		return err
	}
	if _, err := dec.writer.Write(unpadded); err != nil {
		return err
	}
	dec.buffer = nil
	return nil
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
