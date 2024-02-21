package main

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

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

func writeFileToZIP(file *os.File, w io.Writer) (int, error) {
	// Write the file to the ZIP archive
	var bytesWritten int
	buf := make([]byte, 0, 2097152)
	for {
		n, err := io.ReadFull(file, buf[:cap(buf)])
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
		n, err = w.Write(buf[:n])
		if err != nil {
			return bytesWritten, err
		}
		bytesWritten += n
	}
	// log.Printf("%d", bytesWritten)
	return bytesWritten, nil
}

func buildZipReader(fileName string) (*zip.ReadCloser, func(), error) {
	// Open the intunewin archive for reading.
	r, err := zip.OpenReader(fileName)
	if err != nil {
		return nil, nil, err
	}

	closer := func() {
		r.Close()
	}

	return r, closer, nil
}

type AESCBCWriter struct {
	buf   []byte
	block cipher.BlockMode
	out   io.Writer
}

func NewAESCBCWriter(writer io.Writer, key, iv []byte) (*AESCBCWriter, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCEncrypter(b, iv)

	return &AESCBCWriter{
		block: blockMode,
		out:   writer,
	}, nil
}

func (b *AESCBCWriter) Write(p []byte) (n int, err error) {
	toWrite := len(p)
	mul := toWrite / b.block.BlockSize()
	size := mul * b.block.BlockSize()
	if cap(b.buf) != size {
		b.buf = make([]byte, toWrite)
	}

	b.block.CryptBlocks(b.buf, p[:toWrite])

	write, err := b.out.Write(b.buf)
	if err != nil {
		return 0, err
	}

	if write < b.block.BlockSize() {
		return 0, io.ErrUnexpectedEOF
	}

	return write, nil
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
