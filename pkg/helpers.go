package pkg

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

func copyInChunks(r io.Reader, out io.Writer) (int64, error) {
	var written, read int64 // counts the bytes written to the writer
	buf := make([]byte, 0, 2097152)
	for {
		n, err := io.ReadFull(r, buf)
		read += int64(n)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break // Reached end of file
			}
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				return read, err // Return the error to the caller
			}
		}
		n, err = out.Write(buf[:n])
		written += int64(n)
		if err != nil {
			return written, err // Return the error to the caller
		}
	}
	return written, nil
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
