package pkg

import (
	"errors"
	"io"
)

func copyInChunks(r io.Reader, out io.Writer) (int, error) {
	var written int // counts the bytes written to the writer
	buf := make([]byte, 0, 2097152)
	for {
		n, err := io.ReadFull(r, buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break // Reached end of file
			}
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				return n, err // Return the error to the caller
			}
		}
		n, err = out.Write(buf[:n])
		written += n
		if err != nil {
			return n, err // Return the error to the caller
		}
	}
	return written, nil
}