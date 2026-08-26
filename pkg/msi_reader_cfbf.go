//go:build !windows && !libmsi

package pkg

import (
	"github.com/lwalthert/intunewin/internal/data"
)

// msiReader reads MSI metadata using the CFBF reader on platforms without
// Windows Installer or the libmsi C library.
type msiReader struct {
	path string
}

func (m *msiReader) Path() string { return m.path }

func (m *msiReader) Read() (*data.MSIProperties, error) {
	reader := &cfbfMSIReader{path: m.path}
	return reader.Read()
}
