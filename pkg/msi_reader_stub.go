//go:build !windows

package pkg

import (
	"errors"

	"github.com/lwalthert/intunewin/internal/data"
)

// msiReader is the placeholder used on platforms without Windows Installer. It
// always fails so the rest of the tool keeps building and running while MSI
// metadata stays empty on platforms that cannot read MSI files.
type msiReader struct {
	path string
}

func (m *msiReader) Path() string { return m.path }

func (m *msiReader) Read() (*data.MSIProperties, error) {
	return nil, errors.New("reading msi metadata is only supported on windows")
}
