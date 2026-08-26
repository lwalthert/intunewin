package pkg

import (
	"github.com/lwalthert/intunewin/internal/data"
)

// MSIReader reads the metadata of an MSI file so it can populate the MsiInfo
// section of Detection.xml. On Windows, it can use the Windows Installer automation
// API; on Linux and macOS, it uses the built-in CFBF reader (or libmsi if
// built with the libmsi tag).
type MSIReader interface {
	// Path is the location of the MSI file to inspect.
	Path() string
	// Read returns the raw MSI properties needed to fill the MsiInfo metadata.
	Read() (*data.MSIProperties, error)
}

// OpenMSI returns an MSIReader for the MSI file at path. It does not verify
// that the file exists or that it is a valid MSI; that happens on Read(). It is
// a variable so tests can substitute a fake reader.
var OpenMSI = func(path string) (MSIReader, error) {
	return &msiReader{path: path}, nil
}
