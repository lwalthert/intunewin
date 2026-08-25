//go:build libmsi

package pkg

/*
#cgo pkg-config: libmsi-1.0
#include <libmsi.h>
#include <stdlib.h>
#include <unistd.h>
*/
import "C"

import (
	"fmt"
	"io"
	"os"
	"unsafe"

	"github.com/lwalthert/intunewin/internal/data"
)

// msiReader reads MSI metadata by linking directly against the msitools libmsi
// C library. It is selected with the "libmsi" build tag and requires the
// libmsi development headers and library to be available at build time.
type msiReader struct {
	path string
}

func (m *msiReader) Path() string { return m.path }

// Read collects the MSI properties and table rows needed to build
// data.MSIProperties by querying the MSI database through libmsi.
func (m *msiReader) Read() (*data.MSIProperties, error) {
	db, err := m.openDatabase()
	if err != nil {
		return nil, err
	}
	defer C.g_object_unref(C.gpointer(db))

	props := &data.MSIProperties{
		Summary:    map[string]string{},
		Properties: map[string]string{},
	}

	// PackageCode lives in the summary information stream (PID 9).
	if code, err := m.summaryInfo(db); err != nil {
		return nil, err
	} else if code != "" {
		props.Summary["Package Code"] = code
	}

	// The Property table holds ProductCode, ProductVersion, UpgradeCode,
	// Manufacturer and the install-context properties.
	propTable, err := m.exportTable(db, "Property")
	if err != nil {
		return nil, err
	}
	for _, row := range propTable.rows {
		if len(row) >= 2 {
			props.Properties[row[0]] = row[1]
		}
	}

	database := &data.Database{
		Registry:    map[string]string{},
		Filesystems: map[string]string{},
		Components:  map[string]string{},
		Directories: map[string]string{},
	}

	if err := m.readTables(db, database); err != nil {
		return nil, err
	}
	props.Database = database

	return props, nil
}

// openDatabase opens the MSI database in read-only mode.
func (m *msiReader) openDatabase() (*C.LibmsiDatabase, error) {
	cpath := C.CString(m.path)
	defer C.free(unsafe.Pointer(cpath))

	var cerr *C.GError
	db := C.libmsi_database_new(cpath, C.LIBMSI_DB_FLAGS_READONLY, nil, &cerr)
	if db == nil {
		return nil, cgoError("open database", cerr)
	}
	return db, nil
}

// summaryInfo returns the package code from the summary information stream, or
// an empty string if it cannot be determined.
func (m *msiReader) summaryInfo(db *C.LibmsiDatabase) (string, error) {
	var cerr *C.GError
	si := C.libmsi_summary_info_new(db, 0, &cerr)
	if si == nil {
		return "", cgoError("open summary information", cerr)
	}
	defer C.g_object_unref(C.gpointer(si))

	// LIBMSI_PROPERTY_UUID (PID 9) holds the package code.
	str := C.libmsi_summary_info_get_string(si, C.LIBMSI_PROPERTY_UUID, &cerr)
	if str == nil {
		return "", cgoError("read summary information", cerr)
	}
	return C.GoString(str), nil
}

// exportTable exports the named table to a pipe and parses the tab-separated
// output into column names and data rows.
func (m *msiReader) exportTable(db *C.LibmsiDatabase, table string) (*msiTable, error) {
	readFD, writeFD, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer readFD.Close()

	ctable := C.CString(table)
	defer C.free(unsafe.Pointer(ctable))

	var cerr *C.GError
	ok := C.libmsi_database_export(db, ctable, C.int(writeFD.Fd()), &cerr)
	writeFD.Close()
	if ok == 0 {
		return nil, cgoError("export table "+table, cerr)
	}

	data, err := io.ReadAll(readFD)
	if err != nil {
		return nil, err
	}
	return parseExportTable(data, table)
}

// readTables fills database from the tables that map to the boolean MSI
// metadata fields.
func (m *msiReader) readTables(db *C.LibmsiDatabase, database *data.Database) error {
	if t, err := m.exportTable(db, "ServiceInstall"); err == nil {
		database.Services = t.rowsByColumn("Name")
	}
	if t, err := m.exportTable(db, "ODBCDataSource"); err == nil {
		database.ODBCDataSources = t.rowsByColumn("Name")
	}
	if t, err := m.exportTable(db, "Registry"); err == nil {
		database.Registry = t.keyValue("Registry", "Root")
	}
	if t, err := m.exportTable(db, "File"); err == nil {
		database.Filesystems = t.keyValue("FileName", "Component_")
	}
	if t, err := m.exportTable(db, "Component"); err == nil {
		database.Components = t.keyValue("Component", "Directory_")
	}
	if t, err := m.exportTable(db, "Directory"); err == nil {
		database.Directories = t.keyValue("Directory", "Directory_Parent")
	}
	return nil
}

// cgoError converts a GError into a Go error, freeing the GError.
func cgoError(what string, cerr *C.GError) error {
	if cerr == nil {
		return fmt.Errorf("%s: unknown error", what)
	}
	msg := C.GoString(cerr.message)
	C.g_error_free(cerr)
	return fmt.Errorf("%s: %s", what, msg)
}
