//go:build windows

package pkg

import (
	"fmt"
	"strings"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/lwalthert/intunewin/internal/data"
)

// msiReader reads MSI metadata through the Windows Installer automation API,
// mirroring how the official Win32 Content Prep Tool populates the MsiInfo
// section of Detection.xml.
type msiReader struct {
	path string
}

func (m *msiReader) Path() string { return m.path }

// Read opens the MSI database at Path and collects the properties and table
// rows needed to build data.MSIProperties.
func (m *msiReader) Read() (*data.MSIProperties, error) {
	if err := ole.CoInitialize(0); err != nil {
		return nil, fmt.Errorf("failed to initialize COM: %w", err)
	}
	defer ole.CoUninitialize()

	installer, err := oleutil.CreateObject("WindowsInstaller.Installer")
	if err != nil {
		return nil, fmt.Errorf("failed to create WindowsInstaller.Installer: %w", err)
	}
	defer installer.Release()

	idispatch, err := installer.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, fmt.Errorf("failed to query IDispatch: %w", err)
	}
	defer idispatch.Release()

	// Open the database in read-only mode.
	dbVar, err := idispatch.CallMethod("OpenDatabase", m.path, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open msi database %s: %w", m.path, err)
	}
	db := dbVar.ToIDispatch()
	if db == nil {
		return nil, fmt.Errorf("OpenDatabase returned no IDispatch for %s", m.path)
	}
	defer db.Release()
	dbVar.Clear()

	props := &data.MSIProperties{
		Summary:    map[string]string{},
		Properties: map[string]string{},
	}

	if err := readSummary(db, props.Summary); err != nil {
		return nil, err
	}
	if err := readTableStrings(db, "SELECT Key, Value FROM Property", props.Properties); err != nil {
		return nil, err
	}

	database := &data.Database{
		Registry:    map[string]string{},
		Filesystems: map[string]string{},
		Components:  map[string]string{},
		Directories: map[string]string{},
	}
	if err := readTables(db, database); err != nil {
		return nil, err
	}
	props.Database = database

	return props, nil
}

// readSummary populates summary with the standard summary information stream
// properties (identified by PID) that the MSI metadata relies on.
func readSummary(db *ole.IDispatch, summary map[string]string) error {
	siVar, err := db.CallMethod("SummaryInformation", 0)
	if err != nil {
		return fmt.Errorf("failed to open summary information: %w", err)
	}
	defer siVar.Clear()

	si := siVar.ToIDispatch()
	if si == nil {
		return fmt.Errorf("summary information returned no IDispatch")
	}
	defer si.Release()

	// PID 9 combines the installer version and the package code, PID 12 is the
	// package code alone on MSI 4.0+.
	pids := []struct {
		id   int
		name string
	}{
		{9, "Revision Number"},
		{12, "Package Code"},
	}

	for _, p := range pids {
		prop, err := si.GetProperty("Property", p.id)
		if err != nil {
			continue // Malformed summary entries are common and harmless.
		}
		if s := valueToString(prop); s != "" {
			summary[p.name] = s
		}
		prop.Clear()
	}

	return nil
}

// readTableStrings runs a SELECT whose first column is the key and second
// column is the value, storing every row into out.
func readTableStrings(db *ole.IDispatch, query string, out map[string]string) error {
	view, err := openView(db, query)
	if err != nil {
		return err
	}
	defer view.Release()

	for {
		record, err := fetchRow(view)
		if err != nil {
			return err
		}
		if record == nil {
			return nil
		}
		key, err := columnString(record, 1)
		if err != nil {
			record.Clear()
			return err
		}
		value, err := columnString(record, 2)
		record.Clear()
		if err != nil {
			return err
		}
		out[key] = value
	}
}

// readTables fills database from the tables that map to the boolean MSI
// metadata fields.
func readTables(db *ole.IDispatch, database *data.Database) error {
	if err := readSingleColumn(db, "SELECT Name FROM ServiceInstall", &database.Services); err != nil {
		return err
	}
	if err := readSingleColumn(db, "SELECT Name FROM ODBCDataSource", &database.ODBCDataSources); err != nil {
		return err
	}
	if err := readKeyValue(db, "SELECT Registry, Root FROM Registry", database.Registry, parseRegistryRoot); err != nil {
		return err
	}
	if err := readKeyValue(db, "SELECT FileName, Component_ FROM File", database.Filesystems, identity); err != nil {
		return err
	}
	if err := readKeyValue(db, "SELECT Component, Directory_ FROM Component", database.Components, identity); err != nil {
		return err
	}
	if err := readKeyValue(db, "SELECT Directory, Directory_Parent FROM Directory", database.Directories, identity); err != nil {
		return err
	}
	return nil
}

// readSingleColumn fills out with the first column of every row in the view.
func readSingleColumn(db *ole.IDispatch, query string, out *[]string) error {
	view, err := openView(db, query)
	if err != nil {
		return err
	}
	defer view.Release()

	for {
		record, err := fetchRow(view)
		if err != nil {
			return err
		}
		if record == nil {
			return nil
		}
		value, err := columnString(record, 1)
		record.Clear()
		if err != nil {
			return err
		}
		if value != "" {
			*out = append(*out, value)
		}
	}
}

// readKeyValue runs a two-column view storing column1 -> convert(column2).
func readKeyValue(db *ole.IDispatch, query string, out map[string]string, convert func(string) string) error {
	view, err := openView(db, query)
	if err != nil {
		return err
	}
	defer view.Release()

	for {
		record, err := fetchRow(view)
		if err != nil {
			return err
		}
		if record == nil {
			return nil
		}
		key, err := columnString(record, 1)
		if err != nil {
			record.Clear()
			return err
		}
		value, err := columnString(record, 2)
		record.Clear()
		if err != nil {
			return err
		}
		out[key] = convert(value)
	}
}

// openView opens the given SQL query on the database and executes it.
func openView(db *ole.IDispatch, query string) (*ole.IDispatch, error) {
	v, err := db.CallMethod("OpenView", query)
	if err != nil {
		return nil, fmt.Errorf("OpenView %q: %w", query, err)
	}
	disp := v.ToIDispatch()
	if disp == nil {
		v.Clear()
		return nil, fmt.Errorf("OpenView %q returned no IDispatch", query)
	}
	v.Clear()
	if _, err := disp.CallMethod("Execute"); err != nil {
		disp.Release()
		return nil, fmt.Errorf("Execute %q: %w", query, err)
	}
	return disp, nil
}

// fetchRow fetches the next record of an executed view, or nil when exhausted.
func fetchRow(view *ole.IDispatch) (*ole.VARIANT, error) {
	record, err := view.CallMethod("Fetch")
	if err != nil {
		return nil, err
	}
	// A Fetch with no more rows returns a record without any fields.
	if record == nil || record.ToArray() == nil {
		record.Clear()
		return nil, nil
	}
	return record, nil
}

// columnString extracts column (1-based) as a string from a record.
func columnString(record *ole.VARIANT, col int) (string, error) {
	prop, err := record.ToIDispatch().GetProperty("StringData", col)
	if err != nil {
		return "", err
	}
	defer prop.Clear()
	return valueToString(prop), nil
}

// parseRegistryRoot normalizes a Registry.Root column value, mapping the
// HKEY_LOCAL_MACHINE variants to "2".
func parseRegistryRoot(v string) string {
	s := strings.TrimSpace(v)
	switch s {
	case "2", "-2", "#2", "#-2":
		return "2"
	}
	return s
}

// identity returns its argument unchanged.
func identity(v string) string { return v }

// valueToString converts a VARIANT to a Go string.
func valueToString(v *ole.VARIANT) string {
	if v == nil {
		return ""
	}
	switch t := v.Value().(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
