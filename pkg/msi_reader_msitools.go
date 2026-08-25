//go:build msitools

package pkg

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/lwalthert/intunewin/internal/data"
)

// msiReader reads MSI metadata by shelling out to the msitools "msiinfo"
// command, which is available on Linux and macOS. It is selected with the
// "msitools" build tag.
type msiReader struct {
	path string
}

func (m *msiReader) Path() string { return m.path }

// Read collects the MSI properties and table rows needed to build
// data.MSIProperties by invoking msiinfo.
func (m *msiReader) Read() (*data.MSIProperties, error) {
	props := &data.MSIProperties{
		Summary:    map[string]string{},
		Properties: map[string]string{},
	}

	// PackageCode lives in the summary information stream (PID 9).
	code, err := m.summaryInfo()
	if err != nil {
		return nil, err
	}
	if code != "" {
		props.Summary["Package Code"] = code
	}

	// The Property table holds ProductCode, ProductVersion, UpgradeCode,
	// Manufacturer and the install-context properties.
	propTable, err := m.exportTable("Property")
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

	if err := m.readTables(database); err != nil {
		return nil, err
	}
	props.Database = database

	return props, nil
}

// summaryInfo returns the package code from the summary information stream, or
// an empty string if it cannot be determined.
func (m *msiReader) summaryInfo() (string, error) {
	out, err := m.run("suminfo", m.path)
	if err != nil {
		return "", fmt.Errorf("msiinfo suminfo: %w", err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		// e.g. "Revision number (UUID): {GUID}"
		if strings.HasPrefix(line, "Revision number") {
			_, after, ok := strings.Cut(line, ":")
			if !ok {
				return "", nil
			}
			return strings.TrimSpace(after), nil
		}
	}
	return "", nil
}

// exportTable runs "msiinfo export FILE TABLE" and parses the tab-separated
// output into column names and data rows.
func (m *msiReader) exportTable(table string) (*msiTable, error) {
	out, err := m.run("export", m.path, table)
	if err != nil {
		return nil, fmt.Errorf("msiinfo export %s: %w", table, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))

	// The msitools export format has three header lines before the data rows:
	// row 1 column names, row 2 column types, row 3 table name + primary keys.
	if !scanner.Scan() {
		return nil, fmt.Errorf("msiinfo export %s: empty output", table)
	}
	columns := strings.Split(scanner.Text(), "\t")
	// Skip the column types and table-name/primary-key header rows.
	scanner.Scan()
	scanner.Scan()

	t := &msiTable{columns: columns}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		t.rows = append(t.rows, strings.Split(line, "\t"))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return t, nil
}

// readTables fills database from the tables that map to the boolean MSI
// metadata fields.
func (m *msiReader) readTables(database *data.Database) error {
	if t, err := m.exportTable("ServiceInstall"); err == nil {
		database.Services = t.rowsByColumn("Name")
	}
	if t, err := m.exportTable("ODBCDataSource"); err == nil {
		database.ODBCDataSources = t.rowsByColumn("Name")
	}
	if t, err := m.exportTable("Registry"); err == nil {
		database.Registry = t.keyValue("Registry", "Root")
	}
	if t, err := m.exportTable("File"); err == nil {
		database.Filesystems = t.keyValue("FileName", "Component_")
	}
	if t, err := m.exportTable("Component"); err == nil {
		database.Components = t.keyValue("Component", "Directory_")
	}
	if t, err := m.exportTable("Directory"); err == nil {
		database.Directories = t.keyValue("Directory", "Directory_Parent")
	}
	return nil
}

// run executes msiinfo with the given arguments.
func (m *msiReader) run(args ...string) ([]byte, error) {
	cmd := exec.Command("msiinfo", args...)
	return cmd.Output()
}
