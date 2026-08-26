package data

import "strings"

// MSI holds the metadata about an MSI setup file that is stored beneath the
// <MsiInfo> element in Detection.xml. The fields map 1:1 to properties exposed
// by the Windows Installer automation API (see MSIReader in the pkg package
// for how they are sourced).
type MSI struct {
	ProductCode                string `xml:"MsiProductCode"`    // guid
	ProductVersion             string `xml:"MsiProductVersion"` // version string
	PackageCode                string `xml:"MsiPackageCode"`    // guid
	UpgradeCode                string `xml:"MsiUpgradeCode"`    // guid
	ExecutionContext           string `xml:"MsiExecutionContext"`
	RequiresLogon              bool   `xml:"MsiRequiresLogon"`
	RequiresReboot             bool   `xml:"MsiRequiresReboot"`
	IsMachineInstall           bool   `xml:"MsiIsMachineInstall"`
	IsUserInstall              bool   `xml:"MsiIsUserInstall"`
	IncludesServices           bool   `xml:"MsiIncludesServices"`
	IncludesODBCDataSource     bool   `xml:"MsiIncludesODBCDataSource"`
	ContainsSystemRegistryKeys bool   `xml:"MsiContainsSystemRegistryKeys"`
	ContainsSystemFolders      bool   `xml:"MsiContainsSystemFolders"`
	Publisher                  string `xml:"MsiPublisher"`
}

// MSIProperties bundles the raw values extracted from an MSI file so the
// platform specific reader (see pkg) can focus on COM access while all
// interpretation lives here in one well-tested place.
type MSIProperties struct {
	Summary    map[string]string
	Properties map[string]string
	Database   *Database
}

// Database mirrors the subset of the MSI database tables that determines the
// boolean MSI metadata fields.
type Database struct {
	// Services lists the primary keys of the ServiceInstall table. A non-empty
	// value means the package installs one or more Windows services.
	Services []string
	// ODBCDataSources lists the primary keys of the ODBCDataSource table. A
	// non-empty value means the package installs one or more ODBC data sources.
	ODBCDataSources []string
	// Registry maps the primary key of a Registry table row to the string
	// value of its root column ("2" = HKEY_LOCAL_MACHINE, per-user rows are
	// any other value).
	Registry map[string]string
	// Filesystems maps the primary key of a File table row (the FileName) to
	// the identifier of the component that owns the file.
	Filesystems map[string]string
	// Components maps a Component identifier to the directory identifier the
	// component is installed into.
	Components map[string]string
	// Directories maps a Directory identifier to its parent identifier,
	// allowing File->Component->Directory references to be resolved to a root
	// folder.
	Directories map[string]string
}

// systemFolders are Directory/path identifiers that resolve to the Windows
// installation or Program Files areas, i.e. the system scope rather than a
// per-user scope.
var systemFolders = map[string]bool{
	"System64Folder":        true,
	"SystemFolder":          true,
	"WindowsFolder":         true,
	"AdminFilesFolder":      true,
	"ProgramFilesFolder":    true,
	"ProgramFiles64Folder":  true,
	"CommonFilesFolder":     true,
	"CommonFiles6432Folder": true,
	"FontsFolder":           true,
	"System16Folder":        true,
}

// ReadMSI fills msi from the raw MSI properties and database rows in props.
func ReadMSI(msi *MSI, props *MSIProperties) {
	msi.ProductVersion = props.Properties["ProductVersion"]
	msi.ProductCode = props.Properties["ProductCode"]
	msi.PackageCode = props.Summary["Package Code"]
	msi.UpgradeCode = props.Properties["UpgradeCode"]
	msi.Publisher = props.Properties["Manufacturer"]

	// ALLUSERS=1 forces a per-machine installation in every logging mode and is
	// the reliable signal for a machine install; without it the install is
	// treated as per-user.
	msi.IsMachineInstall = strings.EqualFold(props.Properties["ALLUSERS"], "1")
	msi.IsUserInstall = !msi.IsMachineInstall

	msi.ExecutionContext = executionContext(props.Properties)
	msi.RequiresLogon = requiresLogon(props.Properties)
	msi.RequiresReboot = requiresReboot(props.Properties)

	if props.Database != nil {
		db := props.Database
		msi.IncludesServices = len(db.Services) > 0
		msi.IncludesODBCDataSource = len(db.ODBCDataSources) > 0
		msi.ContainsSystemRegistryKeys = containsSystemRegistryKeys(db)
		msi.ContainsSystemFolders = containsSystemFolders(db)
	}
}

// executionContext determines the user context the package is designed to
// install for. There is no direct MSI property for this, so it is inferred
// from ALLUSERS, mirroring the Intune detection heuristic.
func executionContext(props map[string]string) string {
	allUsers := props["ALLUSERS"]
	installPerUser := props["MSIINSTALLPERUSER"]

	switch strings.ToUpper(allUsers) {
	case "1":
		return "machine"
	case "2":
		return "process"
	case "":
		if strings.EqualFold(installPerUser, "1") {
			return "peruser"
		}
		return "system"
	default:
		return "user"
	}
}

// requiresLogon reports whether the package has to run in the user session and
// therefore needs the user to be logged on.
func requiresLogon(props map[string]string) bool {
	switch strings.ToUpper(props["LogonUser"]) {
	case "TRUE", "1":
		return true
	}
	return false
}

// requiresReboot reports whether the MSI needs a reboot after install, as
// signalled through the REBOOT property.
func requiresReboot(props map[string]string) bool {
	return strings.EqualFold(props["REBOOT"], "FORCE")
}

// containsSystemRegistryKeys reports whether the MSI writes registry entries
// into the system (HKEY_LOCAL_MACHINE) hive via the Registry table.
func containsSystemRegistryKeys(db *Database) bool {
	for _, root := range db.Registry {
		if root == "2" {
			return true
		}
	}
	return false
}

// containsSystemFolders reports whether the MSI installs files into the
// Windows or system directories. Files reference a component, which in turn
// references a directory; the directory's parent chain is walked to a known
// system folder root.
func containsSystemFolders(db *Database) bool {
	for _, component := range db.Filesystems {
		dir := db.Components[component]
		if resolvesToSystemFolder(dir, db.Directories) {
			return true
		}
	}
	return false
}

// resolvesToSystemFolder walks the Directory table parent chain starting at the
// given identifier, returning true if it reaches one of the known system folder
// roots.
func resolvesToSystemFolder(identifier string, directories map[string]string) bool {
	seen := make(map[string]bool)
	for id := identifier; id != "" && !seen[id]; id = directories[id] {
		if systemFolders[id] {
			return true
		}
		seen[id] = true
	}
	return false
}
