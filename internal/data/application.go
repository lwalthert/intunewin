package data

import "encoding/xml"

type ApplicationInfo struct {
	XMLName                xml.Name       `xml:"ApplicationInfo"`
	XMLSchemaDef           string         `xml:"xmlns:xsd,attr"` // xmlns:xsd="http://www.w3.org/2001/XMLSchema"
	XMLSchemaIns           string         `xml:"xmlns:xsi,attr"` // xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	ToolVersion            string         `xml:"ToolVersion,attr"`
	Name                   string         `xml:"Name"`
	FileName               string         `xml:"FileName"`
	SetupFile              string         `xml:"SetupFile"`
	UnencryptedContentSize int            `xml:"UnencryptedContentSize"`
	EncryptionInfo         EncryptionInfo `xml:"EncryptionInfo"`
	MSIInfo                MSI            `xml:"MsiInfo"`
}

func NewApplicationInfo(name, setupFile, toolVersion string) *ApplicationInfo {
	return &ApplicationInfo{
		Name:         name,
		FileName:     name + ".intunewin",
		SetupFile:    setupFile,
		ToolVersion:  toolVersion,
		XMLSchemaDef: "http://www.w3.org/2001/XMLSchema",
		XMLSchemaIns: "http://www.w3.org/2001/XMLSchema-instance",
	}
}

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
