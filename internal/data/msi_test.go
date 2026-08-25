package data

import "testing"

func TestReadMSI(t *testing.T) {
	tests := []struct {
		name  string
		props *MSIProperties
		want  MSI
	}{
		{
			name: "machine install with services and system registry",
			props: &MSIProperties{
				Summary: map[string]string{
					"Revision Number": "1.2.3.4",
					"Package Code":    "{PKG-GUID}",
				},
				Properties: map[string]string{
					"ProductCode":    "{PROD-GUID}",
					"ProductVersion": "1.2.3.4",
					"UpgradeCode":    "{UPG-GUID}",
					"Manufacturer":   "Contoso",
					"ALLUSERS":       "1",
				},
				Database: &Database{
					Services:        []string{"svc1"},
					ODBCDataSources: []string{"dsn1"},
					Registry:        map[string]string{"reg1": "2"},
					Filesystems:     map[string]string{"app.exe": "comp1"},
					Components:      map[string]string{"comp1": "TARGETDIR"},
					Directories:     map[string]string{"TARGETDIR": "ProgramFilesFolder"},
				},
			},
			want: MSI{
				ProductCode:                "{PROD-GUID}",
				ProductVersion:             "1.2.3.4",
				PackageCode:                "{PKG-GUID}",
				UpgradeCode:                "{UPG-GUID}",
				Publisher:                  "Contoso",
				ExecutionContext:           "machine",
				IsMachineInstall:           true,
				IsUserInstall:              false,
				IncludesServices:           true,
				IncludesODBCDataSource:     true,
				ContainsSystemRegistryKeys: true,
				ContainsSystemFolders:      true,
			},
		},
		{
			name: "user install via missing ALLUSERS",
			props: &MSIProperties{
				Summary: map[string]string{"Revision Number": "2.0.0"},
				Properties: map[string]string{
					"ProductCode":    "{PROD2}",
					"ProductVersion": "2.0.0",
					"ALLUSERS":       "",
				},
				Database: &Database{
					Registry:    map[string]string{"reg1": "1"}, // per-user root
					Filesystems: map[string]string{"u.exe": "comp2"},
					Components:  map[string]string{"comp2": "LocalAppDataFolder"},
					Directories: map[string]string{"LocalAppDataFolder": "TARGETDIR"},
				},
			},
			want: MSI{
				ProductCode:      "{PROD2}",
				ProductVersion:   "2.0.0",
				ExecutionContext: "system",
				IsMachineInstall: false,
				IsUserInstall:    true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got MSI
			ReadMSI(&got, tt.props)
			if got != tt.want {
				t.Errorf("ReadMSI() =\n got  %+v\n want %+v", got, tt.want)
			}
		})
	}
}
