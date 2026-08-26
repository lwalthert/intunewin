# Intunewin

This projects tries to implement the functionality of the [Microsoft Win32 Content Prep Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool) in golang.
It was made out of frustration with Microsoft's unwillingness to fix bugs in the official tool and regularly breaking it for months after new releases. It is also mostly
crossplatform. Reading the metadata of an .msi setup file (which is stored in the
MsiInfo section of Detection.xml) is supported on Windows (via the Windows Installer
automation API) and, on Linux and macOS, by linking directly against the
[msitools](https://gitlab.gnome.org/GNOME/msitools) libmsi C library via cgo (the
`libmsi` build tag). libmsi is LGPL-2.1+.

```sh
# Link directly against libmsi (cgo; libmsi dev headers required at build time)
go build -tags libmsi -o ./bin/intunewin ./cmd/cli
```

## Dependencies

### Go

A Go toolchain matching the version in [`go.mod`](go.mod) is required to build the
project.

### MSI metadata (Linux and macOS)

Reading the metadata of an `.msi` setup file requires the `libmsi` C library from
[msitools](https://gitlab.gnome.org/GNOME/msitools). It is linked via cgo when
building with the `libmsi` build tag, so the development headers and library must
be installed **at build time**.

**Debian / Ubuntu**
  ```sh
  sudo apt-get install libmsi-dev, libglib2.0-dev
  ```
**macOS (Homebrew)**
  ```sh
  brew install msitools, wixl
  ```
**Fedora**
  ```sh
  sudo dnf install libmsi1-devel, glib2-devel
  ```

The `msitools` package also provides `wixl`, which is used to build the MSI test
fixture when running the test suite.

### Windows

No extra dependencies are required. MSI metadata is read through the built-in
Windows Installer automation API.

## Usage

## Intunewin Package Structure

The .intunewin file is a zip file that contains has the following structure:

```bash
|-- IntuneWinPackage
    |-- Contents
    |   |-- IntunePackage.intunewin
    `-- Metadata
        |-- Detection.xml
```

### Detection.xml

The file "Detection.xml" is an xml file that contains the metadata for the intunewin package. This consists of information about the setup file with additional information
about msi setups and the encryption information for the "IntunePackage.intunewin".

### IntunePackage.intunewin

The file "IntunePackage.intunewin" is an encrypted zip archive that contains the installer. It is encrypte using AES256 in CBC mode with a random IV.
It is also hashed using HMAC-SHA256. The AES encryption key, IV, HMAC hash, and HMAC key for the encrypted file are found in the "Detection.xml" file. The "Detection.xml"
file also contains the hash and hashing algorithm and file length of the unencrypted file.
