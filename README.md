# Intunewin

This projects tries to implement the functionality of the [Microsoft Win32 Content Prep Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool) in golang.
It was made out of frustration with Microsoft's unwillingness to fix bugs in the official tool and regularly breaking it for months after new releases. It is also mostly
crossplatform with support for .msi files missing on macOS and Linux.

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
