package pkg

import (
	"archive/zip"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/lwalthert/intunewin/internal/data"
)

const (
	metadataFile   = "IntuneWinPackage/Metadata/Detection.xml" // The path to the metadata file contained in the intunewin file
	contentsDir    = "IntuneWinPackage/Contents/"
	outputFileName = "IntunePackage.intunewin" // The name of the encrypted content file
	toolVersion    = "1.4.0.0"
	fileDigestAlgo = "SHA256"
)

// Package represents an .intunewin package.
type Package struct {
	Name             string // The name of the intunewin file
	Path             string // The path to the intunewin file
	reader           *zip.ReadCloser
	applicationInfo  data.ApplicationInfo // The metadata of the intunewin file
	contentDir       string               // The path to the content folder
	contentFile      string               // The path to the content file
	validContentFile bool
	aesKey           []byte
	aesIV            []byte
	macKey           []byte
	mac              []byte
	contentHash      []byte
}

// OpenFile opens an existing .intunewin file for reading and extraction.
func OpenFile(file string) (*Package, error) {
	iw := new(Package)
	iw.Path = file

	// Open the intunewin archive for reading.
	r, err := zip.OpenReader(file)
	if err != nil {
		return nil, err
	}

	iw.reader = r

	// Open the file 'IntuneWinPackage/Metadata/Detection.xml' for deserialization.
	f, err := r.Open(metadataFile)
	if err != nil {
		iw.reader.Close()
		return nil, err
	}
	defer f.Close()

	// Decode the xml
	dec := xml.NewDecoder(f)
	err = dec.Decode(&iw.applicationInfo)
	if err != nil {
		iw.reader.Close()
		return nil, err
	}

	iw.Name = iw.applicationInfo.Name

	// Decode the AES key, IV, MAC, MAC key and FileHash
	iw.macKey, err = decodeBase64Key(iw.applicationInfo.EncryptionInfo.MacKey)
	if err != nil {
		iw.reader.Close()
		return nil, err
	}
	iw.mac, err = decodeBase64Key(iw.applicationInfo.EncryptionInfo.Mac)
	if err != nil {
		iw.reader.Close()
		return nil, err
	}

	iw.aesKey, err = decodeBase64Key(iw.applicationInfo.EncryptionInfo.Key)
	if err != nil {
		iw.reader.Close()
		return nil, err
	}

	iw.aesIV, err = decodeBase64Key(iw.applicationInfo.EncryptionInfo.InitializationVector)
	if err != nil {
		iw.reader.Close()
		return nil, err
	}

	iw.contentHash, err = decodeBase64Key(iw.applicationInfo.EncryptionInfo.FileDigest)
	if err != nil {
		iw.reader.Close()
		return nil, err
	}

	// Set the variable contentFile
	iw.contentFile = filepath.Join("IntuneWinPackage/Contents/", iw.applicationInfo.FileName)

	// Validate the HMAC value
	// 1. Open the content file
	// 2. Read the MAC in the first 32 bytes and compare it to the value in Detection.xml
	// 3. Open the content file and verify the MAC
	content, err := r.Open(iw.contentFile)
	if err != nil {
		iw.reader.Close()
		return nil, err
	}
	defer content.Close()

	// Read the first 32 bytes that contain the HMAC of the file
	fileMAC := make([]byte, 32)
	_, err = io.ReadFull(content, fileMAC)
	if err != nil {
		iw.reader.Close()
		return nil, err
	}

	if !hmac.Equal(iw.mac, fileMAC) {
		iw.reader.Close()
		return nil, errors.New("hmac missmatch: value in content.xml doesn't match the value in the file")
	}

	iw.validContentFile, err = ValidateHMAC(content, sha256.New, iw.macKey, iw.mac)
	if err != nil {
		iw.reader.Close()
		return nil, err
	}

	if !iw.validContentFile {
		iw.reader.Close()
		return nil, errors.New("hmac verification failed")
	}

	return iw, nil
}

// Close closes the underlying zip reader if open.
func (iw *Package) Close() error {
	if iw.reader != nil {
		return iw.reader.Close()
	}
	return nil
}

// ExtractContent writes the decrypted content package to destDir.
func (iw *Package) ExtractContent(destDir string) error {
	dest := filepath.Join(destDir, iw.applicationInfo.FileName)
	output, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer output.Close()

	content, err := iw.reader.Open(iw.contentFile)
	if err != nil {
		return err
	}
	defer content.Close()

	err = iw.decryptContentArchive(content, output)
	if err != nil {
		return err
	}

	return nil
}

func (iw *Package) decryptContentArchive(input io.Reader, output *os.File) error {
	// Create a CBC decrypter
	dec, err := NewAESCBCDecrypter(output, iw.aesIV, iw.aesKey)
	if err != nil {
		return err
	}

	// Create a reader for the input and discard the first 48 bytes (MAC + IV)
	header := make([]byte, 48)
	_, err = io.ReadFull(input, header)
	if err != nil {
		return err
	}

	n, err := io.Copy(dec, input)
	if err != nil {
		return err
	}

	if n%int64(dec.Block.BlockSize()) != 0 {
		return errors.New("data is not block-aligned")
	}

	// Strip the PKCS#7 padding
	// https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.2 remove PKCS#7 padding
	buf := make([]byte, 1)
	_, err = output.ReadAt(buf, n-1)
	if err != nil {
		return err
	}
	padLen := int64(buf[0])

	if padLen > 0 && padLen < int64(dec.Block.BlockSize()) {
		refPad := bytes.Repeat([]byte{byte(padLen)}, int(padLen))
		padding := make([]byte, padLen)
		_, err = output.ReadAt(padding, n-1-padLen)
		if err != nil {
			return err
		}

		if bytes.Equal(refPad, padding) {
			output.Truncate(n - padLen)
		}
	}

	// Verify SHA256 hash
	hash, err := sha256FileHash(output)
	if err != nil {
		return err
	}
	if hash != iw.applicationInfo.EncryptionInfo.FileDigest {
		return errors.New("unexpected content file hash")
	}

	return nil
}
