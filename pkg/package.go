package pkg

import (
	"archive/zip"
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
	metadataFile    = "IntuneWinPackage/Metadata/Detection.xml" // The path to the metadata file contained in the intunewin file
	contentFile     = "IntuneWinPackage/Contents/IntunePackage.intunewin"
	contentsDir     = "IntuneWinPackage/Contents/"
	contentFileName = "IntunePackage.intunewin" // The name of the encrypted content file
	toolVersion     = "1.4.0.0"
	fileDigestAlgo  = "SHA256"
)

// Package represents an .intunewin package.
type Package struct {
	Name             string // The name of the intunewin file
	Path             string // The path to the intunewin file
	reader           *zip.ReadCloser
	applicationInfo  data.ApplicationInfo // The metadata of the intunewin file
	validContentFile bool
	aesKey           []byte
	aesIV            []byte
	macKey           []byte
	mac              []byte
	contentHash      []byte
}

// OpenPackage opens an existing .intunewin file for reading and extraction.
func OpenPackage(path string) (*Package, error) {
	p := new(Package)
	p.Path = path

	// Open the intunewin archive for reading.
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}

	p.reader = r

	// Open the file 'IntuneWinPackage/Metadata/Detection.xml' for deserialization.
	f, err := r.Open(metadataFile)
	if err != nil {
		p.reader.Close()
		return nil, err
	}
	defer f.Close()

	// Decode the xml
	dec := xml.NewDecoder(f)
	err = dec.Decode(&p.applicationInfo)
	if err != nil {
		p.reader.Close()
		return nil, err
	}

	p.Name = p.applicationInfo.Name

	// Decode the AES key, IV, MAC, MAC key and FileHash
	p.macKey, err = decodeBase64Key(p.applicationInfo.EncryptionInfo.MacKey)
	if err != nil {
		p.reader.Close()
		return nil, err
	}
	p.mac, err = decodeBase64Key(p.applicationInfo.EncryptionInfo.Mac)
	if err != nil {
		p.reader.Close()
		return nil, err
	}

	p.aesKey, err = decodeBase64Key(p.applicationInfo.EncryptionInfo.Key)
	if err != nil {
		p.reader.Close()
		return nil, err
	}

	p.aesIV, err = decodeBase64Key(p.applicationInfo.EncryptionInfo.InitializationVector)
	if err != nil {
		p.reader.Close()
		return nil, err
	}

	p.contentHash, err = decodeBase64Key(p.applicationInfo.EncryptionInfo.FileDigest)
	if err != nil {
		p.reader.Close()
		return nil, err
	}

	// Validate the HMAC value
	// 1. Open the content file
	// 2. Read the MAC in the first 32 bytes and compare it to the value in Detection.xml
	// 3. Open the content file and verify the MAC
	content, err := r.Open(contentFile)
	if err != nil {
		p.reader.Close()
		return nil, err
	}
	defer content.Close()

	// Read the first 32 bytes that contain the HMAC of the file
	fileMAC := make([]byte, 32)
	_, err = io.ReadFull(content, fileMAC)
	if err != nil {
		p.reader.Close()
		return nil, err
	}

	if !hmac.Equal(p.mac, fileMAC) {
		p.reader.Close()
		return nil, errors.New("hmac mismatch: value in Detection.xml doesn't match the value in the file")
	}

	p.validContentFile, err = ValidateHMAC(content, sha256.New, p.macKey, p.mac)
	if err != nil {
		p.reader.Close()
		return nil, err
	}

	if !p.validContentFile {
		p.reader.Close()
		return nil, errors.New("hmac verification failed")
	}

	return p, nil
}

// Close closes the underlying zip reader if open.
func (p *Package) Close() error {
	if p.reader != nil {
		return p.reader.Close()
	}
	return nil
}

// ExtractContent writes the decrypted content package to destDir.
func (p *Package) ExtractContent(destDir string) error {
	dest := filepath.Join(destDir, p.applicationInfo.FileName)
	output, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer output.Close()

	content, err := p.reader.Open(contentFile)
	if err != nil {
		return err
	}
	defer content.Close()

	err = p.decryptContentArchive(content, output)
	if err != nil {
		return err
	}

	return nil
}

func (p *Package) decryptContentArchive(input io.Reader, output *os.File) error {
	// Create a CBC decrypter
	dec, err := NewAESCBCDecrypter(output, p.aesIV, p.aesKey)
	if err != nil {
		return err
	}

	// Create a reader for the input and discard the first 48 bytes (MAC + IV)
	header := make([]byte, 48)
	_, err = io.ReadFull(input, header)
	if err != nil {
		return err
	}

	if _, err := io.Copy(dec, input); err != nil {
		return err
	}

	if err := dec.Close(); err != nil {
		return err
	}

	// Verify SHA256 hash
	hash, err := sha256FileHash(output)
	if err != nil {
		return err
	}
	if hash != p.applicationInfo.EncryptionInfo.FileDigest {
		return errors.New("unexpected content file hash")
	}

	return nil
}
