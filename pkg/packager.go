package pkg

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/lwalthert/intunewin/internal/data"
	"github.com/lwalthert/intunewin/internal/validator"
)

// Packager handles the creation and packaging of an .intunewin package.
type Packager struct {
	Name        string // The name of the intunewin file
	ContentDir  string // The directory containing the content to package
	SetupFile   string // relative to ContentDir
	OutputDir   string // The directory to output the intunewin file
	ToolVersion string // currently hardcoded to "1.0.0" Microsoft might change this in the future

	applicationInfo data.ApplicationInfo
	outputPath      string
	aesKey          []byte
	aesIV           []byte
	macKey          []byte
}

// NewPackager creates a new Packager with the provided parameters.
// name: The name of the intunewin file
// contentPath: The path to the content folder
// setupFile: The name of the setup file, relative to the content folder
// outputPath: The path to the output folder
// Returns a pointer to the new intunewin file
func NewPackager(name, contentDir, setupFile, outputDir string) *Packager {
	return &Packager{
		Name:        name,
		ContentDir:  contentDir,
		SetupFile:   setupFile,
		OutputDir:   outputDir,
		ToolVersion: toolVersion,
	}
}

// Package executes the full packaging pipeline and creates the .intunewin file.
func (p *Packager) Package() (*Package, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	setupPath := filepath.Join(p.ContentDir, p.SetupFile)
	p.initMetadata(setupPath)

	if err := p.populateMSIInfo(setupPath); err != nil {
		return nil, err
	}

	if err := p.generateEncryptionKeys(); err != nil {
		return nil, err
	}

	return p.build()
}

func (p *Packager) validate() error {
	if !validator.NotBlank(p.Name) {
		return errors.New("input string cannot be blank")
	}
	if !validator.NotBlank(p.SetupFile) {
		return errors.New("setup file cannot be blank")
	}
	if !validator.IsRelativePath(p.SetupFile) {
		return fmt.Errorf("setup file %s must be a file name or relative path, not an absolute path", p.SetupFile)
	}
	if !validator.PathIsExists(p.ContentDir, validator.Directory) {
		return fmt.Errorf("content folder %s does not exist or is not a directory", p.ContentDir)
	}
	if !validator.PathIsExists(p.OutputDir, validator.Directory) {
		return fmt.Errorf("output folder %s does not exist or is not a directory", p.OutputDir)
	}
	if !validator.FileIsInDirectory(p.SetupFile, p.ContentDir) {
		return fmt.Errorf("setup file %s is not in content folder %s", p.SetupFile, p.ContentDir)
	}
	return nil
}

func (p *Packager) initMetadata(setupPath string) {
	tv := p.ToolVersion
	if tv == "" {
		tv = toolVersion
	}
	p.outputPath = filepath.Join(p.OutputDir, p.Name+".intunewin")
	p.applicationInfo = *data.NewApplicationInfo(p.Name, p.SetupFile, tv)
	p.applicationInfo.SetupFile = filepath.Base(setupPath)
	p.applicationInfo.FileName = contentFileName
}

func (p *Packager) populateMSIInfo(setupPath string) error {
	if !strings.EqualFold(filepath.Ext(setupPath), ".msi") {
		return nil
	}
	reader, err := OpenMSI(setupPath)
	if err != nil {
		return err
	}
	props, err := reader.Read()
	if err != nil {
		return fmt.Errorf("failed to read msi metadata: %w", err)
	}
	data.ReadMSI(&p.applicationInfo.MSIInfo, props)
	return nil
}

func (p *Packager) generateEncryptionKeys() error {
	var err error
	if p.aesIV, err = generateKey(16); err != nil {
		return err
	}
	if p.aesKey, err = generateKey(32); err != nil {
		return err
	}
	if p.macKey, err = generateKey(32); err != nil {
		return err
	}

	p.applicationInfo.EncryptionInfo = *data.NewEncryptionInfo(
		base64.StdEncoding.EncodeToString(p.aesKey),
		base64.StdEncoding.EncodeToString(p.macKey),
		base64.StdEncoding.EncodeToString(p.aesIV),
		fileDigestAlgo,
		data.ProfileVersion1,
	)
	return nil
}

func (p *Packager) build() (*Package, error) {
	output, err := os.Create(p.outputPath)
	if err != nil {
		return nil, err
	}
	defer output.Close()

	var success bool
	defer func() {
		if !success {
			os.Remove(p.outputPath)
		}
	}()

	encryptedPayload, err := p.prepareEncryptedPayload()
	if err != nil {
		return nil, err
	}
	defer encryptedPayload.Close()
	defer os.Remove(encryptedPayload.Name())

	if err := p.writeZipPackage(output, encryptedPayload); err != nil {
		return nil, err
	}

	if err := output.Close(); err != nil {
		return nil, err
	}

	success = true
	return &Package{
		Name:            p.Name,
		Path:            p.outputPath,
		applicationInfo: p.applicationInfo,
		aesKey:          p.aesKey,
		aesIV:           p.aesIV,
		macKey:          p.macKey,
	}, nil
}

func (p *Packager) prepareContentArchive() (*os.File, error) {
	contentArchive, err := os.CreateTemp("", "IntunePackage*.zip")
	if err != nil {
		return nil, err
	}

	if err := createContentArchive(p.ContentDir, contentArchive); err != nil {
		contentArchive.Close()
		os.Remove(contentArchive.Name())
		return nil, err
	}

	caStat, err := contentArchive.Stat()
	if err != nil {
		contentArchive.Close()
		os.Remove(contentArchive.Name())
		return nil, err
	}

	p.applicationInfo.UnencryptedContentSize = int(caStat.Size())
	archiveHash, err := sha256FileHash(contentArchive)
	if err != nil {
		contentArchive.Close()
		os.Remove(contentArchive.Name())
		return nil, err
	}

	p.applicationInfo.EncryptionInfo.FileDigest = archiveHash
	p.applicationInfo.EncryptionInfo.FileDigestAlgorithm = fileDigestAlgo

	if _, err := contentArchive.Seek(0, io.SeekStart); err != nil {
		contentArchive.Close()
		os.Remove(contentArchive.Name())
		return nil, err
	}

	return contentArchive, nil
}

func (p *Packager) prepareEncryptedPayload() (*os.File, error) {
	contentArchive, err := p.prepareContentArchive()
	if err != nil {
		return nil, err
	}
	defer contentArchive.Close()
	defer os.Remove(contentArchive.Name())

	encryptedContent, mac, err := p.encryptContentArchive(contentArchive)
	if err != nil {
		return nil, err
	}

	p.applicationInfo.EncryptionInfo.Mac = base64.StdEncoding.EncodeToString(mac)

	if _, err := encryptedContent.Seek(0, io.SeekStart); err != nil {
		encryptedContent.Close()
		os.Remove(encryptedContent.Name())
		return nil, err
	}

	return encryptedContent, nil
}

func (p *Packager) encryptContentArchive(input io.Reader) (*os.File, []byte, error) {
	output, err := os.CreateTemp("", "IntunePackage*.intunewin")
	if err != nil {
		return nil, nil, err
	}

	// The first 32 bytes of the file contain the HMAC of the encrypted file.
	// The value is only known after encrypting the file so it has to be written at the end.
	if _, err := output.Seek(32, 0); err != nil {
		os.Remove(output.Name())
		return nil, nil, err
	}

	aesWriter, err := NewAESCBCEncrypter(output, sha256.New, p.aesIV, p.aesKey, p.macKey)
	if err != nil {
		os.Remove(output.Name())
		return nil, nil, err
	}

	blockSize := int(aesWriter.Block.BlockSize())
	buf := make([]byte, 0, 2097152)
	for {
		n, err := io.ReadFull(input, buf[:cap(buf)])
		if n%blockSize != 0 {
			padding := blockSize - n%blockSize
			buf = append(buf[:n], bytes.Repeat([]byte{byte(padding)}, padding)...)
			n = n + padding
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				os.Remove(output.Name())
				fmt.Fprintln(os.Stderr, err)
				return nil, nil, err
			}
		}

		n, err = aesWriter.Write(buf[:n])
		if err != nil {
			os.Remove(output.Name())
			return nil, nil, err
		}
	}

	hmac := aesWriter.Sum(nil)
	_, err = output.WriteAt(hmac, 0)
	if err != nil {
		os.Remove(output.Name())
		return nil, nil, err
	}

	return output, hmac, nil
}

func (p *Packager) writeZipPackage(w io.Writer, encryptedContent io.Reader) error {
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	fileWriter, err := zipWriter.CreateHeader(&zip.FileHeader{
		Name:   contentFile,
		Method: zip.Store,
	})
	if err != nil {
		return err
	}

	if _, err := io.Copy(fileWriter, encryptedContent); err != nil {
		return err
	}

	metadataWriter, err := zipWriter.Create(metadataFile)
	if err != nil {
		return err
	}

	out, err := xml.MarshalIndent(&p.applicationInfo, " ", " ")
	if err != nil {
		return err
	}
	if _, err := metadataWriter.Write(out); err != nil {
		return err
	}

	return zipWriter.Close()
}

func createContentArchive(setupDirectory string, w io.Writer) error {
	var files []string
	err := filepath.WalkDir(setupDirectory, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	zw := zip.NewWriter(w)

	for _, f := range files {
		file, err := os.Open(f)
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(setupDirectory, f)
		if err != nil {
			file.Close()
			return err
		}
		zipPath := filepath.ToSlash(rel)
		fw, err := zw.Create(zipPath)
		if err != nil {
			file.Close()
			return err
		}

		_, err = io.Copy(fw, file)
		file.Close()
		if err != nil {
			return err
		}
	}

	return zw.Close()
}
