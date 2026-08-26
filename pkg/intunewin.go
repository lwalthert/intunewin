package pkg

import (
	"archive/zip"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/lwalthert/intunewin/internal/data"
	"github.com/lwalthert/intunewin/internal/validator"
)

const (
	metadataFile   = "IntuneWinPackage/Metadata/Detection.xml" // The path to the metadatfile contained in the intunewin file
	contentsDir    = "IntuneWinPackage/Contents/"
	outputFileName = "IntunePackage.intunewin" // The name of the encryptet content file
	toolVersion    = "1.4.0.0"
	fileDigestAlgo = "SHA256"
)

type Intunewin struct {
	Name             string               // The name of the intunewin file
	Path             string               // The path to the intunewin file
	reader           *zip.ReadCloser      //
	applicationInfo  data.ApplicationInfo // the metadata of the intunewin file
	contentDir       string               // The path to the content folder
	contentFile      string               // The path to the content file
	validContentFile bool
	aesKey           []byte
	aesIV            []byte
	macKey           []byte
	mac              []byte
	contentHash      []byte
}

// NewIntunewin creates a new intunewin file
// name: The name of the intunewin file
// contentPath: The path to the content folder
// setupFile: The name of the setup file, relative to the content folder
// outputPath: The path to the output folder
// Returns a pointer to the new intunewin file
func NewIntunewin(name, contentPath, setupFile, outputPath string) (*Intunewin, error) {
	// Validate the input
	if !validator.NotBlank(name) {
		return nil, errors.New("input string cannot be blank")
	}

	if !validator.NotBlank(setupFile) {
		return nil, errors.New("setup file cannot be blank")
	}

	if !validator.IsRelativePath(setupFile) {
		return nil, fmt.Errorf("setup file %s must be a file name or relative path, not an absolute path", setupFile)
	}

	if !validator.PathIsExists(contentPath, validator.Directory) {
		return nil, fmt.Errorf("content folder %s does not exist or is not a directory", contentPath)
	}

	if !validator.PathIsExists(outputPath, validator.Directory) {
		return nil, fmt.Errorf("output folder %s does not exist or is not a directory", outputPath)
	}

	if !validator.FileIsInDirectory(setupFile, contentPath) {
		return nil, fmt.Errorf("setup file %s is not in content folder %s", setupFile, contentPath)
	}

	setupPath := filepath.Join(contentPath, setupFile)

	iw := &Intunewin{
		applicationInfo: *data.NewApplicationInfo(name, setupFile, toolVersion),
	}

	iw.applicationInfo.SetupFile = filepath.Base(setupPath)

	// If the setup file is an MSI package, read its metadata and populate the
	// MsiInfo section of Detection.xml. This is only supported on Windows
	// (where Windows Installer is available); elsewhere the metadata stays
	// empty and a broken or unreadable MSI is reported as an error.
	if strings.EqualFold(filepath.Ext(setupPath), ".msi") {
		reader, err := OpenMSI(setupPath)
		if err != nil {
			return nil, err
		}

		props, err := reader.Read()
		if err != nil {
			return nil, fmt.Errorf("failed to read msi metadata: %w", err)
		}

		data.ReadMSI(&iw.applicationInfo.MSIInfo, props)
	}

	// The FileName metadata field always refers to the name of the
	// encrypted content archive stored inside the package, which is
	// constant, not to the name of the .intunewin file itself.
	iw.applicationInfo.FileName = outputFileName
	iw.Name = name

	// Create the intunewin file
	iw.Path = filepath.Join(outputPath, name+".intunewin")
	output, err := os.Create(iw.Path)
	if err != nil {
		return nil, err
	}

	defer output.Close()
	var success bool
	defer func() {
		if !success {
			os.Remove(iw.Path)
		}
	}()

	// Generate the encryption keys and add them to the metadata
	iv, err := generateKey(16)
	if err != nil {
		return nil, err
	}
	iw.aesIV = iv

	aesKey, err := generateKey(32)
	if err != nil {
		return nil, err
	}
	iw.aesKey = aesKey

	macKey, err := generateKey(32)
	if err != nil {
		return nil, err
	}
	iw.macKey = macKey

	iw.applicationInfo.EncryptionInfo = *data.NewEncryptionInfo(
		base64.StdEncoding.EncodeToString(iw.aesKey),
		base64.StdEncoding.EncodeToString(iw.macKey),
		base64.StdEncoding.EncodeToString(iw.aesIV),
		fileDigestAlgo,
		data.ProfileVersion1)

	// Create the IntunewinPackage.zip containing the content of the content folder
	contentArchive, err := os.CreateTemp("", "IntunePackage*.zip")
	if err != nil {
		// TODO Logging and Error handling
		return nil, err
	}

	defer contentArchive.Close()
	defer os.Remove(contentArchive.Name())

	err = createContentArchive(contentPath, contentArchive)
	if err != nil {
		// TODO Logging and Error handling
		return nil, err
	}

	caStat, err := contentArchive.Stat()
	if err != nil {
		// TODO Logging and Error handling
		return nil, err
	}

	iw.applicationInfo.UnencryptedContentSize = int(caStat.Size())
	archiveHash, err := sha256FileHash(contentArchive)
	if err != nil {
		// TODO Logging and Error handling
		return nil, err
	}

	iw.applicationInfo.EncryptionInfo.FileDigest = archiveHash
	iw.applicationInfo.EncryptionInfo.FileDigestAlgorithm = "SHA256"

	_, err = contentArchive.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	encryptedContent, mac, err := iw.encryptContentArchive(contentArchive)
	if err != nil {
		return nil, err
	}

	defer encryptedContent.Close()
	defer os.Remove(encryptedContent.Name())

	iw.applicationInfo.EncryptionInfo.Mac = base64.StdEncoding.EncodeToString(mac)

	_, err = encryptedContent.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	// Write to zip
	zipWriter := zip.NewWriter(output)

	defer zipWriter.Close()

	// explicitly using path.Join for ZIP file entries
	path := path.Join(contentsDir, outputFileName)
	fileWriter, err := zipWriter.CreateHeader(&zip.FileHeader{
		Name:   path,
		Method: zip.Store,
	})
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(fileWriter, encryptedContent)
	if err != nil {
		return nil, err
	}

	// Write Metadata
	fileWriter, err = zipWriter.Create(metadataFile)
	if err != nil {
		return nil, err
	}
	_, err = iw.writeMetadata(fileWriter)
	if err != nil {
		return nil, err
	}

	err = zipWriter.Close()
	if err != nil {
		return nil, err
	}
	err = output.Close()
	if err != nil {
		return nil, err
	}

	success = true
	return iw, nil
}

func OpenFile(file string) (*Intunewin, error) {
	iw := new(Intunewin)
	// Open the intunewin archive for reading.
	r, err := zip.OpenReader(file)
	if err != nil {
		return nil, err
	}

	iw.reader = r

	// Open the file 'IntuneWinPackage/Metadata/Detection.xml' for deserialization.
	f, err := r.Open(metadataFile)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	// Decode the xml
	dec := xml.NewDecoder(f)
	err = dec.Decode(&iw.applicationInfo)
	if err != nil {
		return nil, err
	}

	// Decode the AES key, IV, MAC, MAC key and FileHash
	iw.macKey, err = decodeBase64Key(iw.applicationInfo.EncryptionInfo.MacKey)
	if err != nil {
		return nil, err
	}
	iw.mac, err = decodeBase64Key(iw.applicationInfo.EncryptionInfo.Mac)
	if err != nil {
		return nil, err
	}

	iw.aesKey, err = decodeBase64Key(iw.applicationInfo.EncryptionInfo.Key)
	if err != nil {
		return nil, err
	}

	iw.aesIV, err = decodeBase64Key(iw.applicationInfo.EncryptionInfo.InitializationVector)
	if err != nil {
		return nil, err
	}

	iw.contentHash, err = decodeBase64Key(iw.applicationInfo.EncryptionInfo.FileDigest)
	if err != nil {
		return nil, err
	}

	// Set the variable contentfile
	iw.contentFile = filepath.Join("IntuneWinPackage/Contents/", iw.applicationInfo.FileName)

	// Validate the HMAC value
	// 1. Open the content file
	// 2. Read the MAC in the first 32 bits and compare it to the value in contents.xml
	// 3. Close the content file
	// 4. Open the content file and verifiy the MAC
	content, err := r.Open(iw.contentFile)
	if err != nil {
		return nil, err
	}

	defer content.Close()

	// Skip the first 32 bytes that contain the HMAC of the file
	fileMAC := make([]byte, 32)
	_, err = io.ReadFull(content, fileMAC)
	if err != nil {
		return nil, err
	}

	if !hmac.Equal(iw.mac, fileMAC) {
		return nil, errors.New("hmac missmatch: value in content.xml doesn't match the value in the file")
	}

	iw.validContentFile, err = ValidateHMAC(content, sha256.New, iw.macKey, iw.mac)
	if err != nil {
		return nil, err
	}

	if !iw.validContentFile {
		return nil, errors.New("hmac verification failed")
	}

	content.Close()

	return iw, nil
}

func (iw *Intunewin) Close() error {
	err := iw.reader.Close()
	if err != nil {
		return err
	}

	return nil
}

// ExtractContent() writes the IntunePackage.intunewin to the path supplied in path
func (iw *Intunewin) ExtractContent(destDir string) error {
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

func (iw *Intunewin) decryptContentArchive(input io.Reader, output *os.File) error {
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

	// TODO maybe only run this when output file size isn't block aligned
	// Strip the PKCS#7 padding
	// https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.2 remove PKCSC#7 padding
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

// encryptContentArchive() encrypts the file
func (iw *Intunewin) encryptContentArchive(input io.Reader) (*os.File, []byte, error) {
	// Create an output file, the handle is passed on to the caller
	// If there is an error the file is deleted with os.Remove(output.Name())
	output, err := os.CreateTemp("", "IntunePackage*.intunewin")
	if err != nil {
		return nil, nil, err
	}

	// The first 32 bytes of the file contain the HMAC of the encrypted file.
	// The value is only know after encrypting the file so it has to written at the end
	// This jumps to the offset after the HMAC ends to leave room for writing it at the end.
	output.Seek(32, 0)

	// Create a new AESCBCEncrypter that encrypts and writes the content to the writer and a hash function
	aesWriter, err := NewAESCBCEncrypter(output, sha256.New, iw.aesIV, iw.aesKey, iw.macKey)
	if err != nil {
		os.Remove(output.Name())
		return nil, nil, err
	}

	// Retrieve the blockSize of the cipher to use it for calculating the padding needed at the end of the file
	blockSize := int(aesWriter.Block.BlockSize())

	buf := make([]byte, 0, 2097152)
	for {
		n, err := io.ReadFull(input, buf[:cap(buf)])
		// Check if the content of the buffer is not a multiple of the block size.
		if n%blockSize != 0 {
			// Append padding to the buffer in the PKCS#7 format
			// https://datatracker.ietf.org/doc/html/rfc5652#section-6.3
			padding := blockSize - n%blockSize
			buf = append(buf[:n], bytes.Repeat([]byte{byte(padding)}, padding)...)
			n = n + padding
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break // Reached end of file
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

	// Calculate the HMAC and write it to the beginning of the file
	hmac := aesWriter.Sum(nil)
	_, err = output.WriteAt(hmac, 0)
	if err != nil {
		os.Remove(output.Name())
		return nil, nil, err
	}

	return output, hmac, nil
}

// Create the archive first because
// We need to know the length of the archive to encrypt it because we use AES CBC
// and might need to add padding to the end of the file.
func createContentArchive(setupDirectory string, w io.Writer) error {
	var files []string
	err := filepath.WalkDir(setupDirectory, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			// TODO open files here?
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	zw := zip.NewWriter(w)

	for _, f := range files {
		// Open the file
		file, err := os.Open(f)
		if err != nil {
			return err
		}
		defer file.Close()

		// Strip the setupDirectory from the file path
		rel, err := filepath.Rel(setupDirectory, f)
		if err != nil {
			return err
		}
		zipPath := filepath.ToSlash(rel)
		fw, err := zw.Create(zipPath)
		if err != nil {
			return err
		}

		// Write the file to the ZIP archive
		_, err = io.Copy(fw, file)
		if err != nil {
			return err
		}

		// Close the file at the end of the loop iteration
		// defer would close the file at the end of the function call
		file.Close()
	}

	return zw.Close()
}

// writeMetadata()
func (iw *Intunewin) writeMetadata(w io.Writer) (int, error) {
	out, err := xml.MarshalIndent(&iw.applicationInfo, " ", " ")
	if err != nil {
		return 0, err
	}
	n, err := w.Write(out)
	if err != nil {
		return n, err
	}
	return n, nil
}
