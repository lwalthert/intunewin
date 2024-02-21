package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
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
)

type Intunewin struct {
	Name        string               // The name of the intunewin file
	Path        string               // The path to the Intunewin file
	metadata    data.ApplicationInfo // the metadata of the intunewin file
	contentFile string               // The path to the content file
	aesKey      []byte
	aesIV       []byte
	macKey      []byte
}

func NewIntunewin(contentPath, setupFile, outputPath string) (*Intunewin, error) {
	iw := new(Intunewin)
	iw.metadata = *data.NewApplicationInfo(toolVersion)
	// Check setup path
	if !validator.PathIsValid(contentPath, validator.Directory) {
		// TODO
		return nil, nil
	}
	log.Printf("Content Directory: %q", contentPath)

	setupPath := path.Join(contentPath, setupFile)
	if !validator.PathIsValid(setupPath, validator.File) {
		// TODO

		return nil, nil
	}

	iw.metadata.SetupFile = path.Base(setupPath)

	log.Printf("Setup File Path: %q", setupPath)
	log.Printf("Setup File Name: %q", iw.metadata.SetupFile)

	setupName := strings.TrimSuffix(iw.metadata.SetupFile, path.Ext(iw.metadata.SetupFile))
	if setupName == "" {
		// TODO
		return nil, nil
	}

	// TODO handle msi setup files
	iw.Name = setupName // set

	// Create the name of the output file
	iw.metadata.FileName = setupName + ".intunewin"
	iw.Path = path.Join(outputPath, iw.metadata.FileName)
	output, err := os.Create(iw.Path)
	if err != nil {
		return nil, err
	}

	defer output.Close()

	// Generate random key and IV
	iv, err := generateKey(16)
	if err != nil {
		return nil, err
	}
	iw.aesIV = iv
	iw.metadata.EncryptionInfo.InitializationVector = base64.RawStdEncoding.EncodeToString(iw.aesIV)
	aesKey, err := generateKey(32)
	if err != nil {
		return nil, err
	}
	iw.aesKey = aesKey
	iw.metadata.EncryptionInfo.Key = base64.RawStdEncoding.EncodeToString(iw.aesKey)
	macKey, err := generateKey(32)
	if err != nil {
		return nil, err
	}
	iw.macKey = macKey
	iw.metadata.EncryptionInfo.MacKey = base64.RawStdEncoding.EncodeToString(iw.macKey)

	iw.metadata.EncryptionInfo.ProfileIdentifier = data.ProfileVersion1

	// Package the content file
	contentArchive, err := os.CreateTemp("", "IntunePackage*.zip")
	if err != nil {
		return nil, err
	}

	defer os.Remove(contentArchive.Name())

	err = createContentArchive(contentPath, contentArchive)
	if err != nil {
		return nil, err
	}

	caStat, err := contentArchive.Stat()
	if err != nil {
		return nil, err
	}
	iw.metadata.UnencryptedContentSize = int(caStat.Size())
	archiveHash, err := sha256FileHash(contentArchive)
	if err != nil {
		return nil, err
	}
	iw.metadata.EncryptionInfo.FileDigest = archiveHash
	iw.metadata.EncryptionInfo.FileDigestAlgorithm = "SHA256"

	// Encrypt the archive
	encryptedContent, err := os.CreateTemp("", "IntunePackage*.intunewin")
	if err != nil {
		return nil, err
	}

	defer os.Remove(encryptedContent.Name())

	_, err = contentArchive.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	mac, err := iw.encryptContentArchive(contentArchive, encryptedContent)
	if err != nil {
		return nil, err
	}

	iw.metadata.EncryptionInfo.Mac = mac

	_, err = encryptedContent.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	// Write to zip
	zipWriter := zip.NewWriter(output)

	defer zipWriter.Close()

	// Write Content
	path := path.Join(contentsDir, outputFileName)
	fileWriter, err := zipWriter.Create(path)
	if err != nil {
		return nil, err
	}

	_, err = writeFileToZIP(encryptedContent, fileWriter)
	if err != nil {
		return nil, err
	}

	// Write Metadata
	fileWriter, err = zipWriter.Create(metadataFile)
	if err != nil {
		return nil, err
	}

	iw.writeMetadata(fileWriter)

	return iw, nil
}

func Extract(file string) error {
	var intunewin Intunewin

	intunewin.Open(file)

	return nil
}

func (iw *Intunewin) Open(file string) error {
	// Open the intunewin archive for reading.
	r, err := zip.OpenReader(file)
	if err != nil {
		// TODO
		log.Fatal(err)
	}

	defer r.Close()

	// Open the file 'IntuneWinPackage/Metadata/Detection.xml' for deserialization.
	f, err := r.Open(metadataFile)
	if err != nil {
		// TODO
		panic(err)
	}
	defer f.Close()

	// Decode the xml
	dec := xml.NewDecoder(f)
	err = dec.Decode(&iw.metadata)
	if err != nil {
		panic(err)
	}

	// Set the variable contentfile
	iw.contentFile = path.Join("IntuneWinPackage/Contents/", iw.metadata.FileName)

	content, err := r.Open(iw.contentFile)
	if err != nil {
		panic(err)
	}
	defer content.Close()

	output, err := os.OpenFile(iw.metadata.FileName, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	defer output.Close()

	macVerified, err := iw.VerifyMac(content)
	if err != nil {
		panic(err)
	}

	if !macVerified {
		return errors.New("HMAC doesn't match")
	}
	content.Close()

	content, err = r.Open(iw.contentFile)
	if err != nil {
		panic(err)
	}
	defer content.Close()

	iw.ReadContent(content, output)

	return nil
}

func (iw *Intunewin) ReadContent(input io.Reader, output io.Writer) error {
	aesKey, err := decodeBase64Key(iw.metadata.EncryptionInfo.Key)
	if err != nil {
		return err
	}

	aesIV, err := decodeBase64Key(iw.metadata.EncryptionInfo.InitializationVector)
	if err != nil {
		return err
	}

	// Create the AES block
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}

	// Create a reader for the input and discard the first 48 bytes (MAC + IV)
	reader := bufio.NewReader(input)
	_, err = reader.Discard(48)
	if err != nil && err != io.EOF {
		panic(err)
	}

	// Create a CBC decrypter
	decrypter := cipher.NewCBCDecrypter(block, aesIV)

	buf := make([]byte, 0, 2097152)
	for {
		n, err := io.ReadFull(reader, buf[:cap(buf)])
		buf = buf[:n]
		if err != nil {
			if err == io.EOF {
				break // Reached end of file
			}
			if err != io.ErrUnexpectedEOF {
				fmt.Fprintln(os.Stderr, err)
				break
			}
		}

		decrypter.CryptBlocks(buf[:n], buf[:n])
		_, err = output.Write(buf)
		if err != nil {
			return nil
		}
	}

	// TODO
	// https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.2 remove padding

	return nil
}

func (iw *Intunewin) VerifyMac(input io.Reader) (bool, error) {
	key, err := decodeBase64Key(iw.metadata.EncryptionInfo.MacKey)
	if err != nil {
		panic(err)
	}
	contentMAC, err := decodeBase64Key(iw.metadata.EncryptionInfo.Mac)
	if err != nil {
		panic(err)
	}

	mac := hmac.New(sha256.New, key)

	reader := bufio.NewReader(input)
	_, err = reader.Discard(32) // Skip the first 32 bytes that contain the HMAC
	if err != nil {
		return false, err
	}

	buf := make([]byte, 0, 2097152)
	for {
		n, err := io.ReadFull(reader, buf[:cap(buf)])
		buf = buf[:n]
		if err != nil {
			if err == io.EOF {
				break // Reached end of file
			}
			if err != io.ErrUnexpectedEOF {
				fmt.Fprintln(os.Stderr, err)
				break
			}
		}
		mac.Write(buf)
	}

	expectedMAC := mac.Sum(nil)

	return hmac.Equal(expectedMAC, contentMAC), nil
}

// Create the archive first because
// We need to know the length of the archive to encrypt it because we use AES CBC
// and might need to add padding to the end of the file.
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
		// Open the file
		file, err := os.Open(f)
		if err != nil {
			panic(err)
		}

		partialPath, ok := strings.CutPrefix(f, setupDirectory)
		if !ok {
			log.Panicf("Couldn't remove prefix\n")
		}

		partialPath, _ = strings.CutPrefix(partialPath, "/")

		fw, err := zw.CreateHeader(&zip.FileHeader{
			Name:   partialPath,
			Method: zip.Store,
		})

		if err != nil {
			log.Panicf(err.Error())
		}

		// Write the file to the ZIP archive
		writeFileToZIP(file, fw)

		// Close the file at the end of the loop iteration
		// defer would close the file at the end of the function call
		file.Close()
	}

	return nil
}

// encryptContentArchive encrypts the file
func (iw *Intunewin) encryptContentArchive(input *os.File, output *os.File) (string, error) {
	// Jump ahead to make room for the HMAC at the start of the file
	output.Seek(32, 0)

	// Create the hmac hash
	mac := hmac.New(sha256.New, iw.macKey)

	// Create a new AESCBCWriter
	block, err := aes.NewCipher(iw.aesKey)
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCEncrypter(block, iw.aesIV)

	// Write the IV to the file and pass it to the hash function
	output.Write(iw.aesIV)
	mac.Write(iw.aesIV)

	blockSize := int(block.BlockSize())
	buf := make([]byte, 0, 2097152)
	for {
		n, err := io.ReadFull(input, buf[:cap(buf)])
		padding := n % blockSize
		if padding != 0 {
			log.Print(n)
			log.Print(padding)
			// Append padding to the buffer in the PKCS#7 format
			// https://datatracker.ietf.org/doc/html/rfc5652#section-6.3
			padding = blockSize - padding
			buf = append(buf[:n], bytes.Repeat([]byte{byte(padding)}, padding)...)
			n = n + padding
		}
		buf = buf[:n]
		if err != nil {
			if err == io.EOF {
				break // Reached end of file
			}
			if err != io.ErrUnexpectedEOF {
				fmt.Fprintln(os.Stderr, err)
				break
			}
		}

		blockMode.CryptBlocks(buf[:n], buf[:n])

		_, err = output.Write(buf)
		if err != nil {
			return "", err
		}
		_, err = mac.Write(buf)
		if err != nil {
			return "", err
		}
	}

	// Calculate the HMAC and write it to the beginning of the file
	hmac := mac.Sum(nil)
	log.Print(hmac)
	_, err = output.WriteAt(hmac, 0)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(hmac), nil
}

// writeMetadata()
func (iw *Intunewin) writeMetadata(w io.Writer) (int, error) {
	out, err := xml.MarshalIndent(&iw.metadata, " ", " ")
	if err != nil {
		return 0, err
	}
	n, err := w.Write(out)
	if err != nil {
		return n, err
	}
	return n, nil
}
