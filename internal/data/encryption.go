package data

type Profile string

const (
	ProfileVersion1 Profile = "ProfileVersion1"
)

type EncryptionInfo struct {
	Key                  string  `xml:"EncryptionKey"`        // 32 byte AES key
	MacKey               string  `xml:"MacKey"`               // 32 byte HMAC key
	InitializationVector string  `xml:"InitializationVector"` // IV for the AES encryption
	Mac                  string  `xml:"Mac"`                  // HMAC hash of the encrypted file
	ProfileIdentifier    Profile `xml:"ProfileIdentifier"`
	FileDigest           string  `xml:"FileDigest"`          // hash of the unencrypted file
	FileDigestAlgorithm  string  `xml:"FileDigestAlgorithm"` // hash algorithm used for the FileDigest SHA256 is the default
}
