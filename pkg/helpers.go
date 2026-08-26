package pkg

import (
	"crypto/rand"
	"encoding/base64"
)

func decodeBase64Key(input string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func generateKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}
