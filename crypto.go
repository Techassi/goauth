package goauth

import (
	"crypto/rand"
	"encoding/base32"
)

func randomCryptoString(n int) (string, error) {
	s := make([]byte, n)
	_, err := rand.Read(s)
	if err != nil {
		return "", err
	}

	return base32.StdEncoding.EncodeToString(s), nil
}
