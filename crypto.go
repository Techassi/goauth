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

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(s), nil
}

func randomCryptoBytes(n int) ([]byte, error) {
	s := make([]byte, n)
	_, err := rand.Read(s)
	if err != nil {
		return []byte(""), err
	}

	return s, nil
}

func bytesToString(b []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
