package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateCodeChallenge(verifier, method string) string {
	if method == "S256" {
		h := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:])
	}
	return verifier // plain
}

func generateRandom(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
