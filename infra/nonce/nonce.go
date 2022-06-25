package nonce

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

func New(length int, defaultValue string) string {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return defaultValue
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}
