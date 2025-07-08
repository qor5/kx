package kx

import (
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
)

// KeySize represents AES key sizes in bits
type KeySize int

const (
	KeySize128 KeySize = 128 // AES-128
	KeySize192 KeySize = 192 // AES-192
	KeySize256 KeySize = 256 // AES-256 (recommended)
)

// GenerateAESKey generates a secure random key for AES encryption
// Returns the key encoded as base64 for use in configuration
func GenerateAESKey(keySize KeySize) (string, error) {
	keySizeRem := int(keySize) % 8
	if keySizeRem != 0 {
		return "", errors.Errorf("invalid key size: %d bits (must be 128, 192, or 256)", keySize)
	}
	// Convert key size from bits to bytes
	keySizeBytes := int(keySize) / 8
	// Validate key size
	validKeySizes := map[int]bool{16: true, 24: true, 32: true}
	if !validKeySizes[keySizeBytes] {
		return "", errors.Errorf("invalid key size: %d bits (must be 128, 192, or 256)", keySize)
	}

	// Generate random key
	key := make([]byte, keySizeBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", errors.Wrap(err, "failed to generate random key")
	}

	// Encode as base64
	return EncodeKey(key), nil
}
