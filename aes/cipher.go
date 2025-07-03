package aes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"sort"
	"strings"

	"github.com/pkg/errors"

	"github.com/qor5/kx/api"
)

// CipherFactory implements api.CipherFactory for AES-GCM encryption
type CipherFactory struct {
	key []byte // AES key for encryption/decryption
	gcm cipher.AEAD
}

// NewCipherFactory creates a new AES cipher factory with the provided key
func NewCipherFactory(key []byte) (*CipherFactory, error) {
	// Validate key length (AES-128, AES-192, or AES-256)
	validKeyLengths := map[int]bool{16: true, 24: true, 32: true}
	if !validKeyLengths[len(key)] {
		return nil, errors.New("invalid key length: must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create AES cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	return &CipherFactory{
		key: key,
		gcm: gcm,
	}, nil
}

// NewEncrypter returns an encrypter instance
func (f *CipherFactory) NewEncrypter() api.Encrypter {
	return f
}

// NewDecrypter returns a decrypter instance
func (f *CipherFactory) NewDecrypter() api.Decrypter {
	return f
}

// Encrypt encrypts plaintext using AES-GCM
// The encryption context is used to derive the additional authenticated data (AAD)
func (f *CipherFactory) Encrypt(
	_ context.Context, plaintext []byte, encryptionContext map[string]string,
) ([]byte, error) {
	// Generate nonce
	nonce := make([]byte, f.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	// Derive additional authenticated data from encryptionContext if provided
	var aad []byte
	if len(encryptionContext) > 0 {
		aad = []byte(serializeContext(encryptionContext))
	}

	// Encrypt and authenticate plaintext
	// Format: nonce + ciphertext
	ciphertext := f.gcm.Seal(nonce, nonce, plaintext, aad)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-GCM
// The encryption context is used to verify the additional authenticated data (AAD)
func (f *CipherFactory) Decrypt(
	_ context.Context, ciphertext []byte, encryptionContext map[string]string,
) ([]byte, error) {
	// Verify ciphertext length
	nonceSize := f.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and actual ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Derive additional authenticated data from encryptionContext if provided
	var aad []byte
	if len(encryptionContext) > 0 {
		aad = []byte(serializeContext(encryptionContext))
	}

	// Decrypt and verify ciphertext
	plaintext, err := f.gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt: authentication failed")
	}

	return plaintext, nil
}

// serializeContext converts encryption context map to a deterministic string
// This is important for AAD to be consistent between encryption and decryption
func serializeContext(context map[string]string) string {
	if len(context) == 0 {
		return ""
	}

	// Sort keys to ensure deterministic ordering
	keys := make([]string, 0, len(context))
	for k := range context {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build result with sorted keys
	var result strings.Builder
	for _, k := range keys {
		result.WriteString(k)
		result.WriteString("=")
		result.WriteString(context[k])
		result.WriteString(";")
	}
	return result.String()
}
