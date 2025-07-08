package kx

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESCipherFactoryIntegration(t *testing.T) {
	// Generate a random key for testing
	key := make([]byte, 32) // 256-bit key
	for i := range key {
		key[i] = byte(i % 256)
	}

	// Encode key as base64 for configuration
	base64Key := base64.StdEncoding.EncodeToString(key)

	// Create AES cipher config
	cfg := CipherConfig{
		Kind: CipherKindAES,
		AES: CipherAESConfig{
			Key: base64Key,
		},
	}

	// Create cipher factory
	factory, err := NewCipherFactory(cfg)
	require.NoError(t, err, "Failed to create cipher factory")

	// Get encrypter and decrypter
	encrypter := factory.NewEncrypter()
	decrypter := factory.NewDecrypter()

	// Test data
	plaintext := []byte("This is a test message for AES encryption via factory")
	ctx := context.Background()

	// Test basic encryption and decryption
	ciphertext, err := encrypter.Encrypt(ctx, plaintext, nil)
	require.NoError(t, err, "Encryption failed")
	assert.NotEqual(t, plaintext, ciphertext, "Ciphertext should be different from plaintext")

	// Decrypt
	decrypted, err := decrypter.Decrypt(ctx, ciphertext, nil)
	require.NoError(t, err, "Decryption failed")
	assert.Equal(t, plaintext, decrypted, "Decrypted text should match original plaintext")

	// Test with encryption context
	encryptionContext := map[string]string{
		"application": "adex",
		"environment": "test",
	}

	ciphertext2, err := encrypter.Encrypt(ctx, plaintext, encryptionContext)
	require.NoError(t, err, "Encryption with context failed")

	// Verify that different contexts produce different ciphertexts
	assert.NotEqual(t, ciphertext, ciphertext2, "Different contexts should produce different ciphertexts")

	// Decrypt with same context
	decrypted2, err := decrypter.Decrypt(ctx, ciphertext2, encryptionContext)
	require.NoError(t, err, "Decryption with context failed")
	assert.Equal(t, plaintext, decrypted2, "Decrypted text with context should match original")

	// Test with empty key (should fail)
	invalidCfg := CipherConfig{
		Kind: CipherKindAES,
		AES: CipherAESConfig{
			Key: "",
		},
	}

	_, err = NewCipherFactory(invalidCfg)
	assert.Error(t, err, "Factory creation should fail with empty key")

	// Test with invalid key (not base64)
	invalidCfg.AES.Key = "not-base64-encoded!"
	_, err = NewCipherFactory(invalidCfg)
	assert.Error(t, err, "Factory creation should fail with invalid base64 key")
}
