package aes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESCipher(t *testing.T) {
	// Test with different key sizes
	testKeyLengths := []int{16, 24, 32} // 128, 192, 256 bits

	for _, keyLen := range testKeyLengths {
		t.Run("KeyLength_"+string(rune(keyLen*8)), func(t *testing.T) {
			// Generate random key of specified length
			key := make([]byte, keyLen)
			_, err := rand.Read(key)
			require.NoError(t, err, "Failed to generate random key")

			// Create the cipher factory
			factory, err := NewCipherFactory(key)
			require.NoError(t, err, "Failed to create cipher factory")

			// Create encrypter and decrypter
			encrypter := factory.NewEncrypter()
			decrypter := factory.NewDecrypter()

			// Test data
			plaintext := []byte("Hello, this is a test of AES-GCM encryption!")
			ctx := context.Background()

			// Test 1: Basic encryption and decryption without context
			ciphertext, err := encrypter.Encrypt(ctx, plaintext, nil)
			require.NoError(t, err, "Encryption failed")
			assert.NotEqual(t, plaintext, ciphertext, "Ciphertext should be different from plaintext")

			// Decrypt
			decrypted, err := decrypter.Decrypt(ctx, ciphertext, nil)
			require.NoError(t, err, "Decryption failed")
			assert.Equal(t, plaintext, decrypted, "Decrypted text should match original plaintext")

			// Test 2: With encryption context
			encryptionContext := map[string]string{
				"purpose": "testing",
				"version": "1.0",
			}

			ciphertext2, err := encrypter.Encrypt(ctx, plaintext, encryptionContext)
			require.NoError(t, err, "Encryption with context failed")

			// Decrypt with same context
			decrypted2, err := decrypter.Decrypt(ctx, ciphertext2, encryptionContext)
			require.NoError(t, err, "Decryption with context failed")
			assert.Equal(t, plaintext, decrypted2, "Decrypted text with context should match original")

			// Test 3: Decrypt with incorrect context should fail
			wrongContext := map[string]string{
				"purpose": "wrong",
				"version": "2.0",
			}
			_, err = decrypter.Decrypt(ctx, ciphertext2, wrongContext)
			assert.Error(t, err, "Decryption with incorrect context should fail")

			// Test 4: Tampering with ciphertext should fail decryption
			if len(ciphertext) > 0 {
				// Modify a byte in the ciphertext (after the nonce)
				tampered := make([]byte, len(ciphertext))
				copy(tampered, ciphertext)
				nonceSize := 12 // GCM nonce size is fixed at 12 bytes
				if len(tampered) > nonceSize+1 {
					tampered[nonceSize+1] ^= 0x01 // Flip one bit
					_, err = decrypter.Decrypt(ctx, tampered, nil)
					assert.Error(t, err, "Decryption of tampered ciphertext should fail")
				}
			}
		})
	}
}

func TestInvalidKeyLength(t *testing.T) {
	// Test with invalid key lengths
	invalidLengths := []int{10, 15, 20, 31, 33}

	for _, keyLen := range invalidLengths {
		t.Run("InvalidKeyLength_"+string(rune(keyLen)), func(t *testing.T) {
			key := make([]byte, keyLen)
			_, err := rand.Read(key)
			require.NoError(t, err, "Failed to generate random key")

			// Creating factory should fail
			_, err = NewCipherFactory(key)
			assert.Error(t, err, "Should fail with invalid key length")
			assert.Contains(t, err.Error(), "invalid key length", "Error message should mention invalid key length")
		})
	}
}

func TestManualKeyGeneration(t *testing.T) {
	// Generate and print a key for manual testing
	// This shows how to generate a properly formatted key for configuration
	t.Run("GenerateKey", func(t *testing.T) {
		key := make([]byte, 32) // 256-bit key
		_, err := rand.Read(key)
		require.NoError(t, err, "Failed to generate random key")

		// Encode key as base64 for configuration
		base64Key := base64.StdEncoding.EncodeToString(key)
		t.Logf("Generated AES-256 key (base64): %s", base64Key)

		// Verify key works
		factory, err := NewCipherFactory(key)
		require.NoError(t, err, "Failed to create cipher factory")

		// Test encryption
		plaintext := []byte("Test message")
		ciphertext, err := factory.Encrypt(context.Background(), plaintext, nil)
		require.NoError(t, err, "Encryption failed")

		// Test decryption
		decrypted, err := factory.Decrypt(context.Background(), ciphertext, nil)
		require.NoError(t, err, "Decryption failed")
		assert.Equal(t, plaintext, decrypted, "Decryption should return original plaintext")
	})
}
