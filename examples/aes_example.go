package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/qor5/kx"
)

func main() {
	// Generate or use an existing key
	// In production, you should store this key securely and use it consistently
	keySize := protection.KeySize256
	base64Key, err := protection.GenerateAESKey(keySize)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	fmt.Printf("Generated key (base64): %s\n", base64Key)

	// Create the AES cipher config
	cfg := protection.CipherConfig{
		Kind: protection.CipherKindAES,
		AES: protection.CipherAESConfig{
			Key: base64Key,
		},
	}

	// Create the cipher factory
	factory, err := protection.NewCipherFactory(cfg)
	if err != nil {
		log.Fatalf("Failed to create cipher factory: %v", err)
	}

	// Get encrypter and decrypter
	encrypter := factory.NewEncrypter()
	decrypter := factory.NewDecrypter()

	// Data to encrypt
	plaintext := []byte("Sensitive data that needs protection")
	ctx := context.Background()

	// Optional encryption context - additional authenticated data
	// This can be used to bind the ciphertext to a specific context
	encryptionContext := map[string]string{
		"application": "adex",
		"purpose":     "example",
		"user":        "admin",
	}

	// Encrypt the data
	ciphertext, err := encrypter.Encrypt(ctx, plaintext, encryptionContext)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("Encrypted (base64): %s\n", base64.StdEncoding.EncodeToString(ciphertext))

	// Decrypt the data - must use the same encryption context
	decrypted, err := decrypter.Decrypt(ctx, ciphertext, encryptionContext)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("Decrypted: %s\n", string(decrypted))

	// Demonstrate decryption failure with wrong context
	wrongContext := map[string]string{
		"application": "wrong",
		"purpose":     "wrong",
	}
	_, err = decrypter.Decrypt(ctx, ciphertext, wrongContext)
	fmt.Printf("Decryption with wrong context (expected to fail): %v\n", err)
}
