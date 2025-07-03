package api

import (
	"context"
	"hash"
)

type HashFactory interface {
	NewHash() hash.Hash
}

type CipherFactory interface {
	NewEncrypter() Encrypter
	NewDecrypter() Decrypter
}

type Encrypter interface {
	// Encrypt encrypts the given plaintext using the configured key and
	// encryption context. The returned ciphertext is encrypted and encoded
	// according to the cipher factory's implementation.
	// encryptionContext in Encrypt must same as Decrypt.
	Encrypt(ctx context.Context, plaintext []byte, encryptionContext map[string]string) (ciphertext []byte, err error)
}

type Decrypter interface {
	// Decrypt decrypts the given ciphertext using the configured key and
	// encryption context. The given encryptionContext must be the same as
	// the one used when encrypting the ciphertext. Decrypt returns the
	// decrypted plaintext and an error if the given ciphertext is invalid.
	Decrypt(ctx context.Context, ciphertext []byte, encryptionContext map[string]string) (plaintext []byte, err error)
}

type InvalidCiphertextError struct {
	Err error
}

func (e *InvalidCiphertextError) Error() string {
	return e.Err.Error()
}

func (e *InvalidCiphertextError) Unwrap() error {
	return e.Err //nolint:errhandle
}
