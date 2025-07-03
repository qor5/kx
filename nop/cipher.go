package nop

import (
	"context"

	"github.com/qor5/kx/api"
)

var _ api.CipherFactory = (*CipherFactory)(nil)

type CipherFactory struct{}

func NewCipherFactory() *CipherFactory {
	return &CipherFactory{}
}

func (*CipherFactory) NewEncrypter() api.Encrypter {
	return &Encrypter{}
}

func (*CipherFactory) NewDecrypter() api.Decrypter {
	return &Decrypter{}
}

type Encrypter struct{}

func (*Encrypter) Encrypt(_ context.Context, plaintext []byte, _ map[string]string) (ciphertext []byte, err error) {
	return plaintext, nil
}

type Decrypter struct{}

func (*Decrypter) Decrypt(_ context.Context, ciphertext []byte, _ map[string]string) (plaintext []byte, err error) {
	return ciphertext, nil
}
