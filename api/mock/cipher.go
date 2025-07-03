package mock

import (
	"context"
	"fmt"

	"github.com/pkg/errors"

	"github.com/qor5/kx/api"
)

type CipherFactory struct {
	encrypter api.Encrypter
	decrypter api.Decrypter
}

func NewCipherFactory() *CipherFactory {
	return &CipherFactory{
		encrypter: &Encrypter{},
		decrypter: &Decrypter{},
	}
}

func (f *CipherFactory) NewEncrypter() api.Encrypter {
	return f.encrypter
}

func (f *CipherFactory) NewDecrypter() api.Decrypter {
	return f.decrypter
}

type Encrypter struct{}

func (e *Encrypter) Encrypt(_ context.Context, plaintext []byte, _ map[string]string) ([]byte, error) {
	return []byte(fmt.Sprintf("ENC(%s)", plaintext)), nil
}

type Decrypter struct{}

func (d *Decrypter) Decrypt(_ context.Context, ciphertext []byte, _ map[string]string) ([]byte, error) {
	if len(ciphertext) < 5 || string(ciphertext[:4]) != "ENC(" || ciphertext[len(ciphertext)-1] != ')' {
		return nil, errors.Errorf("invalid ciphertext format")
	}
	return ciphertext[4 : len(ciphertext)-1], nil
}
