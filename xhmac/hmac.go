package xhmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"github.com/pkg/errors"

	"github.com/qor5/kx/api"
)

type HashFactory struct {
	key []byte
}

func NewHashFactory(key []byte) (api.HashFactory, error) {
	if len(key) < sha256.Size {
		return nil, errors.Errorf("key size(%d) is too short, want at least %d", len(key), sha256.Size)
	}
	return &HashFactory{
		key: key,
	}, nil
}

var _ api.HashFactory = (*HashFactory)(nil)

func (f *HashFactory) NewHash() hash.Hash {
	return hmac.New(sha256.New, f.key)
}
