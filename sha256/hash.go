package sha256

import (
	"crypto/sha256"
	"hash"

	"github.com/qor5/kx/api"
)

type HashFactory struct{}

func (h *HashFactory) NewHash() hash.Hash {
	return sha256.New()
}

func NewHashFactory() api.HashFactory {
	return &HashFactory{}
}
