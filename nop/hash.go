package nop

import (
	"hash"

	"github.com/qor5/kx/api"
)

type HashFactory struct{}

func (h *HashFactory) NewHash() hash.Hash {
	return NewNopHash()
}

func NewHashFactory() api.HashFactory {
	return &HashFactory{}
}

type nopHash struct {
	data []byte
}

func NewNopHash() hash.Hash {
	return &nopHash{}
}

func (n *nopHash) Write(p []byte) (int, error) {
	n.data = append(n.data, p...)
	return len(p), nil
}

func (n *nopHash) Sum(b []byte) []byte {
	return append(b, n.data...)
}

func (n *nopHash) Reset() {
	n.data = n.data[:0]
}

func (n *nopHash) Size() int {
	return len(n.data)
}

func (n *nopHash) BlockSize() int {
	return 1 // Arbitrary block size, as NOP hash doesn't have a real block size
}
