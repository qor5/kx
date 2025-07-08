package kx

import (
	"github.com/samber/lo"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qor5/kx/aes"
	"github.com/qor5/kx/awskms"

	"github.com/qor5/kx/nop"
	"github.com/qor5/kx/xhmac"
)

func TestNewCipherFactory(t *testing.T) {
	t.Run("NOP cipher", func(t *testing.T) {
		config := CipherConfig{
			Kind: CipherKindNOP,
		}
		factory, err := NewCipherFactory(config)
		require.NoError(t, err)
		assert.IsType(t, &nop.CipherFactory{}, factory)
	})

	t.Run("KMS cipher", func(t *testing.T) {
		config := CipherConfig{
			Kind: CipherKindKMS,
			KMS: CipherKMSConfig{
				KeyID: "test-key-id",
			},
		}
		factory, err := NewCipherFactory(config)
		require.NoError(t, err)
		assert.IsType(t, &awskms.CipherFactory{}, factory)
	})

	t.Run("AES cipher", func(t *testing.T) {
		config := CipherConfig{
			Kind: CipherKindAES,
			AES: CipherAESConfig{
				Key: lo.Must1(GenerateAESKey(KeySize128)),
			},
		}
		factory, err := NewCipherFactory(config)
		require.NoError(t, err)
		assert.IsType(t, &aes.CipherFactory{}, factory)
	})

	t.Run("Unknown cipher type", func(t *testing.T) {
		config := CipherConfig{
			Kind: "unknown",
		}
		_, err := NewCipherFactory(config)
		assert.EqualError(t, err, "unknown cipher type: unknown")
	})
}

func TestNewHashFactory(t *testing.T) {
	t.Run("HMAC hash factory", func(t *testing.T) {
		config := HasherConfig{
			Kind: HasherKindHMAC,
			HMAC: HasherHMACConfig{
				Key: EncodeKey([]byte(strings.Repeat("a", 64))),
			},
		}
		factory, err := NewHashFactory(config)
		require.NoError(t, err)
		assert.NotNil(t, factory)
		assert.IsType(t, &xhmac.HashFactory{}, factory)
	})

	t.Run("NOP hash factory", func(t *testing.T) {
		config := HasherConfig{
			Kind: HasherKindNOP,
		}
		factory, err := NewHashFactory(config)
		require.NoError(t, err)
		assert.NotNil(t, factory)
		assert.IsType(t, &nop.HashFactory{}, factory)
	})

	t.Run("Invalid key", func(t *testing.T) {
		config := HasherConfig{
			Kind: HasherKindHMAC,
			HMAC: HasherHMACConfig{
				Key: "invalid-base64-key",
			},
		}
		factory, err := NewHashFactory(config)
		require.Error(t, err)
		assert.Nil(t, factory)
	})

	t.Run("Unknown hash type", func(t *testing.T) {
		config := HasherConfig{
			Kind: "unknown",
		}
		factory, err := NewHashFactory(config)
		require.Error(t, err)
		assert.Nil(t, factory)
		assert.Contains(t, err.Error(), "unknown hash type: unknown")
	})
}
