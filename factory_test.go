package kx

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qor5/kx/xhmac"
)

func TestNewHashFactory(t *testing.T) {
	t.Run("HMAC hash factory", func(t *testing.T) {
		factory, err := NewHashFactory(EncodeKey([]byte(strings.Repeat("a", 64))))
		require.NoError(t, err)
		assert.NotNil(t, factory)
		assert.IsType(t, &xhmac.HashFactory{}, factory)
	})

	t.Run("Invalid key", func(t *testing.T) {
		factory, err := NewHashFactory("invalid-base64-key")
		require.Error(t, err)
		assert.Nil(t, factory)
	})
}
