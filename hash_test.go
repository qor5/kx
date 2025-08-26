package kx_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/qor5/kx"
	"github.com/qor5/kx/xhmac"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashVal(t *testing.T) {
	key := make([]byte, sha256.BlockSize)
	n, err := rand.Read(key)
	require.NoError(t, err)
	require.Equal(t, sha256.BlockSize, n)
	hashFactory, err := xhmac.NewHashFactory(key)
	require.NoError(t, err)

	hashData := func(data []byte) string {
		h := hashFactory.NewHash()
		h.Write(data)
		return base64.StdEncoding.EncodeToString(h.Sum(nil))
	}

	tests := []struct {
		name    string
		val     any
		want    string
		wantErr string
	}{
		{
			name: "string value",
			val:  "Hello World",
			// nop hash factory uses sha256
			want: hashData([]byte("hello world")),
		},
		{
			name: "pointer to string",
			val:  stringPtr("Hello World"),
			want: hashData([]byte("hello world")),
		},
		{
			name: "bytes",
			val:  []byte("Hello World"),
			want: hashData([]byte("Hello World")),
		},
		{
			name: "pointer to bytes",
			val:  bytesPtr([]byte("Hello World")),
			want: hashData([]byte("Hello World")),
		},
		{
			name: "struct",
			val: struct {
				Name string
				Age  int
			}{
				Name: "John",
				Age:  30,
			},
			want: hashData(mustMarshalJSON(struct {
				Name string
				Age  int
			}{
				Name: "John",
				Age:  30,
			})),
		},
		{
			name: "slice of non-bytes",
			val:  []string{"hello", "world"},
			want: hashData(mustMarshalJSON([]string{"hello", "world"})),
		},
		{
			name: "unicode string",
			val:  "Café",
			// é is preserved in lowercase
			want: hashData([]byte("café")),
		},
		{
			name: "full width string",
			val:  "Ｈｅｌｌｏ",
			want: hashData([]byte("hello")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := kx.HashVal(hashFactory, tt.val)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func stringPtr(s string) *string {
	return &s
}

func bytesPtr(b []byte) *[]byte {
	return &b
}

func mustMarshalJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
