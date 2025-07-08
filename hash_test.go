package kx_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	psha256 "github.com/qor5/kx/sha256"
)

func TestHashVal(t *testing.T) {
	hashFactory := psha256.NewHashFactory()

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
			want: sha256Base64([]byte("hello world")),
		},
		{
			name: "pointer to string",
			val:  stringPtr("Hello World"),
			want: sha256Base64([]byte("hello world")),
		},
		{
			name: "bytes",
			val:  []byte("Hello World"),
			want: sha256Base64([]byte("Hello World")),
		},
		{
			name: "pointer to bytes",
			val:  bytesPtr([]byte("Hello World")),
			want: sha256Base64([]byte("Hello World")),
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
			want: sha256Base64(mustMarshalJSON(struct {
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
			want: sha256Base64(mustMarshalJSON([]string{"hello", "world"})),
		},
		{
			name: "unicode string",
			val:  "Café",
			// é is preserved in lowercase
			want: sha256Base64([]byte("café")),
		},
		{
			name: "full width string",
			val:  "Ｈｅｌｌｏ",
			want: sha256Base64([]byte("hello")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HashVal(hashFactory, tt.val)
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

func sha256Base64(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
