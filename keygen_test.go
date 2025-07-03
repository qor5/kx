package protection

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAESKey(t *testing.T) {
	type args struct {
		keySize KeySize
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "AES-128",
			args:    args{keySize: KeySize128},
			wantErr: assert.NoError,
		},
		{
			name:    "AES-192",
			args:    args{keySize: KeySize192},
			wantErr: assert.NoError,
		},
		{
			name:    "AES-256",
			args:    args{keySize: KeySize256},
			wantErr: assert.NoError,
		},
		{
			name:    "invalid key size",
			args:    args{keySize: KeySize128 + 1},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateAESKey(tt.args.keySize)
			if !tt.wantErr(t, err, fmt.Sprintf("GenerateAESKey(%v)", tt.args.keySize)) {
				return
			}
		})
	}
}
