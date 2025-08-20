package kx

import (
	"context"

	"github.com/pkg/errors"

	"github.com/qor5/kx/aes"
	"github.com/qor5/kx/api"
	"github.com/qor5/kx/awskms"
	"github.com/qor5/kx/nop"
	"github.com/qor5/kx/xhmac"

	"github.com/aws/aws-sdk-go-v2/config"
)

func NewCipherFactory(cfg CipherConfig) (api.CipherFactory, error) {
	switch cfg.Kind {
	case CipherKindNOP:
		return nop.NewCipherFactory(), nil
	case CipherKindKMS:
		awsConfig, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, errors.Wrap(err, "failed to get aws session")
		}
		factory, err := awskms.NewCipherFactory(awsConfig, cfg.KMS.KeyID)
		if err != nil {
			return nil, err
		}
		return factory, nil
	case CipherKindAES:
		if cfg.AES.Key == "" {
			return nil, errors.New("AES key is required")
		}
		decodedKey, err := DecodeKey(cfg.AES.Key)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode AES key")
		}

		// Create AES cipher factory
		factory, err := aes.NewCipherFactory(decodedKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create AES cipher factory")
		}
		return factory, nil
	default:
		return nil, errors.Errorf("unknown cipher type: %s", cfg.Kind)
	}
}

func NewHashFactory(config HasherConfig) (api.HashFactory, error) {
	switch config.Kind {
	case HasherKindHMAC:
		keyBytes, err := DecodeKey(config.HMAC.Key)
		if err != nil {
			return nil, err
		}
		f, err := xhmac.NewHashFactory(keyBytes)
		if err != nil {
			return nil, err
		}
		return f, nil
	case HasherKindNOP:
		return nop.NewHashFactory(), nil
	default:
		return nil, errors.Errorf("unknown hash type: %s", config.Kind)
	}
}
