package kx

import (
	"context"

	"github.com/pkg/errors"

	"github.com/qor5/kx/api"
	"github.com/qor5/kx/awskms"
	"github.com/qor5/kx/xhmac"

	"github.com/aws/aws-sdk-go-v2/config"
)

func NewCipherFactory(kmsKeyID string) (api.CipherFactory, error) {
	awsConfig, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "failed to get aws session")
	}
	factory, err := awskms.NewCipherFactory(awsConfig, kmsKeyID)
	if err != nil {
		return nil, err
	}
	return factory, nil
}

func NewHashFactory(key string) (api.HashFactory, error) {
	keyBytes, err := DecodeKey(key)
	if err != nil {
		return nil, err
	}
	f, err := xhmac.NewHashFactory(keyBytes)
	if err != nil {
		return nil, err
	}
	return f, nil
}
