package awskms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/pkg/errors"
	"github.com/theplant/appkit/logtracing"

	"github.com/qor5/kx/api"
)

type CipherFactory struct {
	keyID string

	kmsCipher *kms.Client
}

// NewCipherFactory returns a CipherFactory that uses the AWS KMS key
// with the given keyID for encryption and decryption.
//
// The returned CipherFactory is safe for concurrent use by multiple
// goroutines.
//
// The caller is responsible for ensuring that the keyID refers to a
// symmetric encryption key in AWS KMS.
//
// The returned error is non-nil if s is nil, keyID is empty, or if
// there is an error creating the underlying KMS client.
// https://docs.aws.amazon.com/sdk-for-go/api/service/kms/#EncryptInput
func NewCipherFactory(cfg aws.Config, keyID string) (*CipherFactory, error) {
	if len(keyID) == 0 {
		return nil, errors.New("keyID is required")
	}

	return &CipherFactory{
		keyID:     keyID,
		kmsCipher: kms.NewFromConfig(cfg),
	}, nil
}

var _ api.CipherFactory = (*CipherFactory)(nil)

func (f *CipherFactory) NewEncrypter() api.Encrypter {
	return f
}

func (f *CipherFactory) NewDecrypter() api.Decrypter {
	return f
}

func appendContext(ctx context.Context, eCtx map[string]string) {
	var kvs []interface{}

	for k, v := range eCtx {
		kvs = append(kvs, "kms.enc_ctx."+k, v)
	}
	logtracing.AppendSpanKVs(ctx, kvs...)
}

func (f *CipherFactory) Encrypt(
	ctx context.Context, plaintext []byte, encryptionContext map[string]string,
) (ciphertext []byte, err error) {
	logtracing.AppendSpanKVs(ctx,
		"span.type", "aws.kms",
		"span.role", "client",
		"kms.key_id", f.keyID,
	)
	appendContext(ctx, encryptionContext)
	encryptOutput, err := f.kmsCipher.Encrypt(
		ctx,
		&kms.EncryptInput{
			EncryptionContext: encryptionContext,
			KeyId:             aws.String(f.keyID),
			Plaintext:         plaintext,
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt data")
	}
	return encryptOutput.CiphertextBlob, nil
}

func (f *CipherFactory) Decrypt(
	ctx context.Context, ciphertext []byte, encryptionContext map[string]string,
) (plaintext []byte, err error) {
	logtracing.AppendSpanKVs(ctx,
		"span.type", "aws.kms",
		"span.role", "client",
		"kms.key_id", f.keyID,
	)
	appendContext(ctx, encryptionContext)
	decryptOutput, err := f.kmsCipher.Decrypt(
		ctx,
		&kms.DecryptInput{
			CiphertextBlob:    ciphertext,
			EncryptionContext: encryptionContext,
			KeyId:             aws.String(f.keyID),
		},
	)
	if err != nil {
		var invalidCiphertextException *types.InvalidCiphertextException
		if errors.As(err, &invalidCiphertextException) {
			return nil, errors.WithStack(&api.InvalidCiphertextError{Err: err})
		}
		return nil, errors.WithStack(err)
	}
	return decryptOutput.Plaintext, nil
}
