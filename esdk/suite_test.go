package esdk_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qor5/kx/esdk"
)

// TestCipherFactory_DefaultSuiteIsUnsigned pins the two observable consequences
// of not signing: no aws-crypto-public-key entry is appended to the encryption
// context KMS sees, and the per-row overhead stays smaller.
//
// The KMS-side context matters beyond size — it is what a
// kms:EncryptionContext:* IAM condition key matches on, so an extra entry
// appearing there is a change in what policies have to tolerate.
func TestCipherFactory_DefaultSuiteIsUnsigned(t *testing.T) {
	ctx := context.Background()
	encCtx := reservationContext("res-abc-123")
	plaintext := []byte(strings.Repeat("x", 100))

	unsignedFake := newFakeKMS()
	unsigned, err := esdk.NewCipherFactory(unsignedFake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)
	unsignedCT, err := unsigned.Encrypt(ctx, plaintext, encCtx)
	require.NoError(t, err)

	signedFake := newFakeKMS()
	signed, err := esdk.NewCipherFactory(signedFake.awsConfig(), testKeyARN,
		esdk.WithEnvelopeWrite(true), esdk.WithSigning(true))
	require.NoError(t, err)
	signedCT, err := signed.Encrypt(ctx, plaintext, encCtx)
	require.NoError(t, err)

	require.Len(t, unsignedFake.contextsFor("GenerateDataKey"), 1)
	assert.Equal(t, encCtx, unsignedFake.contextsFor("GenerateDataKey")[0],
		"KMS must see exactly the caller's encryption context")

	require.Len(t, signedFake.contextsFor("GenerateDataKey"), 1)
	assert.Contains(t, signedFake.contextsFor("GenerateDataKey")[0], "aws-crypto-public-key",
		"signing appends a public key to the context; this is what the default avoids")

	assert.Less(t, len(unsignedCT), len(signedCT))
}

// TestCipherFactory_ReadsBothSuites is what makes WithSigning safe to flip in
// either direction on a live table: the suite lives in the message, so rows
// written under one are still readable by a factory configured for the other.
func TestCipherFactory_ReadsBothSuites(t *testing.T) {
	fake := newFakeKMS()
	ctx := context.Background()
	encCtx := reservationContext("r1")

	unsigned, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)
	signed, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN,
		esdk.WithEnvelopeWrite(true), esdk.WithSigning(true))
	require.NoError(t, err)

	unsignedCT, err := unsigned.Encrypt(ctx, []byte("written unsigned"), encCtx)
	require.NoError(t, err)
	signedCT, err := signed.Encrypt(ctx, []byte("written signed"), encCtx)
	require.NoError(t, err)

	got, err := signed.Decrypt(ctx, unsignedCT, encCtx)
	require.NoError(t, err)
	assert.Equal(t, "written unsigned", string(got))

	got, err = unsigned.Decrypt(ctx, signedCT, encCtx)
	require.NoError(t, err)
	assert.Equal(t, "written signed", string(got))
}

// TestCipherFactory_SigningStillRejectsMismatchedContext guards against the
// signed suite quietly losing the row binding, since it puts a second entry into
// the encryption context and takes a different path through header handling.
func TestCipherFactory_SigningStillRejectsMismatchedContext(t *testing.T) {
	fake := newFakeKMS()
	factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN,
		esdk.WithEnvelopeWrite(true), esdk.WithSigning(true))
	require.NoError(t, err)

	ctx := context.Background()
	ciphertext, err := factory.Encrypt(ctx, []byte("secret"), reservationContext("r1"))
	require.NoError(t, err)

	_, err = factory.Decrypt(ctx, ciphertext, reservationContext("r2"))
	require.Error(t, err)
}
