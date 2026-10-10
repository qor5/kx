package esdk_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/qor5/kx/esdk"
)

func TestCtxProbe(t *testing.T) {
	fake := newFakeKMS()
	factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)

	encCtx := reservationContext("r1")
	ct, err := factory.Encrypt(context.Background(), []byte("secret"), encCtx)
	require.NoError(t, err)

	before := fake.callCount("Decrypt")

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	pt, err := factory.Decrypt(cancelled, ct, encCtx)

	t.Logf("envelope decrypt with cancelled ctx: err=%v plaintext=%q kmsDecryptCalls=%d (was %d)",
		err, pt, fake.callCount("Decrypt"), before)

	// Same question for the bare KMS path, for comparison.
	legacyFake := newFakeKMS()
	legacyFactory, err := esdk.NewCipherFactory(legacyFake.awsConfig(), testKeyARN)
	require.NoError(t, err)
	lct, err := legacyFactory.Encrypt(context.Background(), []byte("secret"), encCtx)
	require.NoError(t, err)

	c2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	_, lerr := legacyFactory.Decrypt(c2, lct, encCtx)
	t.Logf("legacy decrypt with cancelled ctx: err=%v", lerr)
}
