package esdk_test

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qor5/kx/api"
	"github.com/qor5/kx/awskms"
	"github.com/qor5/kx/esdk"
)

// reservationContext mirrors the shape callers actually pass: an entity
// discriminator plus a row identifier.
func reservationContext(id string) map[string]string {
	return map[string]string{"entity": "reservation", "reservation_id": id}
}

func TestFakeKMSEncodesBinaryAsBase64(t *testing.T) {
	assertBase64Binary(t)
}

// TestEnvelopePrefixDoesNotCollideWithLegacy pins the assumption format
// detection rests on: a ciphertext written by awskms never starts with the
// envelope prefix, so an unprefixed ciphertext can always be read as legacy.
func TestEnvelopePrefixDoesNotCollideWithLegacy(t *testing.T) {
	fake := newFakeKMS()
	legacy, err := awskms.NewCipherFactory(fake.awsConfig(), testKeyARN)
	require.NoError(t, err)

	ciphertext, err := legacy.Encrypt(context.Background(), []byte("hello"), reservationContext("r1"))
	require.NoError(t, err)

	require.NotEmpty(t, ciphertext)
	assert.EqualValues(t, 0x01, ciphertext[0], "legacy ciphertext must start with the KMS format version")

	// The envelope factory must route this to the legacy path.
	factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)
	plaintext, err := factory.Decrypt(context.Background(), ciphertext, reservationContext("r1"))
	require.NoError(t, err)
	assert.Equal(t, "hello", string(plaintext))
}

// TestCipherFactory_RoundTripsPlaintextLargerThanKMSEncryptLimit is the contract
// this package exists to satisfy. The assertion is on size alone — any
// implementation that stops handing whole plaintexts to kms:Encrypt passes.
func TestCipherFactory_RoundTripsPlaintextLargerThanKMSEncryptLimit(t *testing.T) {
	fake := newFakeKMS()
	factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)

	ctx := context.Background()
	encCtx := reservationContext("r1")

	// 1400 Japanese characters is ~4200 UTF-8 bytes: past the limit, and close
	// to the length a customer can reach in the reservation free-text fields.
	plaintext := []byte(strings.Repeat("あ", 1400))
	require.Greater(t, len(plaintext), kmsEncryptPlaintextLimit)

	ciphertext, err := factory.Encrypt(ctx, plaintext, encCtx)
	require.NoError(t, err)

	got, err := factory.Decrypt(ctx, ciphertext, encCtx)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// TestCipherFactory_RoundTripsAnySize covers the sizes around and far beyond the
// KMS limit, including the empty plaintext.
func TestCipherFactory_RoundTripsAnySize(t *testing.T) {
	fake := newFakeKMS()
	factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)

	for _, size := range []int{0, 1, 4095, 4096, 4097, 64 * 1024, 1024 * 1024} {
		t.Run(sizeName(size), func(t *testing.T) {
			ctx := context.Background()
			encCtx := reservationContext("r1")
			plaintext := []byte(strings.Repeat("x", size))

			ciphertext, err := factory.Encrypt(ctx, plaintext, encCtx)
			require.NoError(t, err)

			got, err := factory.Decrypt(ctx, ciphertext, encCtx)
			require.NoError(t, err)
			assert.Len(t, got, size)
			assert.Equal(t, plaintext, got)
		})
	}
}

// TestCipherFactory_EncryptUsesGenerateDataKey verifies the envelope path calls
// GenerateDataKey and never puts the payload through kms:Encrypt — the latter is
// what imposes the 4096-byte cap.
func TestCipherFactory_EncryptUsesGenerateDataKey(t *testing.T) {
	fake := newFakeKMS()
	factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)

	_, err = factory.Encrypt(context.Background(), []byte(strings.Repeat("x", 10000)), reservationContext("r1"))
	require.NoError(t, err)

	assert.Equal(t, 1, fake.callCount("GenerateDataKey"))
	assert.Equal(t, 0, fake.callCount("Encrypt"))
}

// TestCipherFactory_DecryptRejectsMismatchedEncryptionContext is the guard that
// the migration must not weaken. awskms inherits it from kms:Decrypt, which
// refuses a mismatched encryption context outright. The Encryption SDK does not
// compare contexts by default, so this passes only because the factory seals
// every context entry as required authenticated data.
func TestCipherFactory_DecryptRejectsMismatchedEncryptionContext(t *testing.T) {
	fake := newFakeKMS()
	factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)

	ctx := context.Background()
	ciphertext, err := factory.Encrypt(ctx, []byte("secret"), reservationContext("r1"))
	require.NoError(t, err)

	t.Run("different row", func(t *testing.T) {
		_, err := factory.Decrypt(ctx, ciphertext, reservationContext("r2"))
		require.Error(t, err)
		var invalid *api.InvalidCiphertextError
		assert.ErrorAs(t, err, &invalid, "a ciphertext from another row must not decrypt")
	})

	t.Run("different entity", func(t *testing.T) {
		_, err := factory.Decrypt(ctx, ciphertext, map[string]string{"entity": "participant", "reservation_id": "r1"})
		require.Error(t, err)
		var invalid *api.InvalidCiphertextError
		assert.ErrorAs(t, err, &invalid)
	})

	t.Run("missing key", func(t *testing.T) {
		_, err := factory.Decrypt(ctx, ciphertext, map[string]string{"entity": "reservation"})
		require.Error(t, err)
	})

	t.Run("matching context still works", func(t *testing.T) {
		got, err := factory.Decrypt(ctx, ciphertext, reservationContext("r1"))
		require.NoError(t, err)
		assert.Equal(t, "secret", string(got))
	})
}

// TestCipherFactory_EncryptDoesNotStoreEncryptionContextInMessage is the direct
// evidence that the required-encryption-context manager is doing the work: with
// the Encryption SDK's default manager the context would be serialised into the
// message header in the clear. Keeping it out is what forces the caller to
// supply a matching context on decrypt, and it also stops row identifiers from
// being persisted in plaintext alongside the ciphertext.
func TestCipherFactory_EncryptDoesNotStoreEncryptionContextInMessage(t *testing.T) {
	fake := newFakeKMS()
	factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)

	ciphertext, err := factory.Encrypt(context.Background(), []byte("secret"), reservationContext("res-abc-123"))
	require.NoError(t, err)

	assert.NotContains(t, string(ciphertext), "reservation_id")
	assert.NotContains(t, string(ciphertext), "res-abc-123")
}

// TestCipherFactory_DefaultsToLegacyWrite is the compatibility guarantee that
// lets every downstream repository take this dependency without coordinating a
// rollout: adopting the factory changes nothing about what gets stored, and
// requires no new IAM permission, until envelope writes are switched on.
func TestCipherFactory_DefaultsToLegacyWrite(t *testing.T) {
	fake := newFakeKMS()
	factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN)
	require.NoError(t, err)

	ctx := context.Background()
	encCtx := reservationContext("r1")

	ciphertext, err := factory.Encrypt(ctx, []byte("hello"), encCtx)
	require.NoError(t, err)

	assert.Equal(t, 1, fake.callCount("Encrypt"), "default writes must still go through kms:Encrypt")
	assert.Equal(t, 0, fake.callCount("GenerateDataKey"), "default writes must not need kms:GenerateDataKey")

	// Byte-identical to what awskms alone would have produced.
	legacy, err := awskms.NewCipherFactory(fake.awsConfig(), testKeyARN)
	require.NoError(t, err)
	got, err := legacy.Decrypt(ctx, ciphertext, encCtx)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))

	// And it still reads envelope ciphertexts written by a peer that has them on.
	envelope, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)
	envelopeCiphertext, err := envelope.Encrypt(ctx, []byte(strings.Repeat("x", 10000)), encCtx)
	require.NoError(t, err)

	got, err = factory.Decrypt(ctx, envelopeCiphertext, encCtx)
	require.NoError(t, err)
	assert.Len(t, got, 10000)
}

// TestCipherFactory_LegacyWriteStillHitsKMSLimit is the control: with envelope
// writes off the 4096-byte failure is unchanged, so the test above proves the
// envelope path is what fixed it rather than a lenient fake.
func TestCipherFactory_LegacyWriteStillHitsKMSLimit(t *testing.T) {
	fake := newFakeKMS()
	factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN)
	require.NoError(t, err)

	_, err = factory.Encrypt(context.Background(), []byte(strings.Repeat("x", 4097)), reservationContext("r1"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "4096")
}

// TestCipherFactory_ClassifiesErrors checks the two failure modes callers act on
// differently. Conflating them is how a missing kms:GenerateDataKey permission
// would get misreported as corrupt data.
func TestCipherFactory_ClassifiesErrors(t *testing.T) {
	ctx := context.Background()
	encCtx := reservationContext("r1")

	t.Run("access denied is not a ciphertext problem", func(t *testing.T) {
		fake := newFakeKMS()
		factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
		require.NoError(t, err)

		ciphertext, err := factory.Encrypt(ctx, []byte("secret"), encCtx)
		require.NoError(t, err)

		fake.failOnce("Decrypt", kmsError{
			status:  400,
			errType: "AccessDeniedException",
			message: "User is not authorized to perform kms:Decrypt",
		})

		_, err = factory.Decrypt(ctx, ciphertext, encCtx)
		require.Error(t, err)
		var invalid *api.InvalidCiphertextError
		assert.NotErrorAs(t, err, &invalid, "an authorization failure must not be reported as invalid ciphertext")
	})

	t.Run("corrupt ciphertext is a ciphertext problem", func(t *testing.T) {
		fake := newFakeKMS()
		factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
		require.NoError(t, err)

		ciphertext, err := factory.Encrypt(ctx, []byte("secret"), encCtx)
		require.NoError(t, err)
		ciphertext[len(ciphertext)-1] ^= 0xFF

		_, err = factory.Decrypt(ctx, ciphertext, encCtx)
		require.Error(t, err)
		var invalid *api.InvalidCiphertextError
		assert.ErrorAs(t, err, &invalid)
	})
}

// TestNewCipherFactory_EnvelopeWriteRequiresKeyARN covers a trap the Encryption
// SDK sets: its keyring matches the key ARN recorded in a message against the
// configured key on decrypt, so an alias encrypts fine and then cannot read back
// what it wrote. Failing at construction keeps unreadable rows out of the
// database.
//
// The check is scoped to envelope writes so that adopting this package stays
// inert for deployments still configured with an alias — awskms resolves aliases
// server-side and does not care.
func TestNewCipherFactory_EnvelopeWriteRequiresKeyARN(t *testing.T) {
	fake := newFakeKMS()
	const alias = "alias/mad-test-biz-pii"

	t.Run("envelope write rejects an alias", func(t *testing.T) {
		_, err := esdk.NewCipherFactory(fake.awsConfig(), alias, esdk.WithEnvelopeWrite(true))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ARN")
	})

	t.Run("alias still works without envelope writes", func(t *testing.T) {
		factory, err := esdk.NewCipherFactory(fake.awsConfig(), alias)
		require.NoError(t, err)

		ctx := context.Background()
		encCtx := reservationContext("r1")
		ciphertext, err := factory.Encrypt(ctx, []byte("hello"), encCtx)
		require.NoError(t, err)

		got, err := factory.Decrypt(ctx, ciphertext, encCtx)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(got))
	})

	t.Run("key ARN is accepted", func(t *testing.T) {
		_, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
		require.NoError(t, err)
	})
}

// TestCipherFactory_Concurrent backs the concurrency-safety promise in
// CipherFactory's doc comment: concurrent envelope operations produce correct
// results.
//
// It deliberately asserts on results rather than running under -race. The
// Encryption SDK's transpiled Dafny code races on a package-level singleton by
// writing the constant true to it, with no reader anywhere (see CipherFactory's
// doc comment), so -race here would report upstream's write and prove nothing
// about this package. What can go wrong and stay invisible is a wrong plaintext,
// which is what these assertions catch.
//
// Two shapes: goroutines sharing one factory (what DecryptStructs does), and
// goroutines each building their own.
func TestCipherFactory_Concurrent(t *testing.T) {
	const goroutines = 16

	t.Run("shared factory", func(t *testing.T) {
		fake := newFakeKMS()
		factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
		require.NoError(t, err)

		ctx := context.Background()
		seeds := make([][]byte, goroutines)
		for i := range seeds {
			seeds[i], err = factory.Encrypt(ctx, []byte("hello"), reservationContext(strconv.Itoa(i)))
			require.NoError(t, err)
		}

		var wg sync.WaitGroup
		for i := range seeds {
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, err := factory.Encrypt(ctx, []byte("hello"), reservationContext(strconv.Itoa(i)))
				assert.NoError(t, err)
			}()
			go func() {
				defer wg.Done()
				got, err := factory.Decrypt(ctx, seeds[i], reservationContext(strconv.Itoa(i)))
				if assert.NoError(t, err) {
					assert.Equal(t, "hello", string(got))
				}
			}()
		}
		wg.Wait()
	})

	t.Run("one factory per goroutine", func(t *testing.T) {
		fake := newFakeKMS()
		ctx := context.Background()

		var wg sync.WaitGroup
		for i := range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
				if !assert.NoError(t, err) {
					return
				}
				encCtx := reservationContext(strconv.Itoa(i))
				ciphertext, err := factory.Encrypt(ctx, []byte("hello"), encCtx)
				if !assert.NoError(t, err) {
					return
				}
				got, err := factory.Decrypt(ctx, ciphertext, encCtx)
				if assert.NoError(t, err) {
					assert.Equal(t, "hello", string(got))
				}
			}()
		}
		wg.Wait()
	})
}

func TestNewCipherFactory_RequiresKeyID(t *testing.T) {
	_, err := esdk.NewCipherFactory(newFakeKMS().awsConfig(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keyID is required")
}

func sizeName(size int) string {
	return strconv.Itoa(size) + "-bytes"
}
