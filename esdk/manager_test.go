package esdk_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qor5/kx"
	"github.com/qor5/kx/api"
	"github.com/qor5/kx/awskms"
	"github.com/qor5/kx/esdk"
	"github.com/qor5/kx/xhmac"
)

// reservation mirrors the shape that made this bug hard to predict: several PII
// fields on one struct, all serialised into a single blob and encrypted
// together. The size limit therefore applies to their sum, so a long Answer
// fails or succeeds depending on how long the customer's name happens to be.
type reservation struct {
	ID string

	Sei    string
	Mei    string
	Email  string
	Answer string

	HashedEmail string
}

func reservationPIIFields() []kx.StructOption {
	return []kx.StructOption{
		kx.WithRegularField("Sei", false),
		kx.WithRegularField("Mei", false),
		kx.WithRegularField("Email", true),
		kx.WithRegularField("Answer", false),
	}
}

func newManager(t *testing.T, cipherFactory api.CipherFactory) *kx.Manager {
	t.Helper()

	registry, err := kx.NewRegistry()
	require.NoError(t, err)
	require.NoError(t, registry.RegisterStruct(&reservation{}, reservationPIIFields()...))

	hashKey := make([]byte, sha256.Size)
	_, err = rand.Read(hashKey)
	require.NoError(t, err)
	hashFactory, err := xhmac.NewHashFactory(hashKey)
	require.NoError(t, err)

	manager, err := kx.NewManager(cipherFactory, hashFactory, registry)
	require.NoError(t, err)
	return manager
}

// longFormReservation builds a reservation whose PII fields sum to more than the
// KMS Encrypt limit — roughly what a customer produces by answering a store
// question at length in Japanese, where one character is three UTF-8 bytes.
func longFormReservation() *reservation {
	return &reservation{
		ID:     "res-1",
		Sei:    "山田",
		Mei:    "太郎",
		Email:  "yamada.taro@example.com",
		Answer: strings.Repeat("あ", 1400),
	}
}

func encryptionContext(r *reservation) map[string]string {
	return map[string]string{"entity": "reservation", "reservation_id": r.ID}
}

// TestManager_EncryptStruct_FieldsExceedingKMSEncryptLimit is MAD-750 reduced to
// a test: the whole struct's PII shares one 4096-byte budget, and with the
// envelope cipher that budget no longer exists.
func TestManager_EncryptStruct_FieldsExceedingKMSEncryptLimit(t *testing.T) {
	fake := newFakeKMS()
	factory, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)
	manager := newManager(t, factory)

	ctx := context.Background()
	original := longFormReservation()

	encrypted, ciphertext, err := kx.EncryptStruct(ctx, manager, original, encryptionContext(original))
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	// Plaintext fields are cleared on the encrypted copy; the hashed column is
	// populated so lookups still work without decrypting.
	assert.Empty(t, encrypted.Sei)
	assert.Empty(t, encrypted.Answer)
	assert.NotEmpty(t, encrypted.HashedEmail)

	decrypted, err := kx.DecryptStruct(ctx, manager, encrypted, ciphertext, encryptionContext(original))
	require.NoError(t, err)

	assert.Equal(t, original.Sei, decrypted.Sei)
	assert.Equal(t, original.Mei, decrypted.Mei)
	assert.Equal(t, original.Email, decrypted.Email)
	assert.Equal(t, original.Answer, decrypted.Answer)
}

// TestManager_EncryptStruct_LegacyCipherFailsOnSameInput is the control: the same
// struct through the current awskms cipher reproduces the production failure, so
// the test above is demonstrably about the fix and not about a lenient fake.
func TestManager_EncryptStruct_LegacyCipherFailsOnSameInput(t *testing.T) {
	fake := newFakeKMS()
	legacy, err := awskms.NewCipherFactory(fake.awsConfig(), testKeyARN)
	require.NoError(t, err)
	manager := newManager(t, legacy)

	original := longFormReservation()
	_, _, err = kx.EncryptStruct(context.Background(), manager, original, encryptionContext(original))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "4096")
}

// TestManager_DecryptStruct_ReadsLegacyCiphertext covers the migration path: rows
// written before the switch must stay readable afterwards, which is what makes a
// backfill unnecessary.
func TestManager_DecryptStruct_ReadsLegacyCiphertext(t *testing.T) {
	fake := newFakeKMS()

	legacy, err := awskms.NewCipherFactory(fake.awsConfig(), testKeyARN)
	require.NoError(t, err)
	envelope, err := esdk.NewCipherFactory(fake.awsConfig(), testKeyARN, esdk.WithEnvelopeWrite(true))
	require.NoError(t, err)

	ctx := context.Background()
	original := &reservation{
		ID:     "res-1",
		Sei:    "山田",
		Mei:    "太郎",
		Email:  "yamada.taro@example.com",
		Answer: "短い回答",
	}

	// Written by the old cipher...
	writer := newManager(t, legacy)
	encrypted, ciphertext, err := kx.EncryptStruct(ctx, writer, original, encryptionContext(original))
	require.NoError(t, err)

	// ...and read by the new one. The hash key differs between the two managers,
	// which is fine: the hashed column is not part of the ciphertext.
	reader := newManager(t, envelope)
	decrypted, err := kx.DecryptStruct(ctx, reader, encrypted, ciphertext, encryptionContext(original))
	require.NoError(t, err)

	assert.Equal(t, original.Sei, decrypted.Sei)
	assert.Equal(t, original.Answer, decrypted.Answer)
	assert.Equal(t, 1, fake.callCount("Encrypt"), "the legacy write must not have used GenerateDataKey")
	assert.Equal(t, 0, fake.callCount("GenerateDataKey"))
}
