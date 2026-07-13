package kx_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qor5/kx"
	"github.com/qor5/kx/api/mock"
	"github.com/qor5/kx/xhmac"
)

type batchUser struct {
	Name       string
	HashedName string
}

func newBatchManager(t *testing.T) *kx.Manager {
	t.Helper()
	registry, err := kx.NewRegistry()
	require.NoError(t, err)
	registry.MustRegisterStruct(batchUser{}, kx.WithRegularField("Name", true))

	hashFactory, err := xhmac.NewHashFactory(getHashKey(t))
	require.NoError(t, err)

	m, err := kx.NewManager(mock.NewCipherFactory(), hashFactory, registry)
	require.NoError(t, err)
	return m
}

func mustEncryptBatchUser(t *testing.T, m *kx.Manager, name string) kx.DecryptItem[*batchUser] {
	t.Helper()
	encCtx := map[string]string{"id": name}
	encrypted, ciphertext, err := kx.EncryptStruct(ctx, m, &batchUser{Name: name}, encCtx)
	require.NoError(t, err)
	return kx.DecryptItem[*batchUser]{
		EncryptedObj:      encrypted,
		Ciphertext:        ciphertext,
		EncryptionContext: encCtx,
	}
}

func TestDecryptStructs(t *testing.T) {
	// Run with -race to catch any accidental sharing between decrypt goroutines.
	t.Run("round_trip_preserves_order", func(t *testing.T) {
		m := newBatchManager(t)

		const n = 50
		items := make([]kx.DecryptItem[*batchUser], n)
		for i := range items {
			items[i] = mustEncryptBatchUser(t, m, fmt.Sprintf("user-%d", i))
		}

		got, err := kx.DecryptStructs(ctx, m, items)
		require.NoError(t, err)
		require.Len(t, got, n)
		for i := range got {
			assert.Equal(t, fmt.Sprintf("user-%d", i), got[i].Name)
		}
	})

	t.Run("empty_returns_nil", func(t *testing.T) {
		m := newBatchManager(t)

		got, err := kx.DecryptStructs[*batchUser](ctx, m, nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("concurrency_one_preserves_order", func(t *testing.T) {
		m := newBatchManager(t)

		items := make([]kx.DecryptItem[*batchUser], 10)
		for i := range items {
			items[i] = mustEncryptBatchUser(t, m, fmt.Sprintf("u%d", i))
		}

		got, err := kx.DecryptStructs(ctx, m, items, kx.WithConcurrency(1))
		require.NoError(t, err)
		require.Len(t, got, len(items))
		for i := range got {
			assert.Equal(t, fmt.Sprintf("u%d", i), got[i].Name)
		}
	})

	t.Run("concurrency_larger_than_items", func(t *testing.T) {
		m := newBatchManager(t)

		items := []kx.DecryptItem[*batchUser]{
			mustEncryptBatchUser(t, m, "a"),
			mustEncryptBatchUser(t, m, "b"),
		}

		// WithConcurrency(0) is ignored (default used); a huge value is capped
		// to len(items) internally — both must still succeed and preserve order.
		got, err := kx.DecryptStructs(ctx, m, items, kx.WithConcurrency(0), kx.WithConcurrency(1000))
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, "a", got[0].Name)
		assert.Equal(t, "b", got[1].Name)
	})

	t.Run("fail_fast_on_error", func(t *testing.T) {
		m := newBatchManager(t)

		items := []kx.DecryptItem[*batchUser]{
			mustEncryptBatchUser(t, m, "ok"),
			// Invalid ciphertext: fails inside DecryptStruct; the whole batch
			// must fail and return a nil slice.
			{EncryptedObj: &batchUser{}, Ciphertext: "not-a-valid-ciphertext", EncryptionContext: nil},
		}

		got, err := kx.DecryptStructs(ctx, m, items)
		require.Error(t, err)
		assert.Nil(t, got)
	})
}
