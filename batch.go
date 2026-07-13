package kx

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// DecryptItem pairs an encrypted struct with the ciphertext and encryption
// context needed to decrypt it. It is the unit of work for DecryptStructs.
type DecryptItem[T any] struct {
	// EncryptedObj is the struct holding the encrypted (cleared) fields.
	EncryptedObj T
	// Ciphertext is the encrypted payload produced by EncryptStruct.
	Ciphertext string
	// EncryptionContext must match the context used when the item was
	// encrypted (AWS KMS verifies it during Decrypt).
	EncryptionContext map[string]string
}

// DefaultDecryptConcurrency bounds the number of concurrent decrypt operations
// performed by DecryptStructs.
//
// Each item is decrypted with its own DecryptStruct call, and every call is a
// separate AWS KMS Decrypt request — KMS has no batch-decrypt API. Bounding the
// fan-out keeps a single list-style request from bursting the account-level KMS
// request quota while still collapsing N serial round-trips into a parallel one.
const DefaultDecryptConcurrency = 16

type batchOptions struct {
	concurrency int
}

// BatchOption configures a batch decrypt operation.
type BatchOption func(*batchOptions)

// WithConcurrency overrides the maximum number of concurrent decrypt operations.
// Values < 1 are ignored and DefaultDecryptConcurrency is used.
func WithConcurrency(n int) BatchOption {
	return func(o *batchOptions) {
		if n >= 1 {
			o.concurrency = n
		}
	}
}

// DecryptStructs decrypts multiple independent items concurrently and returns
// the decrypted objects in the same order as items.
//
// Each item is decrypted via DecryptStruct (one AWS KMS Decrypt call each);
// AWS KMS has no batch-decrypt API, so this bounds a concurrent fan-out rather
// than issuing a single call. Concurrency is capped at DefaultDecryptConcurrency
// (override with WithConcurrency).
//
// It is fail-fast: the first error cancels the remaining work and is returned,
// and the returned slice is nil in that case. On success the returned slice has
// the same length and order as items.
func DecryptStructs[T any](ctx context.Context, m *Manager, items []DecryptItem[T], opts ...BatchOption) ([]T, error) {
	if len(items) == 0 {
		return nil, nil
	}

	o := batchOptions{concurrency: DefaultDecryptConcurrency}
	for _, opt := range opts {
		opt(&o)
	}
	if o.concurrency > len(items) {
		o.concurrency = len(items)
	}

	results := make([]T, len(items))

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(o.concurrency)

	for i := range items {
		item := items[i]
		g.Go(func() error {
			decrypted, err := DecryptStruct(ctx, m, item.EncryptedObj, item.Ciphertext, item.EncryptionContext)
			if err != nil {
				return err
			}
			// Distinct index per goroutine: no synchronization needed, and
			// g.Wait provides the happens-before barrier before we read results.
			results[i] = decrypted
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}
