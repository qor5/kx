package awskms

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theplant/appkit/logtracing"
)

type spanRecorder struct {
	mu    sync.Mutex
	spans []*logtracing.SpanData
}

func (r *spanRecorder) ExportSpan(s *logtracing.SpanData) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spans = append(r.spans, s)
}

func (r *spanRecorder) kvs(t *testing.T, name string) map[string]any {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.spans {
		if s.Name != name {
			continue
		}
		m := map[string]any{}
		for i := 0; i+1 < len(s.Keyvals); i += 2 {
			m[s.Keyvals[i].(string)] = s.Keyvals[i+1]
		}
		return m
	}
	t.Fatalf("span %q not exported", name)
	return nil
}

func newTestFactory(t *testing.T, handler http.HandlerFunc, credsDelay time.Duration) *CipherFactory {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cfg := aws.Config{
		Region:       "ap-northeast-1",
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   srv.Client(),
		Credentials: aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			time.Sleep(credsDelay)
			return aws.Credentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET", Source: "test"}, nil
		})),
		Retryer: func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
			})
		},
	}
	f, err := NewCipherFactory(cfg, "alias/test")
	require.NoError(t, err)
	return f
}

func TestDecryptRecordsAttemptsAndIdentityWait(t *testing.T) {
	rec := &spanRecorder{}
	logtracing.RegisterExporter(rec)
	t.Cleanup(func() { logtracing.UnregisterExporter(rec) })

	var calls atomic.Int32
	f := newTestFactory(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"__type":"KMSInternalException","message":"transient"}`))
			return
		}
		_, _ = w.Write([]byte(`{"KeyId":"alias/test","Plaintext":"` + base64.StdEncoding.EncodeToString([]byte("hello")) + `"}`))
	}, 30*time.Millisecond)

	ctx, _ := logtracing.StartSpan(context.Background(), "test/decrypt")
	plaintext, err := f.Decrypt(ctx, []byte("ciphertext"), map[string]string{"entity": "reservation"})
	logtracing.EndSpan(ctx, err)

	require.NoError(t, err)
	assert.Equal(t, "hello", string(plaintext))

	kvs := rec.kvs(t, "test/decrypt")
	assert.Equal(t, 2, kvs["kms.attempts"])
	assert.Contains(t, kvs["kms.first_attempt_err"], "KMSInternalException")
	// Credentials are fetched once (30ms) and served from the cache on the retry.
	assert.GreaterOrEqual(t, kvs["kms.identity_ms"], 30.0)
}

func TestEncryptRecordsSingleAttempt(t *testing.T) {
	rec := &spanRecorder{}
	logtracing.RegisterExporter(rec)
	t.Cleanup(func() { logtracing.UnregisterExporter(rec) })

	f := newTestFactory(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"KeyId":"alias/test","CiphertextBlob":"` + base64.StdEncoding.EncodeToString([]byte("blob")) + `"}`))
	}, 0)

	ctx, _ := logtracing.StartSpan(context.Background(), "test/encrypt")
	_, err := f.Encrypt(ctx, []byte("hello"), nil)
	logtracing.EndSpan(ctx, err)
	require.NoError(t, err)

	kvs := rec.kvs(t, "test/encrypt")
	assert.Equal(t, 1, kvs["kms.attempts"])
	assert.NotContains(t, kvs, "kms.first_attempt_err")
	assert.Contains(t, kvs, "kms.identity_ms")
}
