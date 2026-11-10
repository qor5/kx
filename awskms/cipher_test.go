package awskms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theplant/appkit/logtracing"
)

func TestNewCipherFactory_IdleConnTimeout(t *testing.T) {
	t.Run("default client", func(t *testing.T) {
		f, err := NewCipherFactory(aws.Config{Region: "us-east-1"}, "key")
		require.NoError(t, err)

		c, ok := f.kmsCipher.Options().HTTPClient.(*awshttp.BuildableClient)
		require.True(t, ok)
		assert.Equal(t, 5*time.Second, c.GetTransport().IdleConnTimeout)
	})

	t.Run("buildable client from config is not modified", func(t *testing.T) {
		shared := awshttp.NewBuildableClient()
		f, err := NewCipherFactory(aws.Config{Region: "us-east-1", HTTPClient: shared}, "key")
		require.NoError(t, err)

		c := f.kmsCipher.Options().HTTPClient.(*awshttp.BuildableClient)
		assert.Equal(t, 5*time.Second, c.GetTransport().IdleConnTimeout)
		assert.Equal(t, 90*time.Second, shared.GetTransport().IdleConnTimeout)
	})

	t.Run("custom client is kept", func(t *testing.T) {
		custom := &http.Client{}
		f, err := NewCipherFactory(aws.Config{Region: "us-east-1", HTTPClient: custom}, "key")
		require.NoError(t, err)

		assert.Same(t, custom, f.kmsCipher.Options().HTTPClient)
	})
}

// newFakeKMS serves Encrypt and Decrypt. The first failFirst requests have
// their connection closed without a response, as when KMS has closed an idle
// connection the client is reusing.
func newFakeKMS(t *testing.T, failFirst int32) *httptest.Server {
	var seen atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen.Add(1) <= failFirst {
			conn, _, err := w.(http.Hijacker).Hijack()
			require.NoError(t, err)
			conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.Encrypt":
			w.Write([]byte(`{"CiphertextBlob":"Y2lwaGVy","KeyId":"key"}`))
		case "TrentService.Decrypt":
			w.Write([]byte(`{"Plaintext":"cGxhaW4=","KeyId":"key"}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestFactory(t *testing.T, endpoint string) *CipherFactory {
	f, err := NewCipherFactory(aws.Config{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "id", SecretAccessKey: "secret"}, nil
		}),
		Retryer: func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
			})
		},
	}, "key")
	require.NoError(t, err)
	return f
}

type spanRecorder struct {
	mu    sync.Mutex
	spans []*logtracing.SpanData
}

func (r *spanRecorder) ExportSpan(s *logtracing.SpanData) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spans = append(r.spans, s)
}

// traced runs fn inside a sampled span and returns that span's attributes.
func traced(t *testing.T, fn func(ctx context.Context) error) map[string]any {
	rec := &spanRecorder{}
	logtracing.RegisterExporter(rec)
	defer logtracing.UnregisterExporter(rec)

	ctx, _ := logtracing.StartSpan(context.Background(), "test", logtracing.WithSampler(logtracing.AlwaysSample()))
	err := fn(ctx)
	logtracing.EndSpan(ctx, err)
	require.NoError(t, err)

	require.Len(t, rec.spans, 1)
	kvs := rec.spans[0].Keyvals
	attrs := map[string]any{}
	for i := 0; i+1 < len(kvs); i += 2 {
		key := kvs[i].(string)
		_, dup := attrs[key]
		assert.False(t, dup, "span attribute %q set twice", key)
		attrs[key] = kvs[i+1]
	}
	return attrs
}

func TestCipherFactory_RecordsAttempts(t *testing.T) {
	cases := []struct {
		name      string
		failFirst int32
		want      int
	}{
		{name: "first attempt succeeds", failFirst: 0, want: 1},
		{name: "retried after closed connection", failFirst: 1, want: 2},
	}
	for _, tc := range cases {
		t.Run("decrypt "+tc.name, func(t *testing.T) {
			f := newTestFactory(t, newFakeKMS(t, tc.failFirst).URL)
			attrs := traced(t, func(ctx context.Context) error {
				plaintext, err := f.Decrypt(ctx, []byte("cipher"), nil)
				assert.Equal(t, []byte("plain"), plaintext)
				return err
			})
			assert.Equal(t, tc.want, attrs["kms.attempts"])
		})

		t.Run("encrypt "+tc.name, func(t *testing.T) {
			f := newTestFactory(t, newFakeKMS(t, tc.failFirst).URL)
			attrs := traced(t, func(ctx context.Context) error {
				ciphertext, err := f.Encrypt(ctx, []byte("plain"), nil)
				assert.Equal(t, []byte("cipher"), ciphertext)
				return err
			})
			assert.Equal(t, tc.want, attrs["kms.attempts"])
		})
	}
}
