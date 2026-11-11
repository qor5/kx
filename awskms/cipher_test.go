package awskms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theplant/appkit/logtracing"
)

type recordingExporter struct {
	mu    sync.Mutex
	spans []*logtracing.SpanData
}

func (e *recordingExporter) ExportSpan(s *logtracing.SpanData) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.spans = append(e.spans, s)
}

func (e *recordingExporter) byName(t *testing.T, name string) *logtracing.SpanData {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.spans {
		if s.Name == name {
			return s
		}
	}
	require.FailNowf(t, "span not exported", "no span named %q", name)
	return nil
}

// lastValue returns the value a span ends up with for key: a key appended
// twice is written twice, and the later one is what the log line shows.
func lastValue(s *logtracing.SpanData, key string) any {
	var v any
	for i := 0; i+1 < len(s.Keyvals); i += 2 {
		if s.Keyvals[i] == key {
			v = s.Keyvals[i+1]
		}
	}
	return v
}

// newFakeKMS answers Encrypt and Decrypt over the KMS JSON protocol.
func newFakeKMS(t *testing.T) *CipherFactory {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resp map[string]string
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.Encrypt":
			resp = map[string]string{"CiphertextBlob": base64.StdEncoding.EncodeToString([]byte("ciphertext")), "KeyId": "test-key"}
		case "TrentService.Decrypt":
			resp = map[string]string{"Plaintext": base64.StdEncoding.EncodeToString([]byte("plaintext")), "KeyId": "test-key"}
		default:
			http.Error(w, "unexpected target", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	f, err := NewCipherFactory(aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
		BaseEndpoint: aws.String(srv.URL),
	}, "test-key")
	require.NoError(t, err)
	return f
}

func TestKMSCallDoesNotRelabelCallerSpan(t *testing.T) {
	f := newFakeKMS(t)
	encCtx := map[string]string{"entity": "actor"}

	calls := []struct {
		name string
		call func(ctx context.Context) error
	}{
		{"aws.kms/Encrypt", func(ctx context.Context) error {
			_, err := f.Encrypt(ctx, []byte("plaintext"), encCtx)
			return err
		}},
		{"aws.kms/Decrypt", func(ctx context.Context) error {
			_, err := f.Decrypt(ctx, []byte("ciphertext"), encCtx)
			return err
		}},
	}

	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			exporter := &recordingExporter{}
			logtracing.RegisterExporter(exporter)
			t.Cleanup(func() { logtracing.UnregisterExporter(exporter) })

			callerCtx, caller := logtracing.StartSpan(context.Background(), "http.serve:POST")
			logtracing.AppendSpanKVs(callerCtx, "span.type", "http", "span.role", "server")

			require.NoError(t, c.call(callerCtx))
			logtracing.EndSpan(callerCtx, nil)

			callerSpan := exporter.byName(t, "http.serve:POST")
			assert.Equal(t, "http", lastValue(callerSpan, "span.type"))
			assert.Equal(t, "server", lastValue(callerSpan, "span.role"))
			assert.Nil(t, lastValue(callerSpan, "kms.key_id"))

			kmsSpan := exporter.byName(t, c.name)
			assert.Equal(t, caller.SpanID(), kmsSpan.ParentSpanID)
			assert.Equal(t, "aws.kms", lastValue(kmsSpan, "span.type"))
			assert.Equal(t, "client", lastValue(kmsSpan, "span.role"))
			assert.Equal(t, "test-key", lastValue(kmsSpan, "kms.key_id"))
			assert.Equal(t, "actor", lastValue(kmsSpan, "kms.enc_ctx.entity"))
		})
	}
}

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

// newFlakyKMS is like newFakeKMS, but the first failFirst requests have their
// connection closed without a response, as when KMS has closed an idle
// connection the client is reusing. Retries happen without backoff.
func newFlakyKMS(t *testing.T, failFirst int32) *CipherFactory {
	t.Helper()
	var seen atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen.Add(1) <= failFirst {
			conn, _, err := w.(http.Hijacker).Hijack()
			require.NoError(t, err)
			conn.Close()
			return
		}
		var resp map[string]string
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.Encrypt":
			resp = map[string]string{"CiphertextBlob": base64.StdEncoding.EncodeToString([]byte("ciphertext")), "KeyId": "test-key"}
		case "TrentService.Decrypt":
			resp = map[string]string{"Plaintext": base64.StdEncoding.EncodeToString([]byte("plaintext")), "KeyId": "test-key"}
		default:
			http.Error(w, "unexpected target", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	f, err := NewCipherFactory(aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
		BaseEndpoint: aws.String(srv.URL),
		Retryer: func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
			})
		},
	}, "test-key")
	require.NoError(t, err)
	return f
}

func TestKMSCallRecordsAttempts(t *testing.T) {
	cases := []struct {
		name      string
		failFirst int32
		want      int
	}{
		{name: "first attempt succeeds", failFirst: 0, want: 1},
		{name: "retried after closed connection", failFirst: 1, want: 2},
	}
	calls := []struct {
		span string
		call func(ctx context.Context, f *CipherFactory) error
	}{
		{"aws.kms/Encrypt", func(ctx context.Context, f *CipherFactory) error {
			ciphertext, err := f.Encrypt(ctx, []byte("plaintext"), nil)
			assert.Equal(t, []byte("ciphertext"), ciphertext)
			return err
		}},
		{"aws.kms/Decrypt", func(ctx context.Context, f *CipherFactory) error {
			plaintext, err := f.Decrypt(ctx, []byte("ciphertext"), nil)
			assert.Equal(t, []byte("plaintext"), plaintext)
			return err
		}},
	}

	for _, tc := range cases {
		for _, c := range calls {
			t.Run(c.span+" "+tc.name, func(t *testing.T) {
				f := newFlakyKMS(t, tc.failFirst)
				exporter := &recordingExporter{}
				logtracing.RegisterExporter(exporter)
				t.Cleanup(func() { logtracing.UnregisterExporter(exporter) })

				require.NoError(t, c.call(context.Background(), f))

				assert.Equal(t, tc.want, lastValue(exporter.byName(t, c.span), "kms.attempts"))
			})
		}
	}
}
