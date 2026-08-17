package esdk_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/require"
)

const (
	testKeyARN = "arn:aws:kms:ap-northeast-1:123456789012:key/12345678-1234-1234-1234-123456789012"
	testRegion = "ap-northeast-1"

	// kmsEncryptPlaintextLimit is the hard cap AWS KMS enforces on the
	// Plaintext member of an Encrypt request. It is not adjustable, and it is
	// the entire reason this package exists.
	kmsEncryptPlaintextLimit = 4096
)

// fakeKMS answers KMS requests at the transport layer so tests exercise the
// real Encryption SDK and the real awskms cipher without credentials, network
// access, or a KMS key.
//
// It is deliberately faithful about two behaviours the tests depend on:
// Encrypt rejects plaintext over 4096 bytes exactly as KMS does, and Decrypt
// refuses a blob whose encryption context does not match the one it was sealed
// with. A permissive fake would let both regressions this package guards
// against pass unnoticed.
type fakeKMS struct {
	mu    sync.Mutex
	blobs map[string]sealed

	// calls counts requests per KMS operation.
	calls map[string]int

	// failNext, when set for an operation, makes the next call to it return
	// this error instead of a result.
	failNext map[string]kmsError
}

type sealed struct {
	plaintext         []byte
	encryptionContext map[string]string
}

type kmsError struct {
	status  int
	errType string
	message string
}

func newFakeKMS() *fakeKMS {
	return &fakeKMS{
		blobs:    map[string]sealed{},
		calls:    map[string]int{},
		failNext: map[string]kmsError{},
	}
}

// awsConfig returns a config whose HTTP client is this fake.
func (f *fakeKMS) awsConfig() aws.Config {
	return aws.Config{
		Region:      testRegion,
		Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", "TOKEN"),
		HTTPClient:  &http.Client{Transport: f},
	}
}

func (f *fakeKMS) callCount(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

func (f *fakeKMS) failOnce(op string, e kmsError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[op] = e
}

func (f *fakeKMS) RoundTrip(req *http.Request) (*http.Response, error) {
	target := req.Header.Get("X-Amz-Target")
	op := target[strings.LastIndex(target, ".")+1:]

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	var in struct {
		KeyId             string            `json:"KeyId"`
		Plaintext         []byte            `json:"Plaintext"`
		CiphertextBlob    []byte            `json:"CiphertextBlob"`
		EncryptionContext map[string]string `json:"EncryptionContext"`
		NumberOfBytes     int               `json:"NumberOfBytes"`
		KeySpec           string            `json:"KeySpec"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, err
	}

	f.mu.Lock()
	f.calls[op]++
	if e, ok := f.failNext[op]; ok {
		delete(f.failNext, op)
		f.mu.Unlock()
		return errorResponse(e), nil
	}
	f.mu.Unlock()

	switch op {
	case "Encrypt":
		if len(in.Plaintext) > kmsEncryptPlaintextLimit {
			return errorResponse(kmsError{
				status:  400,
				errType: "ValidationException",
				message: fmt.Sprintf("1 validation error detected: Value at 'plaintext' failed to satisfy constraint: "+
					"Member must have length less than or equal to %d", kmsEncryptPlaintextLimit),
			}), nil
		}
		return jsonResponse(map[string]any{
			"KeyId":          testKeyARN,
			"CiphertextBlob": f.seal(in.Plaintext, in.EncryptionContext),
		}), nil

	case "GenerateDataKey":
		n := in.NumberOfBytes
		if n == 0 {
			n = 32 // AES_256
		}
		dataKey := make([]byte, n)
		for i := range dataKey {
			// Deterministic but distinct per byte; the fake never needs real
			// entropy, and a fixed pattern keeps failures reproducible.
			dataKey[i] = byte(i * 7 % 251)
		}
		return jsonResponse(map[string]any{
			"KeyId":          testKeyARN,
			"Plaintext":      dataKey,
			"CiphertextBlob": f.seal(dataKey, in.EncryptionContext),
		}), nil

	case "Decrypt":
		f.mu.Lock()
		got, ok := f.blobs[string(in.CiphertextBlob)]
		f.mu.Unlock()
		if !ok || !maps.Equal(got.encryptionContext, in.EncryptionContext) {
			return errorResponse(kmsError{
				status:  400,
				errType: "InvalidCiphertextException",
				message: "The ciphertext refers to a customer master key that does not exist, " +
					"does not exist in this region, or you are not allowed to access.",
			}), nil
		}
		return jsonResponse(map[string]any{
			"KeyId":               testKeyARN,
			"Plaintext":           got.plaintext,
			"EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
		}), nil
	}

	return errorResponse(kmsError{
		status:  400,
		errType: "UnsupportedOperationException",
		message: "fakeKMS does not implement " + op,
	}), nil
}

// seal records plaintext under an opaque handle and returns it. The handle
// starts with 0x01 so it looks like a real KMS CiphertextBlob to the format
// detection under test.
func (f *fakeKMS) seal(plaintext []byte, encryptionContext map[string]string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	handle := append([]byte{0x01, 0x02, 0x02, 0x00}, fmt.Appendf(nil, "blob-%d", len(f.blobs))...)
	f.blobs[string(handle)] = sealed{
		plaintext:         bytes.Clone(plaintext),
		encryptionContext: maps.Clone(encryptionContext),
	}
	return handle
}

func jsonResponse(payload map[string]any) *http.Response {
	body, _ := json.Marshal(payload)
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func errorResponse(e kmsError) *http.Response {
	body, _ := json.Marshal(map[string]any{"__type": e.errType, "message": e.message})
	return &http.Response{
		StatusCode: e.status,
		Header: http.Header{
			"Content-Type":     []string{"application/x-amz-json-1.1"},
			"X-Amzn-Errortype": []string{e.errType},
			"X-Amzn-Requestid": []string{"fake-request-id"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}
}

// assertBase64Binary guards the fake itself: the AWS JSON protocol carries blob
// members as base64 strings, and Go marshals []byte that way, so a change in
// how the fake builds payloads would otherwise silently produce garbage.
func assertBase64Binary(t *testing.T) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"Plaintext": []byte("hi")})
	require.NoError(t, err)
	require.JSONEq(t, `{"Plaintext":"`+base64.StdEncoding.EncodeToString([]byte("hi"))+`"}`, string(body))
}
