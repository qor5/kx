package esdk

// Option configures a CipherFactory.
type Option func(*CipherFactory)

// WithEnvelopeWrite controls which format Encrypt produces.
//
// It defaults to false, so adopting this package is inert on its own: the
// factory keeps writing bare KMS ciphertexts exactly as awskms does, while
// gaining the ability to read envelope ciphertexts. That ordering is what makes
// a rollout safe — every reader can be deployed and settled before any writer
// starts producing a format the old code cannot decrypt.
//
// Enable it only once the deployment's IAM role is allowed to call
// kms:GenerateDataKey; without that permission Encrypt fails with
// AccessDeniedException for every call, not just oversized ones.
func WithEnvelopeWrite(enabled bool) Option {
	return func(f *CipherFactory) {
		f.envelopeWrite = enabled
	}
}
