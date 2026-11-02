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

// WithSigning selects the ECDSA-signing algorithm suite
// (ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384), which is the Encryption
// SDK's own default.
//
// It defaults to false here, selecting the unsigned committing suite
// (ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY). Both suites commit to the data key;
// they differ only in whether each message also carries a digital signature.
//
// A signature lets a decryptor verify *which* party encrypted a message, and it
// is worth its cost when encryptors and decryptors are different, mutually
// distrusting roles. kx's callers are not: the same application encrypts and
// decrypts its own rows under one key, and every process that can verify a
// signature can also produce one. Measured against the unsigned suite, signing
// costs roughly 4x the CPU per encrypt/decrypt and ~200 extra bytes per row, and
// it appends an aws-crypto-public-key entry to the encryption context sent to
// KMS.
//
// Enable it if a threat model actually distinguishes the encryptor from the
// decryptor. Switching either way is safe at any time: the suite is recorded in
// each message, so both kinds stay readable and may coexist in one table.
func WithSigning(enabled bool) Option {
	return func(f *CipherFactory) {
		f.signing = enabled
	}
}
