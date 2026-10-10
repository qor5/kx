// Package esdk provides an api.CipherFactory backed by the AWS Encryption SDK.
//
// It exists as a separate Go module so that repositories which do not need
// envelope encryption can upgrade the main kx module without pulling in the
// Encryption SDK's dependency tree (the Dafny runtime, the material-providers
// library, and the DynamoDB client it transitively requires).
//
// The awskms cipher hands the whole plaintext to kms:Encrypt, which caps
// Plaintext at 4096 bytes. This package instead lets the Encryption SDK do
// envelope encryption — kms:GenerateDataKey for a data key, AES-GCM locally for
// the payload — so plaintext size is no longer bounded by a KMS request limit.
package esdk

import "bytes"

// envelopePrefix marks a ciphertext as an Encryption SDK message rather than a
// bare KMS CiphertextBlob.
//
// The first byte is deliberately 0x00. A KMS CiphertextBlob starts with its
// format version 0x01 (observed across every ciphertext this library has
// written), and an Encryption SDK message starts with its own message-format
// version, 0x01 or 0x02. Neither can be 0x00, so a ciphertext carrying this
// prefix is unambiguously ours and everything else is read as legacy.
//
// Detection is therefore one-directional and stays correct even if AWS changes
// either format later: new writes always carry the prefix, and the only
// requirement is that already-stored legacy ciphertexts never begin with it.
var envelopePrefix = []byte{0x00, 'K', 'X', 0x01}

// hasEnvelopePrefix reports whether ciphertext was written by this package.
func hasEnvelopePrefix(ciphertext []byte) bool {
	return bytes.HasPrefix(ciphertext, envelopePrefix)
}

// addEnvelopePrefix prefixes an Encryption SDK message for storage.
func addEnvelopePrefix(message []byte) []byte {
	out := make([]byte, 0, len(envelopePrefix)+len(message))
	out = append(out, envelopePrefix...)
	return append(out, message...)
}

// stripEnvelopePrefix returns the Encryption SDK message inside ciphertext. The
// caller must have checked hasEnvelopePrefix first.
func stripEnvelopePrefix(ciphertext []byte) []byte {
	return ciphertext[len(envelopePrefix):]
}
