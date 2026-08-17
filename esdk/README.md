# kx/esdk

An `api.CipherFactory` backed by the [AWS Encryption SDK for Go](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/go.html).

## Why

`awskms` hands the whole plaintext to `kms:Encrypt`, and KMS caps that request's
`Plaintext` member at **4096 bytes**. The cap is not adjustable, and it applies
to a struct's entire PII blob rather than to any single field — so a long
free-text field fails or succeeds depending on how long the other fields happen
to be. UTF-8 Japanese makes it easy to reach: 4096 bytes is about 1365
characters.

This package does envelope encryption instead — `kms:GenerateDataKey` for a data
key, AES-GCM locally for the payload — so plaintext size is no longer bounded by
a KMS request limit.

It is a **separate Go module** so that repositories which don't need it can
upgrade the main `kx` module without taking on the Encryption SDK's dependency
tree (the Dafny runtime, the material-providers library, and the DynamoDB client
it transitively requires).

## Usage

```go
import "github.com/qor5/kx/esdk"

cipherFactory, err := esdk.NewCipherFactory(awsConfig, kmsKeyID,
    esdk.WithEnvelopeWrite(envelopeWriteEnabled))
if err != nil {
    return nil, err
}
manager, err := kx.NewManager(cipherFactory, hashFactory, registry)
```

Drop-in replacement for `awskms.NewCipherFactory` / `kx.NewCipherFactory`;
nothing above the cipher layer changes.

## Compatibility

| | |
|---|---|
| Reads ciphertexts written by `awskms` | Always, regardless of settings |
| Reads envelope ciphertexts | Always |
| Writes envelope ciphertexts | Only with `WithEnvelopeWrite(true)` |
| Needs `kms:GenerateDataKey` | Only with `WithEnvelopeWrite(true)` |

Envelope ciphertexts carry a 4-byte prefix beginning `0x00`. A KMS
`CiphertextBlob` begins with its format version `0x01`, so the two are
distinguishable without guessing, and an unprefixed ciphertext is always read
through the legacy path. **No backfill is required** — existing rows stay
readable indefinitely.

## Rolling it out

Adopting this package is inert by default: writes still go through
`kms:Encrypt`, byte-for-byte as before, while the reader gains the ability to
decrypt envelope ciphertexts. That ordering is the point — deploy readers first,
then switch writers on.

1. **Add the dependency, leave `WithEnvelopeWrite` off.** Behaviour is unchanged
   and no IAM change is needed. Let it reach every replica.
2. **Grant `kms:GenerateDataKey`** on the PII key to the roles that write.
   Existing policies typically list only `kms:Decrypt` and `kms:Encrypt`.
3. **Turn `WithEnvelopeWrite` on** — preferably from config, so it can be
   reverted without a redeploy.

Step 2 must land before step 3. Without the permission, `Encrypt` fails with
`AccessDeniedException` for *every* call, not just oversized ones.

Because step 1 ships the reader ahead of the writer, rolling step 3 back never
leaves ciphertext that the running code cannot decrypt.

## Notes

- **Encryption context is required authenticated data.** `awskms` inherits
  "a ciphertext from another row does not decrypt" from `kms:Decrypt`, which
  rejects a mismatched encryption context outright. The Encryption SDK does not
  compare contexts by default — it stores them in the message header and returns
  them to the caller uncompared — so this package seals every context entry
  through a required-encryption-context CMM to keep that guarantee. A side
  benefit: the context is no longer written into the message in the clear.
- **KMS call volume is unchanged.** One `GenerateDataKey` per encrypt replaces
  one `Encrypt`; decrypts remain one `Decrypt`. All three share the same
  per-region quota, so no data key caching is needed.
- **Ciphertext grows** by roughly the size of one wrapped data key — about 235
  bytes per row with the default suite.
- **Messages are not signed by default.** Both suites this package can use commit
  to the data key; they differ only in carrying an ECDSA signature. Signing lets a
  decryptor verify *which* party encrypted a message, which is worth paying for
  when encryptors and decryptors are mutually distrusting roles — not the case
  here, where one application encrypts and decrypts its own rows under one key.
  Measured against the unsigned suite, signing costs ~4x the CPU per
  encrypt/decrypt and ~200 extra bytes per row. `WithSigning(true)` restores the
  Encryption SDK's default if a threat model calls for it; the suite is recorded
  per message, so both kinds stay readable and can coexist in one table.
- **A deadline bounds the wait, not the KMS call.** The Encryption SDK accepts a
  context and then drops it: measured against a fake KMS held at 300ms with a
  50ms deadline, the call returned success after the full 300ms and the outbound
  request's context had never been cancelled. `Encrypt` and `Decrypt` therefore
  return as soon as the context is done, which is what keeps a KMS stall from
  pinning an HTTP handler or a batch worker. The abandoned KMS round trip still
  runs to completion in the background and its result is discarded — actually
  cancelling it needs the SDK to propagate the context. The bare KMS path has no
  such gap, since there the AWS SDK gets the caller's context directly.
- **Concurrent envelope operations trip `-race`.** The Encryption SDK and the
  material providers library are transpiled from Dafny, and their generated
  constructors initialise sequence fields from the Dafny runtime's package-level
  `EmptySeq` singleton — `New_KmsGenerateAndWrapKeyMaterial_` runs
  `_dafny.EmptySeq.SetString()` on every encrypt, decrypt, and keyring
  construction. Two goroutines doing envelope crypto at once race on that word.
  Every reported access to it is a write of the constant `true` and there is no
  reader, so results stay correct; giving your goroutines separate
  `CipherFactory` values does not help, since the state belongs to the runtime.
  Silencing it would mean putting every KMS round trip behind one process-wide
  lock, which this package does not do — `DecryptStructs` fans out
  `DefaultDecryptConcurrency` calls and that throughput is worth more than a
  warning about a write that cannot change a value. If a downstream suite runs
  `-race` over concurrent envelope operations, this is what it will report. The
  bare KMS path never enters that code and is unaffected.
- **KMS sees the full encryption context.** Requiring the context keeps them out
  of the message header but not out of the `GenerateDataKey` / `Decrypt` calls, so
  a `kms:EncryptionContext:<key>` IAM condition key can still be used to narrow
  the grant. With the default unsigned suite the context KMS receives is exactly
  what the caller passed — signing adds an `aws-crypto-public-key` entry, which
  such a policy then has to tolerate.
