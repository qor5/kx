package protection

// CipherKind represents the type of encryption to be used
type CipherKind string

const (
	CipherKindKMS CipherKind = "kms"
	CipherKindAES CipherKind = "aes"
	CipherKindNOP CipherKind = "nop"
)

// CipherKMSConfig holds configuration for AWS KMS encryption
type CipherKMSConfig struct {
	KeyID string `confx:"keyID" validate:"required"`
}

// CipherAESConfig holds configuration for local encryption
type CipherAESConfig struct {
	Key string `confx:"key" validate:"required"`
}

// Config holds the protection configuration
type Config struct {
	CipherConfig CipherConfig `confx:"cipher"`
	HasherConfig HasherConfig `confx:"hasher"`
}

type CipherConfig struct {
	Kind CipherKind      `confx:"kind" validate:"required,oneof=kms aes nop"`
	KMS  CipherKMSConfig `confx:"kms" validate:"skip_nested_unless=Kind kms"`
	AES  CipherAESConfig `confx:"aes" validate:"skip_nested_unless=Kind aes"`
}

type HasherKind string

const (
	HasherKindHMAC HasherKind = "hmac"
	hasherSHA256   HasherKind = "sha256"
	HasherKindNOP  HasherKind = "nop"
)

type HasherHMACConfig struct {
	Key string `confx:"key" validate:"required"`
}

type HasherConfig struct {
	Kind HasherKind `confx:"kind" validate:"required,oneof=hmac nop sha256"`
	// HashKey is used for hashing operations
	HMAC HasherHMACConfig `confx:"hmac" validate:"skip_nested_unless=Kind hmac"`
}
