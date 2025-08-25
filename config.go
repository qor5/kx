package kx

// Config holds the protection configuration
type Config struct {
	KMSKeyID string `confx:"kmsKeyID" validate:"required"`
	HashKey  string `confx:"hashKey" validate:"required"`
}
