package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/qor5/kx"
)

func main() {
	// Define command-line flags
	keySize := flag.Int("size", 256, "Key size in bits (128, 192, or 256)")
	flag.Parse()

	// Validate key size
	var size protection.KeySize
	switch *keySize {
	case 128:
		size = protection.KeySize128
	case 192:
		size = protection.KeySize192
	case 256:
		size = protection.KeySize256
	default:
		fmt.Fprintf(os.Stderr, "Error: Invalid key size %d. Must be 128, 192, or 256.\n", *keySize)
		os.Exit(1)
	}

	// Generate key
	key, err := protection.GenerateAESKey(size)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}

	// Output the key
	fmt.Printf("Generated AES-%d key (base64):\n%s\n", *keySize, key)
	fmt.Printf("\nAdd this to your configuration as:\n")
	fmt.Printf("cipher:\n  kind: aes\n  aes:\n    key: %s\n", key)
}
