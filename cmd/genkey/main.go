package main

import (
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/qor5/kx"
	"log"
)

func main() {
	// Define command-line flags
	keySize := flag.Int("size", sha256.Size, "sha256 key size(default 32 bytes)")
	flag.Parse()
	key := make([]byte, *keySize)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Error generating key: %v\n", err)
	}
	encodedKey := kx.EncodeKey(key)
	fmt.Printf("Generated key (base64):\n%s\n", encodedKey)
}
