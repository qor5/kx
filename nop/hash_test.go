package nop

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNopHash(t *testing.T) {
	t.Run("Write and Sum", func(t *testing.T) {
		h := NewNopHash()
		data := []byte("Hello, world!")

		n, err := h.Write(data)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if n != len(data) {
			t.Errorf("Write returned %d, want %d", n, len(data))
		}

		sum := h.Sum(nil)
		if !bytes.Equal(sum, data) {
			t.Errorf("Sum = %x, want %x", sum, data)
		}
	})

	t.Run("Reset", func(t *testing.T) {
		h := NewNopHash()
		h.Write([]byte("Hello"))
		h.Reset()
		h.Write([]byte("World"))
		sum := h.Sum(nil)
		if !bytes.Equal(sum, []byte("World")) {
			t.Errorf("After Reset, Sum = %x, want %x", sum, []byte("World"))
		}
	})

	t.Run("Size", func(t *testing.T) {
		h := NewNopHash()
		data := []byte("Hello, world!")
		h.Write(data)
		if h.Size() != len(data) {
			t.Errorf("Size = %d, want %d", h.Size(), len(data))
		}
	})

	t.Run("BlockSize", func(t *testing.T) {
		h := NewNopHash()
		if h.BlockSize() != 1 {
			t.Errorf("BlockSize = %d, want 1", h.BlockSize())
		}
	})

	t.Run("Multiple Writes", func(t *testing.T) {
		h := NewNopHash()
		h.Write([]byte("Hello"))
		h.Write([]byte(", "))
		h.Write([]byte("world!"))
		sum := h.Sum(nil)
		if !bytes.Equal(sum, []byte("Hello, world!")) {
			t.Errorf("Sum = %x, want %x", sum, []byte("Hello, world!"))
		}
	})

	t.Run("Sum with prefix", func(t *testing.T) {
		h := NewNopHash()
		h.Write([]byte("world!"))
		prefix := []byte("Hello, ")
		sum := h.Sum(prefix)
		if !bytes.Equal(sum, []byte("Hello, world!")) {
			t.Errorf("Sum with prefix = %x, want %x", sum, []byte("Hello, world!"))
		}
	})

	t.Run("io.WriteString compatibility", func(t *testing.T) {
		h := NewNopHash()
		_, err := io.WriteString(h, "Hello, world!")
		require.NoError(t, err)
		sum := h.Sum(nil)
		expected := "48656c6c6f2c20776f726c6421" // hex for "Hello, world!"
		if hex.EncodeToString(sum) != expected {
			t.Errorf("Sum = %s, want %s", hex.EncodeToString(sum), expected)
		}
	})
}
