// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package security

import (
	"bytes"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	methods := []int{0, 1, 2, 3, 4, 5}
	plaintext := []byte("stormdns-roundtrip-test")
	rawKey := "0123456789abcdef0123456789abcdef"

	for _, method := range methods {
		codec, err := NewCodec(method, rawKey)
		if err != nil {
			t.Fatalf("NewCodec(%d) returned error: %v", method, err)
		}

		ciphertext, err := codec.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed for method %d: %v", method, err)
		}

		decrypted, err := codec.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt failed for method %d: %v", method, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("round-trip mismatch for method %d", method)
		}
	}
}

func TestCodecRejectsInvalidCiphertext(t *testing.T) {
	codec, err := NewCodec(3, "0123456789abcdef")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	if _, err := codec.Decrypt([]byte{1, 2, 3}); err == nil {
		t.Fatal("Decrypt should reject truncated AES-GCM ciphertext")
	}
}

func TestCodecXORChangesData(t *testing.T) {
	codec, err := NewCodec(1, "key-material")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	plaintext := []byte("xor-data")
	ciphertext, err := codec.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("XOR encryption should change non-empty data")
	}
}

func TestCodecEncodeDecodeLowerBase32RoundTrip(t *testing.T) {
	codec, err := NewCodec(2, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	plaintext := []byte("header-and-payload")
	encoded, err := codec.EncryptAndEncode(plaintext)
	if err != nil {
		t.Fatalf("EncryptAndEncode returned error: %v", err)
	}

	decoded, err := codec.DecodeAndDecrypt([]byte(encoded))
	if err != nil {
		t.Fatalf("DecodeAndDecrypt returned error: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatal("encode/decode lower-base32 round-trip mismatch")
	}
}
