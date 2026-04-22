// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package basecodec

import (
	"bytes"
	"testing"
)

func TestEncodeLowerBase32UsesOnlyLowerBase32Alphabet(t *testing.T) {
	encoded := EncodeLowerBase32([]byte("StormDNS-123"))
	if encoded == "" {
		t.Fatal("encoded string must not be empty")
	}

	for i := 0; i < len(encoded); i++ {
		ch := encoded[i]
		if ch >= 'a' && ch <= 'z' {
			continue
		}
		if ch >= '2' && ch <= '7' {
			continue
		}
		t.Fatalf("unexpected character at index %d: %q", i, ch)
	}
}

func TestDecodeLowerBase32RoundTrip(t *testing.T) {
	original := []byte{0x00, 0x01, 0x02, 0x10, 0x20, 0x30, 0x40, 0xFE, 0xFF}
	encoded := EncodeLowerBase32(original)

	decoded, err := DecodeLowerBase32([]byte(encoded))
	if err != nil {
		t.Fatalf("DecodeLowerBase32 returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("unexpected decoded bytes: %#v", decoded)
	}
}

func TestDecodeLowerBase32AcceptsUppercaseASCII(t *testing.T) {
	original := []byte{0x00, 0x01, 0xAB, 0xCD, 0xEF}
	encoded := EncodeLowerBase32(original)

	upper := []byte(encoded)
	for i := range upper {
		if upper[i] >= 'a' && upper[i] <= 'z' {
			upper[i] -= 'a' - 'A'
		}
	}

	decodedUpper, err := DecodeLowerBase32(upper)
	if err != nil {
		t.Fatalf("DecodeLowerBase32 returned error for uppercase input: %v", err)
	}
	if !bytes.Equal(decodedUpper, original) {
		t.Fatalf("unexpected decoded uppercase bytes: %#v", decodedUpper)
	}

	decodedString, err := DecodeLowerBase32String(string(upper))
	if err != nil {
		t.Fatalf("DecodeLowerBase32String returned error for uppercase input: %v", err)
	}
	if !bytes.Equal(decodedString, original) {
		t.Fatalf("unexpected decoded uppercase string bytes: %#v", decodedString)
	}
}
