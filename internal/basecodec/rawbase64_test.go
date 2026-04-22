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

func TestRawBase64RoundTrip(t *testing.T) {
	original := []byte("StormDNS-response-payload-1234+/")
	encoded := EncodeRawBase64(original)
	decoded, err := DecodeRawBase64(encoded)
	if err != nil {
		t.Fatalf("DecodeRawBase64 returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("unexpected round trip result: got=%q want=%q", decoded, original)
	}
}

func TestRawBase64Empty(t *testing.T) {
	encoded := EncodeRawBase64(nil)
	if len(encoded) != 0 {
		t.Fatalf("unexpected encoded len: got=%d want=0", len(encoded))
	}

	decoded, err := DecodeRawBase64(nil)
	if err != nil {
		t.Fatalf("DecodeRawBase64 returned error: %v", err)
	}
	if len(decoded) != 0 {
		t.Fatalf("unexpected decoded len: got=%d want=0", len(decoded))
	}
}
