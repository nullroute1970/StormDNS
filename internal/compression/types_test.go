// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package compression

import (
	"bytes"
	"testing"
)

func TestCompressPayloadKeepsSmallDataRaw(t *testing.T) {
	data := bytes.Repeat([]byte("a"), DefaultMinSize)
	out, used := CompressPayload(data, TypeZLIB, DefaultMinSize)
	if used != TypeOff {
		t.Fatalf("unexpected compression type: got=%d want=%d", used, TypeOff)
	}
	if !bytes.Equal(out, data) {
		t.Fatal("small payload should stay uncompressed")
	}
}

func TestCompressPayloadRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("abcabcabcabcabcabcabcabc"), 16)
	compressed, used := CompressPayload(data, TypeZLIB, DefaultMinSize)
	if used != TypeZLIB {
		t.Fatalf("unexpected compression type: got=%d want=%d", used, TypeZLIB)
	}
	if len(compressed) >= len(data) {
		t.Fatalf("compressed payload should be smaller: got=%d raw=%d", len(compressed), len(data))
	}

	decoded, ok := TryDecompressPayload(compressed, used)
	if !ok {
		t.Fatal("TryDecompressPayload returned false")
	}
	if !bytes.Equal(decoded, data) {
		t.Fatal("decompressed payload mismatch")
	}
}

func TestUnavailableCompressionFallsBackToOff(t *testing.T) {
	data := bytes.Repeat([]byte("abcabcabcabcabcabcabcabc"), 16)
	out, used := CompressPayload(data, 255, DefaultMinSize)
	if used != TypeOff {
		t.Fatalf("unexpected compression type: got=%d want=%d", used, TypeOff)
	}
	if !bytes.Equal(out, data) {
		t.Fatal("unsupported compression must return original data")
	}
}

func TestDecompressZSTDDecoderCanBeReusedFromPool(t *testing.T) {
	data := bytes.Repeat([]byte("zstd-roundtrip-"), 128)

	compressed, err := compressZSTD(data)
	if err != nil {
		t.Fatalf("compressZSTD failed: %v", err)
	}

	for i := 0; i < 2; i++ {
		decoded, err := decompressZSTD(compressed)
		if err != nil {
			t.Fatalf("decompressZSTD failed on pass %d: %v", i+1, err)
		}
		if !bytes.Equal(decoded, data) {
			t.Fatalf("decoded payload mismatch on pass %d", i+1)
		}
	}
}
