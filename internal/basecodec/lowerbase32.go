// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package basecodec

import (
	"encoding/base32"
	"strings"
)

var lowerBase32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func EncodedLenLowerBase32(n int) int {
	if n <= 0 {
		return 0
	}
	return lowerBase32Encoding.EncodedLen(n)
}

func EncodeLowerBase32To(dst []byte, data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := lowerBase32Encoding.EncodedLen(len(data))
	lowerBase32Encoding.Encode(dst[:n], data)
	return n
}

func EncodeLowerBase32Bytes(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, lowerBase32Encoding.EncodedLen(len(data)))
	lowerBase32Encoding.Encode(out, data)
	return out
}

func EncodeLowerBase32(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	out := EncodeLowerBase32Bytes(data)
	return string(out)
}

func DecodeLowerBase32(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	normalized := make([]byte, len(data))
	for i, ch := range data {
		if ch >= 'A' && ch <= 'Z' {
			normalized[i] = ch + ('a' - 'A')
			continue
		}
		normalized[i] = ch
	}

	out := make([]byte, lowerBase32Encoding.DecodedLen(len(normalized)))
	n, err := lowerBase32Encoding.Decode(out, normalized)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}

func DecodeLowerBase32String(data string) ([]byte, error) {
	if data == "" {
		return []byte{}, nil
	}
	return DecodeLowerBase32([]byte(strings.ToLower(data)))
}
