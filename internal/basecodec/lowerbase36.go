// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package basecodec

import (
	"errors"
)

var (
	ErrInvalidLowerBase36 = errors.New("invalid lower base36 data")

	lowerBase36Alphabet = [36]byte{
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
		'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
		'u', 'v', 'w', 'x', 'y', 'z',
	}
	lowerBase36DecodeMap = newLowerBase36DecodeMap()
)

var (
	lowerBase36EncodedCharsByBytes = [8]int{0, 2, 4, 5, 7, 8, 10, 11}
	lowerBase36DecodedBytesByChars = [12]int{0, 0, 1, 0, 2, 3, 0, 4, 5, 0, 6, 7}
)

func EncodedLenLowerBase36(n int) int {
	if n <= 0 {
		return 0
	}
	blocks := n / 7
	rem := n % 7
	return blocks*11 + lowerBase36EncodedCharsByBytes[rem]
}

func EncodeLowerBase36To(dst []byte, data []byte) int {
	if len(data) == 0 {
		return 0
	}

	offset := 0
	src := data

	for len(src) >= 7 {
		val := uint64(src[0])<<48 | uint64(src[1])<<40 |
			uint64(src[2])<<32 | uint64(src[3])<<24 |
			uint64(src[4])<<16 | uint64(src[5])<<8 | uint64(src[6])

		writeBase36Block(dst[offset:offset+11], val, 11)
		offset += 11
		src = src[7:]
	}

	if len(src) > 0 {
		var val uint64
		for _, b := range src {
			val = (val << 8) | uint64(b)
		}

		charCount := lowerBase36EncodedCharsByBytes[len(src)]
		writeBase36Block(dst[offset:offset+charCount], val, charCount)
		offset += charCount
	}

	return offset
}

func writeBase36Block(dst []byte, val uint64, count int) {
	for i := count - 1; i >= 0; i-- {
		dst[i] = lowerBase36Alphabet[val%36]
		val /= 36
	}
}

func EncodeLowerBase36Bytes(data []byte) []byte {
	out := make([]byte, EncodedLenLowerBase36(len(data)))
	n := EncodeLowerBase36To(out, data)
	return out[:n]
}

func EncodeLowerBase36(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return string(EncodeLowerBase36Bytes(data))
}

func DecodeLowerBase36(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	totalBytes, err := decodedLenLowerBase36(len(data))
	if err != nil {
		return nil, err
	}

	out := make([]byte, totalBytes)
	offset := 0
	src := data

	for len(src) > 0 {
		blockSize, charCount := lowerBase36NextDecodeBlock(len(src))
		val, err := readBase36Block(src[:charCount])
		if err != nil {
			return nil, err
		}

		for i := blockSize - 1; i >= 0; i-- {
			out[offset+i] = byte(val)
			val >>= 8
		}
		offset += blockSize
		src = src[charCount:]
	}

	return out, nil
}

func readBase36Block(data []byte) (uint64, error) {
	var val uint64
	for _, ch := range data {
		digit := lowerBase36DecodeMap[ch]
		if digit == 0xFF {
			return 0, ErrInvalidLowerBase36
		}
		val = val*36 + uint64(digit)
	}
	return val, nil
}

func DecodeLowerBase36String(data string) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	totalBytes, err := decodedLenLowerBase36(len(data))
	if err != nil {
		return nil, err
	}

	out := make([]byte, totalBytes)
	offset := 0
	src := data

	for len(src) > 0 {
		blockSize, charCount := lowerBase36NextDecodeBlock(len(src))
		val, err := readBase36BlockString(src[:charCount])
		if err != nil {
			return nil, err
		}

		for i := blockSize - 1; i >= 0; i-- {
			out[offset+i] = byte(val)
			val >>= 8
		}
		offset += blockSize
		src = src[charCount:]
	}

	return out, nil
}

func newLowerBase36DecodeMap() [256]byte {
	var table [256]byte
	for i := range table {
		table[i] = 0xFF
	}
	for i, ch := range lowerBase36Alphabet {
		table[ch] = byte(i)
		if ch >= 'a' && ch <= 'z' {
			table[ch-'a'+'A'] = byte(i)
		}
	}
	return table
}

func decodeLowerBase36Small(data []byte, leadingZeros int) ([]byte, error) {
	return DecodeLowerBase36(data)
}

func decodeLowerBase36SmallString(data string, leadingZeros int) ([]byte, error) {
	return DecodeLowerBase36String(data)
}

func decodeLowerBase36LargeBytes(data []byte, leadingZeros int) ([]byte, error) {
	return DecodeLowerBase36(data)
}

func decodeLowerBase36LargeString(data string, leadingZeros int) ([]byte, error) {
	return DecodeLowerBase36String(data)
}

func decodedLenLowerBase36(encodedLen int) (int, error) {
	if encodedLen <= 0 {
		return 0, nil
	}
	blocks := encodedLen / 11
	rem := encodedLen % 11
	if rem >= len(lowerBase36DecodedBytesByChars) {
		return 0, ErrInvalidLowerBase36
	}
	decodedRem := lowerBase36DecodedBytesByChars[rem]
	if rem != 0 && decodedRem == 0 {
		return 0, ErrInvalidLowerBase36
	}
	return blocks*7 + decodedRem, nil
}

func lowerBase36NextDecodeBlock(remaining int) (blockSize int, charCount int) {
	if remaining >= 11 {
		return 7, 11
	}
	return lowerBase36DecodedBytesByChars[remaining], remaining
}

func readBase36BlockString(data string) (uint64, error) {
	var val uint64
	for i := 0; i < len(data); i++ {
		digit := lowerBase36DecodeMap[data[i]]
		if digit == 0xFF {
			return 0, ErrInvalidLowerBase36
		}
		val = val*36 + uint64(digit)
	}
	return val, nil
}
