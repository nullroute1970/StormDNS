// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package basecodec

func EncodedLen(n int) int {
	return EncodedLenLowerBase36(n)
}

func EncodeTo(dst []byte, data []byte) int {
	return EncodeLowerBase36To(dst, data)
}

func EncodeToBytes(data []byte) []byte {
	return EncodeLowerBase36Bytes(data)
}

// Encode encodes data to a string using the current active encoding scheme (default: LowerBase32)
func Encode(data []byte) string {
	// To switch to Base36, change this to: return EncodeLowerBase36(data)
	return EncodeLowerBase36(data)
}

// Decode decodes data from a byte slice using the current active encoding scheme
func Decode(data []byte) ([]byte, error) {
	// To switch to Base36, change this to: return DecodeLowerBase36(data)
	return DecodeLowerBase36(data)
}

// DecodeString decodes data from a string using the current active encoding scheme
func DecodeString(data string) ([]byte, error) {
	// To switch to Base36, change this to: return DecodeLowerBase36String(data)
	return DecodeLowerBase36String(data)
}
