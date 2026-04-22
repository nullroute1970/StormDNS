package basecodec

import (
	"crypto/rand"
	"testing"
)

func BenchmarkEncodeLowerBase36_Large(b *testing.B) {
	data := make([]byte, 512)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeLowerBase36(data)
	}
}

func BenchmarkDecodeLowerBase36_Large(b *testing.B) {
	data := make([]byte, 512)
	rand.Read(data)
	encoded := EncodeLowerBase36(data)
	encodedBytes := []byte(encoded)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeLowerBase36(encodedBytes)
	}
}
