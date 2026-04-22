// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20"

	baseCodec "stormdns-go/internal/basecodec"
	"stormdns-go/internal/config"
)

var (
	ErrInvalidCodecMethod = errors.New("invalid encryption method")
	ErrInvalidCiphertext  = errors.New("invalid ciphertext")
)

const (
	chachaNonceSize = 16
	aesNonceSize    = 12
)

var cryptoBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096)
		return &b
	},
}

func getCryptoBuffer(size int) *[]byte {
	bufPtr := cryptoBufferPool.Get().(*[]byte)
	if cap(*bufPtr) < size {
		b := make([]byte, size*2)
		bufPtr = &b
	}
	return bufPtr
}

func putCryptoBuffer(bufPtr *[]byte) {
	if bufPtr != nil {
		cryptoBufferPool.Put(bufPtr)
	}
}

type Codec struct {
	method  int
	key     []byte
	encrypt func(dst, src []byte) ([]byte, error)
	decrypt func(dst, src []byte) ([]byte, error)
}

func NewCodecFromConfig(cfg config.ServerConfig, rawKey string) (*Codec, error) {
	return NewCodec(cfg.DataEncryptionMethod, rawKey)
}

func NewCodec(method int, rawKey string) (*Codec, error) {
	if method < 0 || method > 5 {
		return nil, ErrInvalidCodecMethod
	}

	derivedKey := deriveKey(method, rawKey)
	codec := &Codec{
		method: method,
		key:    derivedKey,
	}

	switch method {
	case 0:
		codec.encrypt = codec.noCrypto
		codec.decrypt = codec.noCrypto
	case 1:
		codec.encrypt = codec.xorCrypto
		codec.decrypt = codec.xorCrypto
	case 2:
		codec.encrypt = codec.chachaEncrypt
		codec.decrypt = codec.chachaDecrypt
	case 3, 4, 5:
		aead, err := newAESGCM(derivedKey)
		if err != nil {
			return nil, err
		}
		codec.encrypt = codec.makeAESEncryptor(aead)
		codec.decrypt = codec.makeAESDecryptor(aead)
	default:
		return nil, ErrInvalidCodecMethod
	}

	return codec, nil
}

func (c *Codec) Encrypt(data []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidCodecMethod
	}
	return c.encrypt(nil, data)
}

func (c *Codec) Decrypt(data []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidCodecMethod
	}
	return c.decrypt(nil, data)
}

func (c *Codec) Method() int {
	if c == nil {
		return 0
	}
	return c.method
}

func (c *Codec) EncryptAndEncode(data []byte) (string, error) {
	if c == nil {
		return "", ErrInvalidCodecMethod
	}
	if c.method == 0 {
		return baseCodec.Encode(data), nil
	}

	bufPtr := getCryptoBuffer(len(data) + 64)
	defer putCryptoBuffer(bufPtr)

	encrypted, err := c.encrypt((*bufPtr)[:0], data)
	if err != nil {
		return "", err
	}
	return baseCodec.Encode(encrypted), nil
}

func (c *Codec) EncryptAndEncodeBytes(data []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidCodecMethod
	}
	if c.method == 0 {
		return baseCodec.EncodeToBytes(data), nil
	}

	bufPtr := getCryptoBuffer(len(data) + 64)
	defer putCryptoBuffer(bufPtr)

	encrypted, err := c.encrypt((*bufPtr)[:0], data)
	if err != nil {
		return nil, err
	}
	return baseCodec.EncodeToBytes(encrypted), nil
}

func (c *Codec) DecodeAndDecrypt(data []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidCodecMethod
	}

	decoded, err := baseCodec.Decode(data)
	if err != nil {
		return nil, err
	}
	if c.method == 0 {
		return decoded, nil
	}
	return c.decrypt(nil, decoded)
}

func (c *Codec) DecodeStringAndDecrypt(data string) ([]byte, error) {
	if c == nil {
		return nil, ErrInvalidCodecMethod
	}

	decoded, err := baseCodec.DecodeString(data)
	if err != nil {
		return nil, err
	}
	if c.method == 0 {
		return decoded, nil
	}
	return c.decrypt(nil, decoded)
}

func (c *Codec) noCrypto(dst, data []byte) ([]byte, error) {
	if cap(dst) < len(data) {
		dst = make([]byte, len(data))
	} else {
		dst = dst[:len(data)]
	}
	copy(dst, data)
	return dst, nil
}

func (c *Codec) xorCrypto(dst, data []byte) ([]byte, error) {
	key := c.key
	keyLen := len(key)
	if len(data) == 0 || keyLen == 0 {
		if cap(dst) < len(data) {
			dst = make([]byte, len(data))
		} else {
			dst = dst[:len(data)]
		}
		copy(dst, data)
		return dst, nil
	}

	if cap(dst) < len(data) {
		dst = make([]byte, len(data))
	} else {
		dst = dst[:len(data)]
	}

	if keyLen == 1 {
		mask := key[0]
		for i := 0; i < len(data); i++ {
			dst[i] = data[i] ^ mask
		}
		return dst, nil
	}

	fullBlocks := len(data) / keyLen
	offset := 0
	for block := 0; block < fullBlocks; block++ {
		for i := 0; i < keyLen; i++ {
			dst[offset+i] = data[offset+i] ^ key[i]
		}
		offset += keyLen
	}
	for i := offset; i < len(data); i++ {
		dst[i] = data[i] ^ key[i-offset]
	}
	return dst, nil
}

func (c *Codec) chachaEncrypt(dst, data []byte) ([]byte, error) {
	if len(data) == 0 {
		if cap(dst) == 0 {
			dst = make([]byte, 0)
		} else {
			dst = dst[:0]
		}
		return dst, nil
	}

	reqSize := chachaNonceSize + len(data)
	if cap(dst) < reqSize {
		dst = make([]byte, reqSize)
	} else {
		dst = dst[:reqSize]
	}

	nonce := dst[:chachaNonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate chacha20 nonce: %w", err)
	}

	stream, err := chacha20.NewUnauthenticatedCipher(c.key, nonce[4:])
	if err != nil {
		return nil, err
	}
	stream.SetCounter(binary.LittleEndian.Uint32(nonce[:4]))
	stream.XORKeyStream(dst[chachaNonceSize:], data)
	return dst, nil
}

func (c *Codec) chachaDecrypt(dst, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil // Return nil per original intention
	}
	if len(data) <= chachaNonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce := data[:chachaNonceSize]
	ciphertext := data[chachaNonceSize:]

	if cap(dst) < len(ciphertext) {
		dst = make([]byte, len(ciphertext))
	} else {
		dst = dst[:len(ciphertext)]
	}

	stream, err := chacha20.NewUnauthenticatedCipher(c.key, nonce[4:])
	if err != nil {
		return nil, err
	}
	stream.SetCounter(binary.LittleEndian.Uint32(nonce[:4]))

	stream.XORKeyStream(dst, ciphertext)
	return dst, nil
}

func (c *Codec) makeAESEncryptor(aead cipher.AEAD) func(dst, src []byte) ([]byte, error) {
	return func(dst, src []byte) ([]byte, error) {
		if len(src) == 0 {
			if cap(dst) == 0 {
				dst = make([]byte, 0)
			} else {
				dst = dst[:0]
			}
			return dst, nil
		}

		reqSize := aesNonceSize + len(src) + aead.Overhead()
		if cap(dst) < reqSize {
			dst = make([]byte, aesNonceSize, reqSize)
		} else {
			dst = dst[:aesNonceSize]
		}

		nonce := dst[:aesNonceSize]
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generate aes-gcm nonce: %w", err)
		}

		dst = aead.Seal(dst, nonce, src, nil)
		return dst, nil
	}
}

func (c *Codec) makeAESDecryptor(aead cipher.AEAD) func(dst, src []byte) ([]byte, error) {
	return func(dst, src []byte) ([]byte, error) {
		if len(src) == 0 {
			return nil, nil
		}
		if len(src) <= aesNonceSize {
			return nil, ErrInvalidCiphertext
		}

		nonce := src[:aesNonceSize]
		ciphertext := src[aesNonceSize:]

		if cap(dst) == 0 {
			dst = make([]byte, 0, len(ciphertext))
		} else {
			dst = dst[:0]
		}

		plaintext, err := aead.Open(dst, nonce, ciphertext, nil)
		if err != nil {
			return nil, ErrInvalidCiphertext
		}
		return plaintext, nil
	}
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create aes-gcm: %w", err)
	}
	return aead, nil
}

func deriveKey(method int, rawKey string) []byte {
	bKey := []byte(rawKey)
	targetLen := requiredDerivedKeyLength(method)

	switch method {
	case 2, 5:
		sum := sha256.Sum256(bKey)
		return sum[:]
	case 3:
		sum := md5.Sum(bKey)
		return sum[:]
	default:
		key := make([]byte, targetLen)
		copy(key, bKey)
		return key
	}
}

func requiredDerivedKeyLength(method int) int {
	switch method {
	case 2, 5:
		return 32
	case 3:
		return 16
	case 4:
		return 24
	default:
		return 32
	}
}
