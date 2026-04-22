// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"errors"

	"stormdns-go/internal/compression"
	"stormdns-go/internal/security"
)

var ErrInvalidCompressedPayload = errors.New("invalid compressed vpn payload")

func PreparePayload(packetType uint8, payload []byte, requestedCompression uint8, minSize int) ([]byte, uint8) {
	requestedCompression = compression.NormalizeAvailableType(requestedCompression)
	if requestedCompression == compression.TypeOff {
		return payload, compression.TypeOff
	}

	if !hasCompressionExtension(packetType) {
		return payload, compression.TypeOff
	}
	if len(payload) == 0 {
		return payload, compression.TypeOff
	}
	return compression.CompressPayload(payload, requestedCompression, minSize)
}

func InflatePayload(packet Packet) (Packet, error) {
	if !packet.HasCompressionType || packet.CompressionType == compression.TypeOff {
		return packet, nil
	}

	payload, ok := compression.TryDecompressPayload(packet.Payload, packet.CompressionType)
	if !ok {
		return Packet{}, ErrInvalidCompressedPayload
	}
	packet.Payload = payload
	return packet, nil
}

func ParseInflatedFromLabels(labels string, codec *security.Codec) (Packet, error) {
	packet, err := ParseFromLabels(labels, codec)
	if err != nil {
		return Packet{}, err
	}

	return InflatePayload(packet)
}

func ParseInflated(data []byte) (Packet, error) {
	packet, err := Parse(data)
	if err != nil {
		return Packet{}, err
	}

	return InflatePayload(packet)
}

func BuildRawAuto(opts BuildOptions, minSize int) ([]byte, error) {
	payload, compressionType := PreparePayload(opts.PacketType, opts.Payload, opts.CompressionType, minSize)
	opts.Payload = payload
	opts.CompressionType = compressionType
	return BuildRaw(opts)
}

func BuildEncodedAuto(opts BuildOptions, codec *security.Codec, minSize int) (string, error) {
	raw, err := BuildRawAuto(opts, minSize)
	if err != nil {
		return "", err
	}
	if codec == nil {
		return "", ErrCodecUnavailable
	}
	return codec.EncryptAndEncode(raw)
}
