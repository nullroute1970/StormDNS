// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package vpnproto

import "stormdns-go/internal/security"

type BuildOptions struct {
	SessionID       uint8
	PacketType      uint8
	SessionCookie   uint8
	StreamID        uint16
	SequenceNum     uint16
	FragmentID      uint8
	TotalFragments  uint8
	CompressionType uint8
	Payload         []byte
}

func BuildRaw(opts BuildOptions) ([]byte, error) {
	flags := packetFlags[opts.PacketType]
	if flags&packetFlagValid == 0 {
		return nil, ErrInvalidPacketType
	}

	headerLen := 2 + integrityLength // SessionID + PacketType + SessionCookie + Integrity
	if flags&packetFlagStream != 0 {
		headerLen += 2
	}
	if flags&packetFlagSequence != 0 {
		headerLen += 2
	}
	if flags&packetFlagFragment != 0 {
		headerLen += 2
	}
	if flags&packetFlagCompression != 0 {
		headerLen++
	}

	raw := make([]byte, headerLen+len(opts.Payload))
	raw[0] = opts.SessionID
	raw[1] = opts.PacketType
	offset := 2

	if flags&packetFlagStream != 0 {
		raw[offset] = byte(opts.StreamID >> 8)
		raw[offset+1] = byte(opts.StreamID)
		offset += 2
	}
	if flags&packetFlagSequence != 0 {
		raw[offset] = byte(opts.SequenceNum >> 8)
		raw[offset+1] = byte(opts.SequenceNum)
		offset += 2
	}
	if flags&packetFlagFragment != 0 {
		raw[offset] = opts.FragmentID
		raw[offset+1] = opts.TotalFragments
		offset += 2
	}
	if flags&packetFlagCompression != 0 {
		raw[offset] = opts.CompressionType
		offset++
	}

	raw[offset] = opts.SessionCookie
	offset++
	raw[offset] = computeHeaderCheckByte(raw[:offset])
	offset++
	copy(raw[offset:], opts.Payload)
	return raw, nil
}

func BuildEncoded(opts BuildOptions, codec *security.Codec) (string, error) {
	raw, err := BuildRaw(opts)
	if err != nil {
		return "", err
	}
	if codec == nil {
		return "", ErrCodecUnavailable
	}
	return codec.EncryptAndEncode(raw)
}

func HeaderRawSize(packetType uint8) int {
	flags := packetFlags[packetType]
	if flags&packetFlagValid == 0 {
		return 0
	}

	size := 2 + integrityLength
	if flags&packetFlagStream != 0 {
		size += 2
	}
	if flags&packetFlagSequence != 0 {
		size += 2
	}
	if flags&packetFlagFragment != 0 {
		size += 2
	}
	if flags&packetFlagCompression != 0 {
		size++
	}
	return size
}

func MaxHeaderRawSize() int {
	maxSize := 0
	for packetType := range len(packetFlags) {
		size := HeaderRawSize(uint8(packetType))
		if size > maxSize {
			maxSize = size
		}
	}
	return maxSize
}

func MaxHeaderPacketType() uint8 {
	var bestType uint8
	maxSize := 0
	for packetType := range len(packetFlags) {
		size := HeaderRawSize(uint8(packetType))
		if size > maxSize {
			maxSize = size
			bestType = uint8(packetType)
		}
	}
	return bestType
}
