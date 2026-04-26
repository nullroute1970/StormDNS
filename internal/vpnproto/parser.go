// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"errors"

	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/security"
)

var (
	ErrPacketTooShort      = errors.New("vpn packet too short")
	ErrInvalidPacketType   = errors.New("invalid vpn packet type")
	ErrInvalidHeaderCheck  = errors.New("invalid vpn header check")
	ErrInvalidEncodedData  = errors.New("invalid encoded vpn labels")
	ErrCodecUnavailable    = errors.New("vpn codec unavailable")
	ErrInvalidFragmentInfo = errors.New("invalid vpn fragment info")
)

const (
	integrityLength = 2
	minHeaderLength = 4

	packetFlagValid = 1 << iota
	packetFlagStream
	packetFlagSequence
	packetFlagFragment
	packetFlagCompression
)

var packetFlags = buildPacketFlags()

// Header layout copied from the Python parser, with one change:
// `total_data_length` has been removed from the fragment extension.
//
// Base header:
//   [0] Session ID     (1 byte)
//   [1] Packet Type    (1 byte)
//
// Optional extensions by packet type:
//   Stream extension:
//     [2..3] Stream ID         (2 bytes)
//   Sequence extension:
//     [+2]   Sequence Number   (2 bytes)
//   Fragment extension:
//     [+1]   Fragment ID       (1 byte)
//     [+1]   Total Fragments   (1 byte)
//   Compression extension:
//     [+1]   Compression Type  (1 byte)
//
// Integrity footer:
//   [+1] Session Cookie  (1 byte)
//   [+1] Header Check    (1 byte)
//
// Payload starts immediately after the header check byte.

type Packet struct {
	SessionID     uint8
	PacketType    uint8
	SessionCookie uint8

	HasStreamID bool
	StreamID    uint16

	HasSequenceNum bool
	SequenceNum    uint16

	HasFragmentInfo bool
	FragmentID      uint8
	TotalFragments  uint8

	HasCompressionType bool
	CompressionType    uint8

	HeaderLength int
	Payload      []byte
}

func ParseFromLabels(labels string, codec *security.Codec) (Packet, error) {
	if codec == nil {
		return Packet{}, ErrCodecUnavailable
	}
	if labels == "" {
		return Packet{}, ErrInvalidEncodedData
	}

	raw, err := codec.DecodeStringAndDecrypt(labels)
	if err != nil {
		return Packet{}, err
	}

	return Parse(raw)
}

func Parse(data []byte) (Packet, error) {
	return ParseAtOffset(data, 0)
}

func ParseAtOffset(data []byte, offset int) (Packet, error) {
	if offset < 0 || offset >= len(data) {
		return Packet{}, ErrPacketTooShort
	}
	return parseFrom(data, offset)
}

func parseFrom(data []byte, start int) (Packet, error) {
	data = data[start:]
	if len(data) < minHeaderLength {
		return Packet{}, ErrPacketTooShort
	}

	packetType := data[1]
	flags := packetFlags[packetType]
	if flags&packetFlagValid == 0 {
		return Packet{}, ErrInvalidPacketType
	}

	// Fast-path length check
	minLen := 2 + integrityLength
	if flags&packetFlagStream != 0 {
		minLen += 2
	}
	if flags&packetFlagSequence != 0 {
		minLen += 2
	}
	if flags&packetFlagFragment != 0 {
		minLen += 2
	}
	if flags&packetFlagCompression != 0 {
		minLen++
	}

	if len(data) < minLen {
		return Packet{}, ErrPacketTooShort
	}

	packet := Packet{
		SessionID:  data[0],
		PacketType: packetType,
	}

	offset := 2
	if flags&packetFlagStream != 0 {
		packet.HasStreamID = true
		packet.StreamID = (uint16(data[offset]) << 8) | uint16(data[offset+1])
		offset += 2
	}

	if flags&packetFlagSequence != 0 {
		packet.HasSequenceNum = true
		packet.SequenceNum = (uint16(data[offset]) << 8) | uint16(data[offset+1])
		offset += 2
	}

	if flags&packetFlagFragment != 0 {
		packet.HasFragmentInfo = true
		packet.FragmentID = data[offset]
		packet.TotalFragments = data[offset+1]
		offset += 2
		// Defensive validation: when a packet declares actual fragmentation
		// (TotalFragments > 1), reject any FragmentID outside the valid
		// range so downstream reassembly never sees out-of-bounds indices.
		// TotalFragments of 0 or 1 means "single packet, no reassembly" by
		// existing protocol convention and is left untouched here.
		if packet.TotalFragments > 1 && packet.FragmentID >= packet.TotalFragments {
			return Packet{}, ErrInvalidFragmentInfo
		}
	}

	if flags&packetFlagCompression != 0 {
		packet.HasCompressionType = true
		packet.CompressionType = data[offset]
		offset++
	}

	packet.SessionCookie = data[offset]
	checkByte := data[offset+1]
	expected := computeHeaderCheckByte(data[:offset+1])
	if checkByte != expected {
		return Packet{}, ErrInvalidHeaderCheck
	}

	packet.HeaderLength = offset + integrityLength
	packet.Payload = data[packet.HeaderLength:]
	return packet, nil
}

func computeHeaderCheckByte(header []byte) byte {
	acc := byte(len(header)*17 + 0x5D)
	for idx, value := range header {
		acc += value + byte(idx)
		acc ^= value << (idx & 0x03)
	}
	return acc
}

func hasStreamExtension(packetType uint8) bool {
	return packetFlags[packetType]&packetFlagStream != 0
}

func hasSequenceExtension(packetType uint8) bool {
	return packetFlags[packetType]&packetFlagSequence != 0
}

func hasFragmentExtension(packetType uint8) bool {
	return packetFlags[packetType]&packetFlagFragment != 0
}

func hasCompressionExtension(packetType uint8) bool {
	return packetFlags[packetType]&packetFlagCompression != 0
}

func buildPacketFlags() [256]uint8 {
	var flags [256]uint8

	setValid := func(packetType uint8) {
		flags[packetType] |= packetFlagValid
	}
	set := func(packetType uint8, extra uint8) {
		flags[packetType] |= packetFlagValid | extra
	}

	validOnly := [...]uint8{
		Enums.PACKET_MTU_UP_RES,
		Enums.PACKET_MTU_DOWN_REQ,
		Enums.PACKET_SESSION_INIT,
		Enums.PACKET_SESSION_ACCEPT,
		Enums.PACKET_SESSION_BUSY,
		Enums.PACKET_SESSION_CLOSE,
		Enums.PACKET_PING,
		Enums.PACKET_PONG,
		Enums.PACKET_ERROR_DROP,
		Enums.PACKET_MTU_UP_REQ,
		Enums.PACKET_MTU_DOWN_RES,
	}

	for _, packetType := range validOnly {
		setValid(packetType)
	}

	streamAndSeq := [...]uint8{
		Enums.PACKET_STREAM_SYN,
		Enums.PACKET_STREAM_SYN_ACK,
		Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_DATA_ACK,
		Enums.PACKET_STREAM_DATA_NACK,
		Enums.PACKET_STREAM_RESEND,
		Enums.PACKET_STREAM_CLOSE_WRITE,
		Enums.PACKET_STREAM_CLOSE_WRITE_ACK,
		Enums.PACKET_STREAM_CLOSE_READ,
		Enums.PACKET_STREAM_CLOSE_READ_ACK,
		Enums.PACKET_STREAM_RST,
		Enums.PACKET_STREAM_RST_ACK,
		Enums.PACKET_MTU_UP_REQ,
		Enums.PACKET_MTU_DOWN_RES,
		Enums.PACKET_SOCKS5_SYN,
		Enums.PACKET_SOCKS5_SYN_ACK,
		Enums.PACKET_STREAM_CONNECTED,
		Enums.PACKET_STREAM_CONNECTED_ACK,
		Enums.PACKET_STREAM_CONNECT_FAIL,
		Enums.PACKET_STREAM_CONNECT_FAIL_ACK,
		Enums.PACKET_SOCKS5_CONNECT_FAIL,
		Enums.PACKET_SOCKS5_CONNECT_FAIL_ACK,
		Enums.PACKET_SOCKS5_RULESET_DENIED,
		Enums.PACKET_SOCKS5_RULESET_DENIED_ACK,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
		Enums.PACKET_SOCKS5_TTL_EXPIRED,
		Enums.PACKET_SOCKS5_TTL_EXPIRED_ACK,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_AUTH_FAILED,
		Enums.PACKET_SOCKS5_AUTH_FAILED_ACK,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
		Enums.PACKET_SOCKS5_CONNECTED,
		Enums.PACKET_SOCKS5_CONNECTED_ACK,
		Enums.PACKET_DNS_QUERY_REQ,
		Enums.PACKET_DNS_QUERY_RES,
		Enums.PACKET_DNS_QUERY_REQ_ACK,
		Enums.PACKET_DNS_QUERY_RES_ACK,
	}

	for _, packetType := range streamAndSeq {
		set(packetType, packetFlagStream|packetFlagSequence)
	}

	frag := [...]uint8{
		Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_RESEND,
		Enums.PACKET_SOCKS5_SYN,
		Enums.PACKET_DNS_QUERY_REQ,
		Enums.PACKET_DNS_QUERY_RES,
		Enums.PACKET_DNS_QUERY_REQ_ACK,
		Enums.PACKET_DNS_QUERY_RES_ACK,
		Enums.PACKET_MTU_UP_REQ,
		Enums.PACKET_MTU_DOWN_RES,
	}
	for _, packetType := range frag {
		flags[packetType] |= packetFlagFragment
	}

	comp := [...]uint8{
		Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_RESEND,
		Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Enums.PACKET_DNS_QUERY_REQ,
		Enums.PACKET_DNS_QUERY_RES,
		Enums.PACKET_MTU_UP_REQ,
		Enums.PACKET_MTU_DOWN_RES,
	}

	for _, packetType := range comp {
		flags[packetType] |= packetFlagValid | packetFlagCompression
	}

	return flags
}
