// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package vpnproto

import (
	Enums "stormdns-go/internal/enums"
	"strconv"
	"strings"
)

// PackedControlBlockSize is the fixed size of each block inside a PACKET_PACKED_CONTROL_BLOCKS (Type 14)
// Structure: Type(1) + StreamID(2) + SeqNum(2) + FragID(1) + Total(1) = 7 Bytes
const PackedControlBlockSize = 7

// IsPackableControlPacket returns true if a packet type is eligible for packing.
// Only control packets without payload should be packed.
func IsPackableControlPacket(packetType uint8, payloadLen int) bool {
	if payloadLen != 0 {
		return false
	}

	switch packetType {
	case Enums.PACKET_STREAM_DATA_ACK,
		Enums.PACKET_STREAM_DATA_NACK,
		Enums.PACKET_STREAM_SYN_ACK,
		Enums.PACKET_STREAM_CLOSE_WRITE_ACK,
		Enums.PACKET_STREAM_CLOSE_READ_ACK,
		Enums.PACKET_STREAM_RST_ACK,
		Enums.PACKET_SOCKS5_SYN_ACK,
		Enums.PACKET_STREAM_CONNECTED,
		Enums.PACKET_STREAM_CONNECTED_ACK,
		Enums.PACKET_STREAM_CONNECT_FAIL,
		Enums.PACKET_STREAM_CONNECT_FAIL_ACK,
		Enums.PACKET_SOCKS5_CONNECT_FAIL,
		Enums.PACKET_SOCKS5_RULESET_DENIED,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED,
		Enums.PACKET_SOCKS5_TTL_EXPIRED,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
		Enums.PACKET_SOCKS5_AUTH_FAILED,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
		Enums.PACKET_SOCKS5_CONNECTED,
		Enums.PACKET_SOCKS5_CONNECTED_ACK,
		Enums.PACKET_SOCKS5_CONNECT_FAIL_ACK,
		Enums.PACKET_SOCKS5_RULESET_DENIED_ACK,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
		Enums.PACKET_SOCKS5_TTL_EXPIRED_ACK,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_AUTH_FAILED_ACK,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
		Enums.PACKET_DNS_QUERY_REQ_ACK,
		Enums.PACKET_DNS_QUERY_RES_ACK:
		return true
	default:
		return false
	}
}

// AppendPackedControlBlock serializes a control packet metadata into a 7-byte block and appends it to dst.
func AppendPackedControlBlock(dst []byte, ptype uint8, streamID uint16, sn uint16, fragID uint8, total uint8) []byte {
	return append(dst,
		ptype,
		uint8(streamID>>8), uint8(streamID),
		uint8(sn>>8), uint8(sn),
		fragID,
		total,
	)
}

// ForEachPackedControlBlock iterates over a Type 14 payload and invokes yield for each block.
func ForEachPackedControlBlock(payload []byte, yield func(ptype uint8, streamID uint16, sn uint16, fragID uint8, total uint8) bool) {
	if payload == nil || yield == nil {
		return
	}

	for offset := 0; offset+PackedControlBlockSize <= len(payload); offset += PackedControlBlockSize {
		ptype := payload[offset]
		streamID := uint16(payload[offset+1])<<8 | uint16(payload[offset+2])
		sn := uint16(payload[offset+3])<<8 | uint16(payload[offset+4])
		fragID := payload[offset+5]
		total := payload[offset+6]

		if !yield(ptype, streamID, sn, fragID, total) {
			break
		}
	}
}

// DescribePackedControlBlocks returns a compact summary suitable for logs.
// Example: "Blocks(4): PACKET_STREAM_DATA_ACK x2, PACKET_STREAM_DATA_NACK x1, PACKET_STREAM_CLOSE_WRITE_ACK x1"
func DescribePackedControlBlocks(payload []byte, maxKinds int) string {
	if len(payload) == 0 {
		return "Blocks(0)"
	}
	if maxKinds <= 0 {
		maxKinds = 4
	}

	order := make([]uint8, 0, maxKinds)
	counts := make(map[uint8]int)
	totalBlocks := 0

	ForEachPackedControlBlock(payload, func(ptype uint8, _ uint16, _ uint16, _ uint8, _ uint8) bool {
		totalBlocks++
		if _, exists := counts[ptype]; !exists {
			order = append(order, ptype)
		}
		counts[ptype]++
		return true
	})

	if totalBlocks == 0 {
		return "Blocks(0)"
	}

	var b strings.Builder
	b.WriteString("Blocks(")
	b.WriteString(strconv.Itoa(totalBlocks))
	b.WriteString("): ")

	limit := len(order)
	if limit > maxKinds {
		limit = maxKinds
	}

	for i := 0; i < limit; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		ptype := order[i]
		b.WriteString(Enums.PacketTypeName(ptype))
		b.WriteString(" x")
		b.WriteString(strconv.Itoa(counts[ptype]))
	}

	if len(order) > limit {
		b.WriteString(", +")
		b.WriteString(strconv.Itoa(len(order) - limit))
		b.WriteString(" more types")
	}

	return b.String()
}
