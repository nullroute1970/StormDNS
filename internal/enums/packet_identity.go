// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package enums

// PacketIdentityKey builds the queue/deduplication key for stream-owned packets.
// DATA and RESEND intentionally remain distinct so retransmits can live in their
// own priority lane while enqueue policy decides coexistence.
func PacketIdentityKey(streamID uint16, packetType uint8, sequenceNum uint16, fragmentID uint8) uint64 {
	switch packetType {
	// Data and fragment-aware control packets may coexist per fragment.
	case PACKET_STREAM_DATA,
		PACKET_STREAM_RESEND,
		PACKET_STREAM_DATA_ACK,
		PACKET_STREAM_DATA_NACK,
		PACKET_STREAM_SYN,
		PACKET_STREAM_SYN_ACK,
		PACKET_SOCKS5_SYN,
		PACKET_SOCKS5_SYN_ACK,
		PACKET_DNS_QUERY_REQ,
		PACKET_DNS_QUERY_REQ_ACK,
		PACKET_DNS_QUERY_RES,
		PACKET_DNS_QUERY_RES_ACK:
		return packetIdentitySeqFrag(streamID, packetType, sequenceNum, fragmentID)

	// Terminal / result packets are unique per stream+type+sequence.
	case PACKET_STREAM_CLOSE_WRITE,
		PACKET_STREAM_CLOSE_WRITE_ACK,
		PACKET_STREAM_CLOSE_READ,
		PACKET_STREAM_CLOSE_READ_ACK,
		PACKET_STREAM_RST,
		PACKET_STREAM_RST_ACK,
		PACKET_STREAM_CONNECTED,
		PACKET_STREAM_CONNECTED_ACK,
		PACKET_STREAM_CONNECT_FAIL,
		PACKET_STREAM_CONNECT_FAIL_ACK,
		PACKET_SOCKS5_CONNECT_FAIL,
		PACKET_SOCKS5_CONNECT_FAIL_ACK,
		PACKET_SOCKS5_RULESET_DENIED,
		PACKET_SOCKS5_RULESET_DENIED_ACK,
		PACKET_SOCKS5_NETWORK_UNREACHABLE,
		PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
		PACKET_SOCKS5_HOST_UNREACHABLE,
		PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
		PACKET_SOCKS5_CONNECTION_REFUSED,
		PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
		PACKET_SOCKS5_TTL_EXPIRED,
		PACKET_SOCKS5_TTL_EXPIRED_ACK,
		PACKET_SOCKS5_COMMAND_UNSUPPORTED,
		PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
		PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
		PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
		PACKET_SOCKS5_AUTH_FAILED,
		PACKET_SOCKS5_AUTH_FAILED_ACK,
		PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
		PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
		PACKET_SOCKS5_CONNECTED,
		PACKET_SOCKS5_CONNECTED_ACK,
		PACKET_PACKED_CONTROL_BLOCKS,
		PACKET_ERROR_DROP,
		PACKET_PING,
		PACKET_PONG:
		return packetIdentitySeq(streamID, packetType, sequenceNum)

	// Session control packets should have at most one queued copy per stream owner.
	case PACKET_SESSION_CLOSE,
		PACKET_SESSION_BUSY:
		return PacketTypeStreamKey(streamID, packetType)

	default:
		return packetIdentitySeqFrag(streamID, packetType, sequenceNum, fragmentID)
	}
}

// PacketTypeStreamKey builds a coarser identity for cases where the packet type is unique
// per stream and sequence/fragment should be ignored, such as orphan fallback resets.
func PacketTypeStreamKey(streamID uint16, packetType uint8) uint64 {
	return uint64(streamID)<<40 | uint64(packetType)<<32
}

func packetIdentitySeq(streamID uint16, packetType uint8, sequenceNum uint16) uint64 {
	return uint64(streamID)<<40 | uint64(packetType)<<32 | uint64(sequenceNum)<<8
}

func packetIdentitySeqFrag(streamID uint16, packetType uint8, sequenceNum uint16, fragmentID uint8) uint64 {
	return uint64(streamID)<<40 | uint64(packetType)<<32 | uint64(sequenceNum)<<8 | uint64(fragmentID)
}
