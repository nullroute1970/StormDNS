// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package enums

const (
	PacketPriorityCritical = 0
	PacketPriorityRetry    = 1
	PacketPriorityHigh     = 2
	PacketPriorityNormal   = 3
	PacketPriorityLow      = 4
	PacketPriorityIdle     = 5
)

// DefaultPacketPriority centralizes the queue priority for each packet type.
// Lower numbers mean higher priority.
func DefaultPacketPriority(packetType uint8) int {
	switch packetType {
	case PACKET_STREAM_DATA_ACK,
		PACKET_STREAM_DATA_NACK,
		PACKET_STREAM_SYN,
		PACKET_STREAM_SYN_ACK,
		PACKET_STREAM_CONNECTED,
		PACKET_STREAM_CONNECTED_ACK,
		PACKET_STREAM_CONNECT_FAIL,
		PACKET_STREAM_CONNECT_FAIL_ACK,
		PACKET_STREAM_CLOSE_WRITE_ACK,
		PACKET_STREAM_CLOSE_READ,
		PACKET_STREAM_CLOSE_READ_ACK,
		PACKET_STREAM_RST,
		PACKET_STREAM_RST_ACK,
		PACKET_SOCKS5_SYN,
		PACKET_SOCKS5_SYN_ACK,
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
		PACKET_DNS_QUERY_REQ_ACK,
		PACKET_DNS_QUERY_RES_ACK:
		return PacketPriorityCritical

	case PACKET_STREAM_RESEND,
		PACKET_DNS_QUERY_RES,
		PACKET_DNS_QUERY_REQ:
		return PacketPriorityRetry

	case PACKET_STREAM_DATA:
		return PacketPriorityNormal

	case PACKET_STREAM_CLOSE_WRITE,
		PACKET_SESSION_CLOSE:
		return PacketPriorityLow

	case PACKET_PING,
		PACKET_PONG:
		return PacketPriorityIdle

	default:
		return PacketPriorityNormal
	}
}

func NormalizePacketPriority(packetType uint8, priority int) int {
	if priority >= PacketPriorityCritical && priority <= PacketPriorityIdle {
		return priority
	}
	return DefaultPacketPriority(packetType)
}
