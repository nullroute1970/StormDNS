package vpnproto

import (
	"testing"

	Enums "stormdns-go/internal/enums"
)

func TestIsPackableControlPacketIncludesSmallSocksResults(t *testing.T) {
	packetTypes := []uint8{
		Enums.PACKET_SOCKS5_SYN_ACK,
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
	}

	for _, packetType := range packetTypes {
		if !IsPackableControlPacket(packetType, 0) {
			t.Fatalf("expected packet type 0x%02X to be packable without payload", packetType)
		}
		if IsPackableControlPacket(packetType, 1) {
			t.Fatalf("expected packet type 0x%02X to be non-packable with payload", packetType)
		}
	}
}
