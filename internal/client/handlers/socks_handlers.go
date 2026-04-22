// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package handlers

import (
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
	"net"
)

func init() {
	// Register SOCKS5 success handler
	RegisterHandler(Enums.PACKET_SOCKS5_CONNECTED, handleSocksConnected)

	// Register SOCKS5 failure handlers
	failureTypes := []uint8{
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
	}

	for _, pt := range failureTypes {
		RegisterHandler(pt, handleSocksFailure)
	}

	// Register SOCKS5 control ACKs (if they skip general ReceiveControlAck)
	RegisterHandler(Enums.PACKET_SOCKS5_SYN_ACK, handleSocksControlAck)
}

func handleSocksConnected(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleSocksConnected(packet)
}

func handleSocksFailure(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleSocksFailure(packet)
}

func handleSocksControlAck(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleSocksControlAck(packet)
}
