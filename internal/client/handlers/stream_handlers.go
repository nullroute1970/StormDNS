// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package handlers

import (
	"net"

	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

func init() {
	streamTypes := []uint8{
		Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_DATA_ACK,
		Enums.PACKET_STREAM_DATA_NACK,
		Enums.PACKET_STREAM_RESEND,
		Enums.PACKET_STREAM_SYN,
		Enums.PACKET_STREAM_SYN_ACK,
		Enums.PACKET_STREAM_CONNECTED,
		Enums.PACKET_STREAM_CONNECTED_ACK,
		Enums.PACKET_STREAM_CONNECT_FAIL,
		Enums.PACKET_STREAM_CONNECT_FAIL_ACK,
		Enums.PACKET_STREAM_CLOSE_WRITE,
		Enums.PACKET_STREAM_CLOSE_WRITE_ACK,
		Enums.PACKET_STREAM_CLOSE_READ,
		Enums.PACKET_STREAM_CLOSE_READ_ACK,
		Enums.PACKET_STREAM_RST,
		Enums.PACKET_STREAM_RST_ACK,
	}

	for _, pt := range streamTypes {
		RegisterHandler(pt, handleStreamPacket)
	}
}

func handleStreamPacket(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleStreamPacket(packet)
}
