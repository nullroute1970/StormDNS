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
	RegisterHandler(Enums.PACKET_DNS_QUERY_REQ_ACK, handleDNSQueryAck)
	RegisterHandler(Enums.PACKET_DNS_QUERY_RES, handleDNSQueryRes)
}

func handleDNSQueryAck(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleDNSQueryAck(packet)
}

func handleDNSQueryRes(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleDNSQueryRes(packet)
}
