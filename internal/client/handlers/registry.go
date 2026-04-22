// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package handlers

import (
	"fmt"
	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/logger"
	VpnProto "stormdns-go/internal/vpnproto"
	"net"
)

// ClientContext defines the interface that the client must implement to be handled.
// This prevents circular dependencies between the 'client' and 'handlers' packages.
type ClientContext interface {
	Log() *logger.Logger
	SessionID() uint8
	IsSessionReady() bool
	ResponseMode() uint8
	NotifyPacket(packetType uint8, isInbound bool)
	PreprocessInboundPacket(packet VpnProto.Packet) bool

	// Stream Management
	HandleStreamPacket(packet VpnProto.Packet) error

	// Session Management
	HandleSessionReject(packet VpnProto.Packet) error
	HandleSessionBusy() error
	HandleErrorDrop(packet VpnProto.Packet) error

	// MTU Management
	HandleMTUResponse(packet VpnProto.Packet) error

	// DNS Management
	HandleDNSQueryAck(packet VpnProto.Packet) error
	HandleDNSQueryRes(packet VpnProto.Packet) error

	// SOCKS5 Management
	HandleSocksConnected(packet VpnProto.Packet) error
	HandleSocksFailure(packet VpnProto.Packet) error
	HandleSocksControlAck(packet VpnProto.Packet) error
}

// HandlerFunc is the signature for all packet type handlers.
type HandlerFunc func(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error

var (
	// dispatchTable provides O(1) routing for all packet types.
	dispatchTable [256]HandlerFunc
)

// RegisterHandler binds a handler function to a specific packet type.
func RegisterHandler(packetType uint8, handler HandlerFunc) {
	dispatchTable[packetType] = handler
}

// Dispatch routes an inbound VPN packet to its registered handler.
func Dispatch(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	if c == nil {
		return fmt.Errorf("dispatch failed: nil client context")
	}

	// 2. Lookup handler
	handler := dispatchTable[packet.PacketType]
	if handler != nil {
		return handler(c, packet, addr)
	}

	// 3. Fallback or Generic Handling
	return handleGenericPacket(c, packet, addr)
}

func handleGenericPacket(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	switch packet.PacketType {
	case 0, Enums.PACKET_PONG:
		// Silently ignore keepalives/empty packets
		return nil
	default:
		c.Log().Warnf("\U0001F937 <yellow>No handler registered for packet type: %d</yellow>", packet.PacketType)
		return nil
	}
}

func init() {
	// Initial placeholder registrations can go here, but final ones will be in specific files.
}
