// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package handlers

import (
	"testing"

	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/logger"
	VpnProto "stormdns-go/internal/vpnproto"
)

type packedTestClientContext struct {
	preprocessCalls int
	handledConnects int
	preprocessStop  bool
}

func (m *packedTestClientContext) Log() *logger.Logger { return nil }
func (m *packedTestClientContext) SessionID() uint8    { return 1 }
func (m *packedTestClientContext) IsSessionReady() bool {
	return true
}
func (m *packedTestClientContext) ResponseMode() uint8 { return 0 }
func (m *packedTestClientContext) NotifyPacket(packetType uint8, isInbound bool) {
}
func (m *packedTestClientContext) PreprocessInboundPacket(packet VpnProto.Packet) bool {
	m.preprocessCalls++
	return m.preprocessStop
}
func (m *packedTestClientContext) HandleStreamPacket(packet VpnProto.Packet) error {
	return nil
}
func (m *packedTestClientContext) HandleSessionReject(packet VpnProto.Packet) error {
	return nil
}
func (m *packedTestClientContext) HandleSessionBusy() error                     { return nil }
func (m *packedTestClientContext) HandleErrorDrop(packet VpnProto.Packet) error { return nil }
func (m *packedTestClientContext) HandleMTUResponse(packet VpnProto.Packet) error {
	return nil
}
func (m *packedTestClientContext) HandleDNSQueryAck(packet VpnProto.Packet) error {
	return nil
}
func (m *packedTestClientContext) HandleDNSQueryRes(packet VpnProto.Packet) error {
	return nil
}
func (m *packedTestClientContext) HandleSocksConnected(packet VpnProto.Packet) error {
	m.handledConnects++
	return nil
}
func (m *packedTestClientContext) HandleSocksFailure(packet VpnProto.Packet) error {
	return nil
}
func (m *packedTestClientContext) HandleSocksControlAck(packet VpnProto.Packet) error {
	return nil
}

func TestPackedControlBlocksPreprocessesInnerPacketsBeforeDispatch(t *testing.T) {
	ctx := &packedTestClientContext{}
	payload := VpnProto.AppendPackedControlBlock(nil, Enums.PACKET_SOCKS5_CONNECTED, 7, 0, 0, 0)
	packet := VpnProto.Packet{
		SessionID:   1,
		PacketType:  Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Payload:     payload,
		HasStreamID: true,
		StreamID:    0,
	}

	if err := handlePackedControlBlocks(ctx, packet, nil); err != nil {
		t.Fatalf("handlePackedControlBlocks returned error: %v", err)
	}

	if ctx.preprocessCalls != 1 {
		t.Fatalf("expected preprocess to run once for packed inner packet, got %d", ctx.preprocessCalls)
	}
	if ctx.handledConnects != 1 {
		t.Fatalf("expected packed inner SOCKS5_CONNECTED to be dispatched once, got %d", ctx.handledConnects)
	}
}

func TestPackedControlBlocksSkipsDispatchWhenPreprocessConsumesInnerPacket(t *testing.T) {
	ctx := &packedTestClientContext{preprocessStop: true}
	payload := VpnProto.AppendPackedControlBlock(nil, Enums.PACKET_SOCKS5_CONNECTED, 9, 0, 0, 0)
	packet := VpnProto.Packet{
		SessionID:   1,
		PacketType:  Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Payload:     payload,
		HasStreamID: true,
		StreamID:    0,
	}

	if err := handlePackedControlBlocks(ctx, packet, nil); err != nil {
		t.Fatalf("handlePackedControlBlocks returned error: %v", err)
	}

	if ctx.preprocessCalls != 1 {
		t.Fatalf("expected preprocess to run once for packed inner packet, got %d", ctx.preprocessCalls)
	}
	if ctx.handledConnects != 0 {
		t.Fatalf("expected packed inner packet dispatch to be skipped after preprocess consumed it, got %d", ctx.handledConnects)
	}
}
