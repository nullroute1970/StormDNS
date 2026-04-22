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
	VpnProto "stormdns-go/internal/vpnproto"
)

type mtuTestClientContext struct {
	packedTestClientContext
	mtuPackets []uint8
}

func (m *mtuTestClientContext) HandleMTUResponse(packet VpnProto.Packet) error {
	m.mtuPackets = append(m.mtuPackets, packet.PacketType)
	return nil
}

func TestDispatchRoutesMTUResponses(t *testing.T) {
	ctx := &mtuTestClientContext{}

	for _, packetType := range []uint8{Enums.PACKET_MTU_UP_RES, Enums.PACKET_MTU_DOWN_RES} {
		packet := VpnProto.Packet{PacketType: packetType}
		if err := Dispatch(ctx, packet, nil); err != nil {
			t.Fatalf("dispatch failed for packet type %d: %v", packetType, err)
		}
	}

	if len(ctx.mtuPackets) != 2 {
		t.Fatalf("expected 2 MTU packets to be handled, got %d", len(ctx.mtuPackets))
	}
	if ctx.mtuPackets[0] != Enums.PACKET_MTU_UP_RES || ctx.mtuPackets[1] != Enums.PACKET_MTU_DOWN_RES {
		t.Fatalf("unexpected MTU packets handled: %#v", ctx.mtuPackets)
	}
}
