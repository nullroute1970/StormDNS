package udpserver

import (
	"encoding/binary"
	"sync"
	"testing"

	DnsParser "stormdns-go/internal/dnsparser"
	domainMatcher "stormdns-go/internal/domainmatcher"
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

func TestHandleMTUDownRequestBuildsZeroFilledPayload(t *testing.T) {
	s := &Server{
		mtuProbePayloadPool: sync.Pool{
			New: func() any {
				return make([]byte, mtuProbeMaxDownSize)
			},
		},
	}

	query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	payload := make([]byte, mtuProbeDownMinSize)
	payload[0] = mtuProbeModeRaw
	copy(payload[1:1+mtuProbeCodeLength], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(payload[mtuProbeUpMinSize:mtuProbeDownMinSize], 40)

	response := s.handleMTUDownRequest(query, DnsParser.LitePacket{}, domainMatcher.Decision{RequestName: "x.v.example.com"}, VpnProto.Packet{
		SessionID:   9,
		PacketType:  Enums.PACKET_MTU_DOWN_REQ,
		StreamID:    1,
		SequenceNum: 2,
		Payload:     payload,
	})
	if response == nil {
		t.Fatal("expected response packet")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_DOWN_RES)
	}
	if len(packet.Payload) != 40 {
		t.Fatalf("unexpected payload len: got=%d want=%d", len(packet.Payload), 40)
	}
	if got := packet.Payload[:mtuProbeCodeLength]; string(got) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("unexpected probe code: got=%v", got)
	}
	if got := binary.BigEndian.Uint16(packet.Payload[mtuProbeCodeLength:mtuProbeMetaLength]); got != 40 {
		t.Fatalf("unexpected advertised length: got=%d want=%d", got, 40)
	}
	for i, b := range packet.Payload[mtuProbeMetaLength:] {
		if b != 0 {
			t.Fatalf("expected zero tail at offset %d, got=%d", i+mtuProbeMetaLength, b)
		}
	}
}
