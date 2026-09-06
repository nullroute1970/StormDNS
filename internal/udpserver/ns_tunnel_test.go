// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
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

// patternBytes produces deterministic pseudo-random data that does not compress,
// so frame sizes (and thus NS chunk counts) stay stable.
func patternBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*31 + 7)
	}
	return out
}

func TestNSTunnelQueryAcceptedEndToEnd(t *testing.T) {
	// 1. An NS-type tunnel query for a data-bearing name passes the domain matcher.
	matcher := domainMatcher.New([]string{"v.example.com"}, 3)
	query, err := DnsParser.BuildTunnelTXTQuestionPacket("abc.v.example.com", []byte("q3f2abc"), Enums.DNS_RECORD_TYPE_NS, 0)
	if err != nil {
		t.Fatal(err)
	}
	lite, err := DnsParser.ParseDNSRequestLite(query)
	if err != nil {
		t.Fatal(err)
	}
	decision := matcher.Match(lite)
	if decision.Action != domainMatcher.ActionProcess {
		t.Fatalf("NS tunnel query rejected: action=%v reason=%s", decision.Action, decision.Reason)
	}

	// 2. The real server response handler mirrors the question type into NS answers.
	s := &Server{
		mtuProbePayloadPool: sync.Pool{
			New: func() any {
				return make([]byte, mtuProbeMaxDownSize)
			},
		},
	}

	downloadSize := 300 // forces multi-chunk NS framing
	payload := make([]byte, mtuProbeDownMinSize+downloadSize)
	payload[0] = mtuProbeModeRaw
	copy(payload[1:1+mtuProbeCodeLength], []byte{9, 8, 7, 6})
	binary.BigEndian.PutUint16(payload[mtuProbeUpMinSize:mtuProbeDownMinSize], uint16(downloadSize))
	copy(payload[mtuProbeDownMinSize:], patternBytes(downloadSize))

	response := s.handleMTUDownRequest(query, lite, decision, VpnProto.Packet{
		SessionID:   9,
		PacketType:  Enums.PACKET_MTU_DOWN_REQ,
		StreamID:    1,
		SequenceNum: 2,
		Payload:     payload,
	})
	if response == nil {
		t.Fatal("expected response packet")
	}

	parsed, err := DnsParser.ParsePacket(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) < 2 {
		t.Fatalf("expected multiple NS answers, got %d", len(parsed.Answers))
	}
	for i, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_NS {
			t.Fatalf("answer %d type = %d, want NS", i, ans.Type)
		}
	}

	// 3. The client-side extractor recovers the payload from the NS answers.
	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_DOWN_RES)
	}
	if len(packet.Payload) != downloadSize {
		t.Fatalf("unexpected payload len: got=%d want=%d", len(packet.Payload), downloadSize)
	}
	if got := packet.Payload[:mtuProbeCodeLength]; string(got) != string([]byte{9, 8, 7, 6}) {
		t.Fatalf("unexpected probe code: got=%v", got)
	}
}
