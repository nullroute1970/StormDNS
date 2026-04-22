// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"bytes"
	"testing"

	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/security"
)

func buildRawPacket(
	t *testing.T,
	sessionID uint8,
	packetType uint8,
	streamID uint16,
	sequenceNum uint16,
	fragmentID uint8,
	totalFragments uint8,
	compressionType uint8,
	sessionCookie uint8,
	payload []byte,
) []byte {
	t.Helper()

	raw := make([]byte, 0, 16+len(payload))
	raw = append(raw, sessionID, packetType)

	if hasStreamExtension(packetType) {
		raw = append(raw, byte(streamID>>8), byte(streamID))
	}
	if hasSequenceExtension(packetType) {
		raw = append(raw, byte(sequenceNum>>8), byte(sequenceNum))
	}
	if hasFragmentExtension(packetType) {
		raw = append(raw, fragmentID, totalFragments)
	}
	if hasCompressionExtension(packetType) {
		raw = append(raw, compressionType)
	}

	raw = append(raw, sessionCookie)
	raw = append(raw, computeHeaderCheckByte(raw))
	raw = append(raw, payload...)
	return raw
}

func TestParseSessionInitPacket(t *testing.T) {
	payload := []byte("hello")
	raw := buildRawPacket(t, 7, Enums.PACKET_SESSION_INIT, 0, 0, 0, 0, 0, 9, payload)

	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if parsed.SessionID != 7 || parsed.PacketType != Enums.PACKET_SESSION_INIT {
		t.Fatalf("unexpected base fields: %+v", parsed)
	}
	if parsed.HasStreamID || parsed.HasSequenceNum || parsed.HasFragmentInfo || parsed.HasCompressionType {
		t.Fatalf("unexpected optional fields for session init: %+v", parsed)
	}
	if parsed.SessionCookie != 9 {
		t.Fatalf("unexpected session cookie: got=%d want=%d", parsed.SessionCookie, 9)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatalf("unexpected payload: got=%q want=%q", parsed.Payload, payload)
	}
}

func TestParseStreamDataPacket(t *testing.T) {
	payload := []byte("vpn-data")
	raw := buildRawPacket(t, 4, Enums.PACKET_STREAM_DATA, 0x1122, 0x3344, 5, 9, 2, 7, payload)

	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if !parsed.HasStreamID || parsed.StreamID != 0x1122 {
		t.Fatalf("unexpected stream id: %+v", parsed)
	}
	if !parsed.HasSequenceNum || parsed.SequenceNum != 0x3344 {
		t.Fatalf("unexpected sequence number: %+v", parsed)
	}
	if !parsed.HasFragmentInfo || parsed.FragmentID != 5 || parsed.TotalFragments != 9 {
		t.Fatalf("unexpected fragment info: %+v", parsed)
	}
	if !parsed.HasCompressionType || parsed.CompressionType != 2 {
		t.Fatalf("unexpected compression info: %+v", parsed)
	}
	if parsed.HeaderLength != 11 {
		t.Fatalf("unexpected header length: got=%d want=%d", parsed.HeaderLength, 11)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatalf("unexpected payload: got=%q want=%q", parsed.Payload, payload)
	}
}

func TestParseRejectsInvalidCheckByte(t *testing.T) {
	raw := buildRawPacket(t, 1, Enums.PACKET_PING, 0, 0, 0, 0, 0, 2, nil)
	raw[len(raw)-1] ^= 0x01

	if _, err := Parse(raw); err != ErrInvalidHeaderCheck {
		t.Fatalf("unexpected error: got=%v want=%v", err, ErrInvalidHeaderCheck)
	}
}

func TestParseFromLabels(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	payload := []byte("tunnel-payload")
	raw := buildRawPacket(t, 3, Enums.PACKET_DNS_QUERY_REQ, 100, 200, 1, 2, 1, 4, payload)
	encoded, err := codec.EncryptAndEncode(raw)
	if err != nil {
		t.Fatalf("EncryptAndEncode returned error: %v", err)
	}

	parsed, err := ParseFromLabels(encoded, codec)
	if err != nil {
		t.Fatalf("ParseFromLabels returned error: %v", err)
	}
	if parsed.PacketType != Enums.PACKET_DNS_QUERY_REQ || parsed.StreamID != 100 || parsed.SequenceNum != 200 {
		t.Fatalf("unexpected parsed fields: %+v", parsed)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatalf("unexpected payload: got=%q want=%q", parsed.Payload, payload)
	}
}
