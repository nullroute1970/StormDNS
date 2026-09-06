package dnsparser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

// buildCNAMEAnswerTestPacket crafts a single-question, single-answer response
// whose answer type is CNAME and whose rdata is the wire name given in rdata.
// The owner is written as a compression pointer to the question name (0xC00C).
func buildCNAMEAnswerTestPacket(t *testing.T, rdata []byte) []byte {
	t.Helper()
	question, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_CNAME, 0)
	if err != nil {
		t.Fatal(err)
	}
	rdataLen := len(rdata)
	if rdata == nil {
		rdataLen = 2 // compression pointer
	}
	packet := make([]byte, 0, len(question)+2+10+rdataLen)
	packet = append(packet, question...)
	binary.BigEndian.PutUint16(packet[6:8], 1) // ANCount = 1
	packet = append(packet, 0xC0, 0x0C)        // owner: pointer to qname
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], Enums.DNS_RECORD_TYPE_CNAME)
	binary.BigEndian.PutUint16(fixed[2:4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint16(fixed[8:10], uint16(rdataLen))
	packet = append(packet, fixed[:]...)
	if rdata != nil {
		packet = append(packet, rdata...)
	} else {
		packet = append(packet, 0xC0, 0x0C) // rdata: pointer to qname
	}
	return packet
}

func TestParsePacketDecodesCNAMERDataNamePlain(t *testing.T) {
	rdata, err := encodeDNSNameStrict("cdn1.v.example.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(buildCNAMEAnswerTestPacket(t, rdata))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	if got := parsed.Answers[0].RDataName; got != "cdn1.v.example.com" {
		t.Fatalf("RDataName = %q, want %q", got, "cdn1.v.example.com")
	}
}

func TestParsePacketDecodesCNAMERDataNameCompressed(t *testing.T) {
	parsed, err := ParsePacket(buildCNAMEAnswerTestPacket(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	if got := parsed.Answers[0].RDataName; got != "x.v.example.com" {
		t.Fatalf("RDataName = %q, want %q", got, "x.v.example.com")
	}
}

func TestParsePacketToleratesGarbageCNAMERData(t *testing.T) {
	// rdata claims 3 bytes but is a 63-byte label start: name decode fails,
	// packet parse must still succeed with empty RDataName.
	parsed, err := ParsePacket(buildCNAMEAnswerTestPacket(t, []byte{63, 'a', 'b'}))
	if err != nil {
		t.Fatalf("parse must not fail on malformed CNAME rdata: %v", err)
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].RDataName != "" {
		t.Fatalf("want 1 answer with empty RDataName, got %+v", parsed.Answers)
	}
}

func TestBuildVPNResponsePacketMirrorsCNAMEQuestionSingle(t *testing.T) {
	question, err := BuildTXTQuestionPacket("a1b2.v.example.com", Enums.DNS_RECORD_TYPE_CNAME, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello cname world")
	resp, err := BuildVPNResponsePacket(question, "a1b2.v.example.com", vpnPacketForTest(payload), false)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Questions) != 1 || parsed.Questions[0].Type != Enums.DNS_RECORD_TYPE_CNAME {
		t.Fatalf("question type not echoed: %+v", parsed.Questions)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 CNAME answer, got %d", len(parsed.Answers))
	}
	if parsed.Answers[0].Type != Enums.DNS_RECORD_TYPE_CNAME {
		t.Fatalf("answer type = %d, want CNAME(%d)", parsed.Answers[0].Type, Enums.DNS_RECORD_TYPE_CNAME)
	}
	if parsed.Answers[0].RDataName == "" {
		t.Fatal("CNAME answer rdata name not decoded")
	}
	for _, label := range splitLabels(parsed.Answers[0].RDataName) {
		if len(label) > 63 {
			t.Fatalf("label %q exceeds 63 chars", label)
		}
	}

	got, err := ExtractVPNResponse(resp, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("roundtrip mismatch: type=%d payload=%q", got.PacketType, got.Payload)
	}
}

func TestBuildVPNResponsePacketMirrorsCNAMEQuestionChain(t *testing.T) {
	question, err := BuildTXTQuestionPacket("aa.bb.v.example.com", Enums.DNS_RECORD_TYPE_CNAME, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := patternedPayload(800) // forces multiple CNAME answer records
	resp, err := BuildVPNResponsePacket(question, "aa.bb.v.example.com", VpnProto.Packet{
		SessionID:      7,
		PacketType:     Enums.PACKET_STREAM_DATA, // carries stream/seq in the header
		StreamID:       3,
		SequenceNum:    99,
		TotalFragments: 1,
		Payload:        payload,
	}, true /* base64 flag must be irrelevant for CNAME */)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) < 2 {
		t.Fatalf("want multiple CNAME answers, got %d", len(parsed.Answers))
	}
	for i, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_CNAME {
			t.Fatalf("answer %d type = %d, want CNAME", i, ans.Type)
		}
		if ans.RDataName == "" {
			t.Fatalf("answer %d rdata name missing", i)
		}
		if i > 0 && ans.Name != parsed.Answers[i-1].RDataName {
			t.Fatalf("chain broken at link %d: owner %q != previous target %q", i, ans.Name, parsed.Answers[i-1].RDataName)
		}
	}

	got, err := ExtractVPNResponse(resp, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_STREAM_DATA || got.StreamID != 3 || got.SequenceNum != 99 ||
		!bytes.Equal(got.Payload, payload) {
		t.Fatalf("roundtrip mismatch: type=%d stream=%d seq=%d payloadlen=%d",
			got.PacketType, got.StreamID, got.SequenceNum, len(got.Payload))
	}
}

func TestExtractVPNResponseReadsCNAMENamePayload(t *testing.T) {
	// Single CNAME answer whose rdata target name carries base36 of a real raw
	// frame (the server's single-answer path).
	question, err := BuildTXTQuestionPacket("k9.v.example.com", Enums.DNS_RECORD_TYPE_CNAME, 0)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
		SessionID:  7,
		PacketType: Enums.PACKET_PONG,
		Payload:    []byte{1, 2, 3, 4, 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	nameWire, err := buildNSAnswerName(frame)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := buildSingleCNAMEResponsePacket(question, "k9.v.example.com", nameWire)
	if err != nil {
		t.Fatal(err)
	}

	// baseEncoded=true must not corrupt CNAME-unit decoding (name transport is
	// charset-safe by itself).
	got, err := ExtractVPNResponse(resp, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || !bytes.Equal(got.Payload, []byte{1, 2, 3, 4, 5}) {
		t.Fatalf("roundtrip mismatch: type=%d payload=%v", got.PacketType, got.Payload)
	}
}

func TestExtractVPNResponseNoPayloadFromUnreadableCNAME(t *testing.T) {
	// A CNAME answer whose rdata name cannot be decoded must behave like a
	// response without tunnel payload: ErrTXTAnswerMissing, not a panic.
	resp := buildCNAMEAnswerTestPacket(t, []byte{63, 'a', 'b'})
	if _, err := ExtractVPNResponse(resp, false); !errors.Is(err, ErrTXTAnswerMissing) {
		t.Fatalf("want ErrTXTAnswerMissing, got %v", err)
	}
}

func TestExtractVPNResponseIgnoresRecordsAppendedByRecursor(t *testing.T) {
	// Recursors may append address records after a CNAME chain; units must come
	// only from the CNAME rdata names, in order.
	payload := patternedPayload(400)
	question, err := BuildTXTQuestionPacket("aa.bb.v.example.com", Enums.DNS_RECORD_TYPE_CNAME, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := BuildVPNResponsePacket(question, "aa.bb.v.example.com", vpnPacketForTest(payload), false)
	if err != nil {
		t.Fatal(err)
	}

	// Append one A record after the chain and bump ANCount.
	owner, err := encodeDNSNameStrict("extra.example.net")
	if err != nil {
		t.Fatal(err)
	}
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], Enums.DNS_RECORD_TYPE_A)
	binary.BigEndian.PutUint16(fixed[2:4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint16(fixed[8:10], 4)
	resp = append(resp, owner...)
	resp = append(resp, fixed[:]...)
	resp = append(resp, 1, 2, 3, 4)
	anCount := binary.BigEndian.Uint16(resp[6:8])
	binary.BigEndian.PutUint16(resp[6:8], anCount+1)

	got, err := ExtractVPNResponse(resp, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("roundtrip mismatch: type=%d payloadlen=%d", got.PacketType, len(got.Payload))
	}
}
