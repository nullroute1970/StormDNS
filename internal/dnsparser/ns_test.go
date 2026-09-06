// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package dnsparser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	baseCodec "stormdns-go/internal/basecodec"
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

// buildNSAnswerTestPacket crafts a single-question, single-answer response whose
// answer rdata is the wire name given in rdata. owner is written as a compression
// pointer to the question name (0xC00C). Passing nil rdata emits a compression
// pointer as the rdata (pointing back at the question name).
func buildNSAnswerTestPacket(t *testing.T, qtype uint16, rdata []byte) []byte {
	t.Helper()
	question, err := BuildTXTQuestionPacket("x.v.example.com", qtype, 0)
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
	packet = append(packet, 0xC0, 0x0C) // owner: pointer to qname
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], Enums.DNS_RECORD_TYPE_NS)
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

func TestParsePacketDecodesNSRDataNamePlain(t *testing.T) {
	rdata, err := encodeDNSNameStrict("ns1.v.example.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(buildNSAnswerTestPacket(t, Enums.DNS_RECORD_TYPE_NS, rdata))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	got := parsed.Answers[0].RDataName
	if got != "ns1.v.example.com" {
		t.Fatalf("RDataName = %q, want %q", got, "ns1.v.example.com")
	}
}

func TestParsePacketDecodesNSRDataNameCompressed(t *testing.T) {
	parsed, err := ParsePacket(buildNSAnswerTestPacket(t, Enums.DNS_RECORD_TYPE_NS, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	got := parsed.Answers[0].RDataName
	if got != "x.v.example.com" {
		t.Fatalf("RDataName = %q, want %q", got, "x.v.example.com")
	}
}

func TestParsePacketLeavesRDataNameEmptyForTXT(t *testing.T) {
	rdata := []byte{5, 'h', 'e', 'l', 'l', 'o'}
	question, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 0)
	if err != nil {
		t.Fatal(err)
	}
	// answer section: owner pointer + TXT fixed part + rdata
	packet := append(question, 0xC0, 0x0C)
	binary.BigEndian.PutUint16(packet[6:8], 1) // ANCount = 1
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], Enums.DNS_RECORD_TYPE_TXT)
	binary.BigEndian.PutUint16(fixed[2:4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rdata)))
	packet = append(packet, fixed[:]...)
	packet = append(packet, rdata...)

	parsed, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].RDataName != "" {
		t.Fatalf("TXT answer must have empty RDataName, got %+v", parsed.Answers)
	}
}

func TestParsePacketToleratesGarbageNSRData(t *testing.T) {
	// rdata claims 3 bytes but starts with a 63-byte label: name decode fails,
	// packet parse must still succeed with empty RDataName.
	parsed, err := ParsePacket(buildNSAnswerTestPacket(t, Enums.DNS_RECORD_TYPE_NS, []byte{63, 'a', 'b'}))
	if err != nil {
		t.Fatalf("parse must not fail on malformed NS rdata: %v", err)
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].RDataName != "" {
		t.Fatalf("want 1 answer with empty RDataName, got %+v", parsed.Answers)
	}
}

// ---- Task 2/3: NS tunnel answer builders and extraction ----

// deterministic pseudo-random payload that does not compress smaller, so frame
// sizes (and therefore chunk counts) are stable.
func patternedPayload(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*31 + 7)
	}
	return out
}

func vpnPacketForTest(payload []byte) VpnProto.Packet {
	return VpnProto.Packet{
		SessionID:      7,
		PacketType:     Enums.PACKET_PONG,
		StreamID:       3,
		SequenceNum:    99,
		FragmentID:     0,
		TotalFragments: 1,
		Payload:        payload,
	}
}

func TestBuildVPNResponsePacketMirrorsNSQuestionSingle(t *testing.T) {
	question, err := BuildTXTQuestionPacket("a1b2.v.example.com", Enums.DNS_RECORD_TYPE_NS, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello ns world")
	resp, err := BuildVPNResponsePacket(question, "a1b2.v.example.com", vpnPacketForTest(payload), false)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Questions) != 1 || parsed.Questions[0].Type != Enums.DNS_RECORD_TYPE_NS {
		t.Fatalf("question type not echoed: %+v", parsed.Questions)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 NS answer, got %d", len(parsed.Answers))
	}
	if parsed.Answers[0].Type != Enums.DNS_RECORD_TYPE_NS {
		t.Fatalf("answer type = %d, want NS(%d)", parsed.Answers[0].Type, Enums.DNS_RECORD_TYPE_NS)
	}
	if parsed.Answers[0].RDataName == "" {
		t.Fatal("NS answer rdata name not decoded")
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

func TestBuildVPNResponsePacketMirrorsNSQuestionMultiChunk(t *testing.T) {
	question, err := BuildTXTQuestionPacket("aa.bb.v.example.com", Enums.DNS_RECORD_TYPE_NS, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := patternedPayload(800) // forces multiple NS answer records
	resp, err := BuildVPNResponsePacket(question, "aa.bb.v.example.com", VpnProto.Packet{
		SessionID:      7,
		PacketType:     Enums.PACKET_STREAM_DATA, // carries stream/seq in the header
		StreamID:       3,
		SequenceNum:    99,
		TotalFragments: 1,
		Payload:        payload,
	}, true /* base64 flag must be irrelevant for NS */)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) < 2 {
		t.Fatalf("want multiple NS answers, got %d", len(parsed.Answers))
	}
	for i, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_NS {
			t.Fatalf("answer %d type = %d, want NS", i, ans.Type)
		}
		if ans.RDataName == "" {
			t.Fatalf("answer %d rdata name missing", i)
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

func TestBuildVPNResponsePacketKeepsTXTForTXTQuestion(t *testing.T) {
	question, err := BuildTXTQuestionPacket("a1b2.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := patternedPayload(800)
	resp, err := BuildVPNResponsePacket(question, "a1b2.v.example.com", vpnPacketForTest(payload), false)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) == 0 {
		t.Fatal("no answers")
	}
	for _, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_TXT {
			t.Fatalf("TXT question must yield TXT answers, got type %d", ans.Type)
		}
	}
	got, err := ExtractVPNResponse(resp, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatal("TXT roundtrip regression")
	}
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func TestExtractVPNResponseReadsBase36NamePayload(t *testing.T) {
	// Single NS answer whose rdata name carries base36 of a real raw frame
	// (the server's single-answer path).
	question, err := BuildTXTQuestionPacket("k9.v.example.com", Enums.DNS_RECORD_TYPE_NS, 0)
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
	resp, err := buildSingleNSResponsePacket(question, "k9.v.example.com", nameWire)
	if err != nil {
		t.Fatal(err)
	}

	// baseEncoded=true must not corrupt NS-unit decoding (NS is charset-safe by itself).
	got, err := ExtractVPNResponse(resp, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || !bytes.Equal(got.Payload, []byte{1, 2, 3, 4, 5}) {
		t.Fatalf("roundtrip mismatch: type=%d payload=%v", got.PacketType, got.Payload)
	}
}

func TestExtractVPNResponseNoPayloadFromUnreadableNS(t *testing.T) {
	// An NS answer whose rdata name cannot be decoded must behave like a
	// response without tunnel payload: ErrTXTAnswerMissing, not a panic.
	// (garbage rdata: 63-byte label declared but only 2 bytes present)
	resp := buildNSAnswerTestPacket(t, Enums.DNS_RECORD_TYPE_NS, []byte{63, 'a', 'b'})
	if _, err := ExtractVPNResponse(resp, false); !errors.Is(err, ErrTXTAnswerMissing) {
		t.Fatalf("want ErrTXTAnswerMissing, got %v", err)
	}
}

func TestDecodeNSAnswerNameHandlesLabelSplits(t *testing.T) {
	raw := patternedPayload(100)
	text := baseCodec.EncodeLowerBase36(raw)
	labels := EncodeDataToLabels(text)
	got, err := decodeNSAnswerName(labels)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("base36 label roundtrip mismatch")
	}
}
