// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package dnsparser

import (
	"encoding/binary"
	"testing"

	Enums "stormdns-go/internal/enums"
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
