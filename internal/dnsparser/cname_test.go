package dnsparser

import (
	"encoding/binary"
	"testing"

	Enums "stormdns-go/internal/enums"
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
