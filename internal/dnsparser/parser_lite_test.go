// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package dnsparser

import (
	"testing"

	Enums "stormdns-go/internal/enums"
)

func TestParsePacketLiteParsesAllQuestions(t *testing.T) {
	request := buildMultiQuestionDNSQuery(
		0x4242,
		[]liteQuestionSpec{
			{Name: "example.com", Type: Enums.DNS_RECORD_TYPE_A, Class: Enums.DNSQ_CLASS_IN},
			{Name: "example.org", Type: Enums.DNS_RECORD_TYPE_AAAA, Class: Enums.DNSQ_CLASS_IN},
		},
		true,
	)

	parsed, err := ParsePacketLite(request)
	if err != nil {
		t.Fatalf("ParsePacketLite returned error: %v", err)
	}

	if !parsed.HasQuestion {
		t.Fatal("expected HasQuestion to be true")
	}
	if len(parsed.Questions) != 2 {
		t.Fatalf("unexpected question count: got=%d want=2", len(parsed.Questions))
	}
	if parsed.FirstQuestion.Name != "example.com" {
		t.Fatalf("unexpected first question name: got=%q want=%q", parsed.FirstQuestion.Name, "example.com")
	}
	if parsed.Questions[1].Name != "example.org" {
		t.Fatalf("unexpected second question name: got=%q want=%q", parsed.Questions[1].Name, "example.org")
	}
	if parsed.QuestionEndOffset <= dnsHeaderSize {
		t.Fatalf("unexpected QuestionEndOffset: got=%d want>%d", parsed.QuestionEndOffset, dnsHeaderSize)
	}
}

type liteQuestionSpec struct {
	Name  string
	Type  uint16
	Class uint16
}

func buildMultiQuestionDNSQuery(id uint16, questions []liteQuestionSpec, withOPT bool) []byte {
	totalQuestionLen := 0
	for _, question := range questions {
		totalQuestionLen += len(encodeDNSName(question.Name)) + 4
	}

	arCount := uint16(0)
	opt := []byte(nil)
	if withOPT {
		arCount = 1
		opt = []byte{
			0x00,
			0x00, 0x29,
			0x10, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		}
	}

	packet := make([]byte, dnsHeaderSize+totalQuestionLen+len(opt))
	packet[0] = byte(id >> 8)
	packet[1] = byte(id)
	packet[2] = 0x01
	packet[3] = 0x00
	packet[4] = byte(len(questions) >> 8)
	packet[5] = byte(len(questions))
	packet[10] = byte(arCount >> 8)
	packet[11] = byte(arCount)

	offset := dnsHeaderSize
	for _, question := range questions {
		qname := encodeDNSName(question.Name)
		offset += copy(packet[offset:], qname)
		packet[offset] = byte(question.Type >> 8)
		packet[offset+1] = byte(question.Type)
		packet[offset+2] = byte(question.Class >> 8)
		packet[offset+3] = byte(question.Class)
		offset += 4
	}

	copy(packet[offset:], opt)
	return packet
}
