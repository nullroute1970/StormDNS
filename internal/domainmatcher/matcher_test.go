// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package domainmatcher

import (
	"testing"

	DnsParser "stormdns-go/internal/dnsparser"
	Enums "stormdns-go/internal/enums"
)

func TestMatcherReturnsNoDataForUnauthorizedDomain(t *testing.T) {
	matcher := New([]string{"a.com", "c.b.com", "cc.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("evil.com", Enums.DNS_RECORD_TYPE_TXT))
	if decision.Action != ActionNoData {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionNoData)
	}
	if decision.Reason != "unauthorized-domain" {
		t.Fatalf("unexpected reason: got=%q", decision.Reason)
	}
}

func TestMatcherReturnsNoDataForExactAllowedDomain(t *testing.T) {
	matcher := New([]string{"a.com", "c.b.com", "cc.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("c.b.com", Enums.DNS_RECORD_TYPE_TXT))
	if decision.Action != ActionNoData {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionNoData)
	}
	if decision.Reason != "missing-vpn-labels" {
		t.Fatalf("unexpected reason: got=%q", decision.Reason)
	}
}

func TestMatcherReturnsNoDataForUnsupportedType(t *testing.T) {
	matcher := New([]string{"a.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("vpn.a.com", Enums.DNS_RECORD_TYPE_A))
	if decision.Action != ActionNoData {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionNoData)
	}
	if decision.Reason != "unsupported-qtype" {
		t.Fatalf("unexpected reason: got=%q", decision.Reason)
	}
}

func TestMatcherReturnsProcessForTXTWithExtraLabels(t *testing.T) {
	matcher := New([]string{"a.com", "c.b.com", "cc.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("vpn-01.c.b.com", Enums.DNS_RECORD_TYPE_TXT))
	if decision.Action != ActionProcess {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionProcess)
	}
	if decision.BaseDomain != "c.b.com" {
		t.Fatalf("unexpected base domain: got=%q want=%q", decision.BaseDomain, "c.b.com")
	}
	if decision.Labels != "vpn-01" {
		t.Fatalf("unexpected labels: got=%q want=%q", decision.Labels, "vpn-01")
	}
}

func TestMatcherPreservesMultipleLabels(t *testing.T) {
	matcher := New([]string{"a.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("aa.bb.a.com", Enums.DNS_RECORD_TYPE_TXT))
	if decision.Action != ActionProcess {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionProcess)
	}
	if decision.Labels != "aabb" {
		t.Fatalf("unexpected labels: got=%q want=%q", decision.Labels, "aabb")
	}
}

func TestMatcherRespectsBoundaryBeforeSuffix(t *testing.T) {
	matcher := New([]string{"a.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("notreallya.com", Enums.DNS_RECORD_TYPE_TXT))
	if decision.Action != ActionNoData {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionNoData)
	}
	if decision.Reason != "unauthorized-domain" {
		t.Fatalf("unexpected reason: got=%q", decision.Reason)
	}
}

func litePacketWithQuestion(name string, qtype uint16) DnsParser.LitePacket {
	question := DnsParser.Question{
		Name:  name,
		Type:  qtype,
		Class: Enums.DNSQ_CLASS_IN,
	}

	return DnsParser.LitePacket{
		Header:        DnsParser.Header{QDCount: 1},
		Questions:     []DnsParser.Question{question},
		FirstQuestion: question,
		HasQuestion:   true,
	}
}
