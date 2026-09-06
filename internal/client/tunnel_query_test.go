// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package client

import (
	"testing"

	DnsParser "stormdns-go/internal/dnsparser"
	Enums "stormdns-go/internal/enums"
)

func questionTypeOf(t *testing.T, packet []byte) uint16 {
	t.Helper()
	lite, err := DnsParser.ParsePacketLite(packet)
	if err != nil || !lite.HasQuestion {
		t.Fatalf("bad test packet: %v", err)
	}
	return lite.FirstQuestion.Type
}

func TestPickTunnelQueryTypeTXTMode(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "TXT"
	for i := 0; i < 20; i++ {
		if got := c.pickTunnelQueryType(); got != Enums.DNS_RECORD_TYPE_TXT {
			t.Fatalf("TXT mode picked %d", got)
		}
	}
}

func TestPickTunnelQueryTypeNSMode(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "NS"
	if got := c.pickTunnelQueryType(); got != Enums.DNS_RECORD_TYPE_NS {
		t.Fatalf("NS mode picked %d", got)
	}
}

func TestPickTunnelQueryTypeRotateMix(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "ROTATE"
	seen := map[uint16]bool{}
	for i := 0; i < 200; i++ {
		seen[c.pickTunnelQueryType()] = true
	}
	if !seen[Enums.DNS_RECORD_TYPE_TXT] || !seen[Enums.DNS_RECORD_TYPE_NS] {
		t.Fatalf("ROTATE must produce both types, got %v", seen)
	}
}

func TestPickTunnelQueryTypeDefaultIsTXT(t *testing.T) {
	c := &Client{} // zero cfg -> "" -> TXT
	if got := c.pickTunnelQueryType(); got != Enums.DNS_RECORD_TYPE_TXT {
		t.Fatalf("default picked %d", got)
	}
}

func TestBuildTunnelQuestionBytesUsesMode(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "NS"
	packet, err := c.buildTunnelQuestionBytes("v.example.com", []byte("abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	if got := questionTypeOf(t, packet); got != Enums.DNS_RECORD_TYPE_NS {
		t.Fatalf("packet qtype = %d, want NS", got)
	}
}
