// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"testing"

	"stormdns-go/internal/config"
)

func TestFragmentDNSResponsePayloadEnforcesMaxBytes(t *testing.T) {
	cfg := config.ServerConfig{MaxDNSResponseBytes: 1024}
	s := &Server{cfg: cfg}

	// Within cap: standard fragmentation is performed.
	small := make([]byte, 800)
	if frags := s.fragmentDNSResponsePayload(small, 256); len(frags) == 0 {
		t.Fatal("expected within-cap response to fragment normally")
	}

	// Exactly at the cap is still allowed.
	atCap := make([]byte, 1024)
	if frags := s.fragmentDNSResponsePayload(atCap, 256); len(frags) == 0 {
		t.Fatal("expected response at MaxDNSResponseBytes to be allowed")
	}

	// Over the cap: caller observes nil and falls back to a no-data path.
	over := make([]byte, 1025)
	if frags := s.fragmentDNSResponsePayload(over, 256); frags != nil {
		t.Fatalf("expected over-cap response to be rejected, got %d fragments", len(frags))
	}
}

func TestFragmentDNSResponsePayloadAllowsZeroCap(t *testing.T) {
	// Cap of 0 disables the size guard (defensive: ensures upgrade
	// compatibility for existing configs that might somehow yield 0).
	s := &Server{cfg: config.ServerConfig{MaxDNSResponseBytes: 0}}
	payload := make([]byte, 4096)
	if frags := s.fragmentDNSResponsePayload(payload, 256); len(frags) == 0 {
		t.Fatal("expected payload to fragment when cap is 0 (disabled)")
	}
}
