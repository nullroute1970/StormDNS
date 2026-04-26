// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"testing"
	"time"

	"stormdns-go/internal/arq"
	"stormdns-go/internal/config"
	fragmentStore "stormdns-go/internal/fragmentstore"
)

// TestStatsZeroValueAndNilSafe exercises the documented contracts of Stats():
// nil-receiver and just-constructed servers must return a zero-value Stats
// without panicking.
func TestStatsZeroValueAndNilSafe(t *testing.T) {
	var nilServer *Server
	if got := nilServer.Stats(); got != (Stats{}) {
		t.Fatalf("nil server Stats() should be zero, got %+v", got)
	}

	s := &Server{
		cfg:             config.ServerConfig{MaxDNSResponseBytes: 1024, MaxStreamsPerSession: 0},
		sessions:        newSessionStore(8, 16),
		dnsFragments:    fragmentStore.New[dnsFragmentKey](8),
		socks5Fragments: fragmentStore.New[socks5FragmentKey](8),
	}
	if got := s.Stats(); got != (Stats{}) {
		t.Fatalf("fresh Stats() should be zero, got %+v", got)
	}
}

// TestStatsReflectsHardeningPathIncrements verifies that each Phase 1 reject
// path increments the corresponding observability counter exposed via Stats().
func TestStatsReflectsHardeningPathIncrements(t *testing.T) {
	s := &Server{
		cfg:             config.ServerConfig{MaxDNSResponseBytes: 64, MaxStreamsPerSession: 0},
		sessions:        newSessionStore(8, 16, time.Minute, time.Minute, 32, 1),
		dnsFragments:    fragmentStore.New[dnsFragmentKey](8),
		socks5Fragments: fragmentStore.New[socks5FragmentKey](8),
	}

	// 1. Oversize DNS response.
	if frags := s.fragmentDNSResponsePayload(make([]byte, 128), 32); frags != nil {
		t.Fatal("expected oversize response to be rejected")
	}

	// 2. Stream cap rejection. Build a session record via the store with cap=1
	// then try to create two data streams.
	record := &sessionRecord{
		ID:                  9,
		Streams:             make(map[uint16]*Stream_server),
		ActiveStreams:       make([]uint16, 0, 4),
		RecentlyClosed:      make(map[uint16]recentlyClosedStreamRecord, 4),
		MaxStreams:          1,
		streamCapRejections: &s.sessions.streamCapRejections,
	}
	if got := record.getOrCreateStream(1, arq.Config{}, nil, nil); got == nil {
		t.Fatal("expected first data stream to be created")
	}
	if got := record.getOrCreateStream(2, arq.Config{}, nil, nil); got != nil {
		t.Fatal("expected second data stream to be rejected")
	}

	// 3. Fragment conflict: first fragment with totalFragments=4, then an
	// incoming fragment for the same key with totalFragments=8.
	now := time.Unix(1700000000, 0)
	if _, ready, _ := s.dnsFragments.Collect(dnsFragmentKey{}, []byte("a"), 0, 4, now, time.Minute); ready {
		t.Fatal("expected first fragment to stay incomplete")
	}
	if _, ready, completed := s.dnsFragments.Collect(dnsFragmentKey{}, []byte("b"), 0, 8, now.Add(time.Millisecond), time.Minute); ready || completed {
		t.Fatal("expected conflicting fragment to be dropped")
	}

	stats := s.Stats()
	if stats.DNSResponseOversize != 1 {
		t.Errorf("DNSResponseOversize: got %d want 1", stats.DNSResponseOversize)
	}
	if stats.StreamCapRejections != 1 {
		t.Errorf("StreamCapRejections: got %d want 1", stats.StreamCapRejections)
	}
	if stats.FragmentConflictDrops != 1 {
		t.Errorf("FragmentConflictDrops: got %d want 1", stats.FragmentConflictDrops)
	}
}
