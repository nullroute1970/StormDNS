// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"testing"

	"stormdns-go/internal/arq"
)

func TestGetOrCreateStreamEnforcesMaxStreamsPerSession(t *testing.T) {
	record := newTestSessionRecord(3)
	record.MaxStreams = 2

	cfg := arq.Config{}
	if s := record.getOrCreateStream(1, cfg, nil, nil); s == nil {
		t.Fatal("expected stream 1 to be created within cap")
	}
	if s := record.getOrCreateStream(2, cfg, nil, nil); s == nil {
		t.Fatal("expected stream 2 to be created within cap")
	}

	// Cap of 2 reached. A third distinct stream must be rejected.
	if s := record.getOrCreateStream(3, cfg, nil, nil); s != nil {
		t.Fatal("expected stream 3 creation to be rejected once cap is reached")
	}

	// Existing streams must still be retrievable, idempotently.
	if s := record.getOrCreateStream(1, cfg, nil, nil); s == nil {
		t.Fatal("expected existing stream 1 to remain accessible")
	}
	if s := record.getOrCreateStream(2, cfg, nil, nil); s == nil {
		t.Fatal("expected existing stream 2 to remain accessible")
	}
}

func TestGetOrCreateStreamCapNeverBlocksStreamZero(t *testing.T) {
	record := newTestSessionRecord(4)
	// Use an absurdly low cap that is already exceeded by stream 0 alone if
	// stream 0 were counted against the cap.
	record.MaxStreams = 0 // 0 means "no cap" by convention; verify untouched
	if s := record.getOrCreateStream(0, arq.Config{IsVirtual: true}, nil, nil); s == nil {
		t.Fatal("stream 0 must always be available when cap is disabled")
	}

	// Now set a positive cap and confirm stream 0 still doesn't count
	// against data streams.
	record2 := newTestSessionRecord(5)
	record2.MaxStreams = 1
	cfg := arq.Config{}
	if s := record2.getOrCreateStream(7, cfg, nil, nil); s == nil {
		t.Fatal("expected stream 7 (first data stream) to be created within cap of 1")
	}
	// Cap reached for data streams.
	if s := record2.getOrCreateStream(8, cfg, nil, nil); s != nil {
		t.Fatal("expected second data stream to be rejected when cap is 1")
	}
}
