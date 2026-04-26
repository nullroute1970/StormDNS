// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"
)

// TestDialExternalSOCKS5WatchdogExitsAfterHandshake verifies that the watchdog
// goroutine spawned by dialExternalSOCKS5TargetContext stops when the
// handshake returns rather than lingering until ctx is cancelled. Before the
// fix, the goroutine sat on `<-ctx.Done()` for the entire session lifetime
// even after the connection was successfully handed off.
func TestDialExternalSOCKS5WatchdogExitsAfterHandshake(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	s.useExternalSOCKS5 = true
	s.externalSOCKS5Address = "203.0.113.10:1080"

	conn := &scriptedSOCKS5Conn{
		readBufs: [][]byte{
			{0x05, 0x00},
			{0x05, 0x00, 0x00, 0x01},
			{203, 0, 113, 1, 0x04, 0x38},
		},
	}
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		return conn, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	baseline := runtime.NumGoroutine()
	for i := 0; i < 16; i++ {
		targetPayload := []byte{0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb}
		conn.readBufs = [][]byte{
			{0x05, 0x00},
			{0x05, 0x00, 0x00, 0x01},
			{203, 0, 113, 1, 0x04, 0x38},
		}
		conn.readIndex = 0
		conn.writes = nil
		if _, err := s.dialExternalSOCKS5TargetContext(ctx, targetPayload); err != nil {
			t.Fatalf("iteration %d: unexpected handshake error: %v", i, err)
		}
	}

	// Give any spawned watchdog goroutines a chance to wind down.
	deadline := time.Now().Add(2 * time.Second)
	var current int
	for time.Now().Before(deadline) {
		current = runtime.NumGoroutine()
		if current <= baseline+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("watchdog goroutines appear to leak: baseline=%d after_16_handshakes=%d", baseline, current)
}
