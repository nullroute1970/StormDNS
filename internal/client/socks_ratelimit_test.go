// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package client

import (
	"testing"
	"time"
)

func TestSocksRateLimiterAllowsUnderThreshold(t *testing.T) {
	rl := newSocksRateLimiter()
	ip := "192.168.1.100"

	for i := 0; i < socksRateLimitMaxFailures-1; i++ {
		if rl.RecordFailure(ip) {
			t.Fatalf("should not ban after %d failures (threshold=%d)", i+1, socksRateLimitMaxFailures)
		}
	}

	if rl.IsBlocked(ip) {
		t.Fatal("should not be blocked under threshold")
	}
}

func TestSocksRateLimiterBansAtThreshold(t *testing.T) {
	rl := newSocksRateLimiter()
	ip := "10.0.0.1"

	for i := 0; i < socksRateLimitMaxFailures-1; i++ {
		rl.RecordFailure(ip)
	}

	banned := rl.RecordFailure(ip)
	if !banned {
		t.Fatal("should be banned at threshold")
	}

	if !rl.IsBlocked(ip) {
		t.Fatal("should report blocked after ban")
	}
}

func TestSocksRateLimiterDifferentIPsIndependent(t *testing.T) {
	rl := newSocksRateLimiter()

	for i := 0; i < socksRateLimitMaxFailures; i++ {
		rl.RecordFailure("1.2.3.4")
	}

	if rl.IsBlocked("5.6.7.8") {
		t.Fatal("unrelated IP should not be blocked")
	}
}

func TestSocksRateLimiterEmptyIPNotBlocked(t *testing.T) {
	rl := newSocksRateLimiter()
	if rl.IsBlocked("") {
		t.Fatal("empty IP should never be blocked")
	}
	if rl.RecordFailure("") {
		t.Fatal("empty IP should never trigger ban")
	}
}

func TestSocksRateLimiterLoopbackNeverBanned(t *testing.T) {
	rl := newSocksRateLimiter()

	for _, ip := range []string{"127.0.0.1", "::1"} {
		for i := 0; i < socksRateLimitMaxFailures+2; i++ {
			if rl.RecordFailure(ip) {
				t.Fatalf("loopback IP %s should never trigger ban", ip)
			}
		}
		if rl.IsBlocked(ip) {
			t.Fatalf("loopback IP %s should never be blocked", ip)
		}
	}
}

func TestSocksRateLimiterSuccessClearsState(t *testing.T) {
	rl := newSocksRateLimiter()
	ip := "10.0.0.99"

	for i := 0; i < socksRateLimitMaxFailures-1; i++ {
		rl.RecordFailure(ip)
	}

	rl.RecordSuccess(ip)

	if rl.IsBlocked(ip) {
		t.Fatal("success should clear any pending block state")
	}
	if rl.RecordFailure(ip) {
		t.Fatal("success should clear accumulated failures")
	}
}

func TestSocksRateLimiterBanDecayResetsEscalation(t *testing.T) {
	rl := newSocksRateLimiter()
	ip := "10.0.0.50"

	// First ban: banCount becomes 1, ban = 1 minute.
	for i := 0; i < socksRateLimitMaxFailures; i++ {
		rl.RecordFailure(ip)
	}
	if !rl.IsBlocked(ip) {
		t.Fatal("should be banned after first threshold breach")
	}

	// Simulate time passing: ban expired + decay period elapsed.
	rl.mu.Lock()
	rec := rl.records[ip]
	rec.banUntil = time.Now().Add(-(socksRateLimitBanDecayAfter + time.Minute))
	rl.mu.Unlock()

	// Next threshold breach should be treated as a first offense again (1 min ban).
	for i := 0; i < socksRateLimitMaxFailures; i++ {
		rl.RecordFailure(ip)
	}

	rl.mu.Lock()
	if rec.banCount != 1 {
		t.Fatalf("ban count should have decayed and reset to 1, got %d", rec.banCount)
	}
	rl.mu.Unlock()
}

func TestSocksRateLimiterPurgeRemovesStale(t *testing.T) {
	rl := newSocksRateLimiter()
	ip := "172.16.0.1"

	// Manually insert an old record.
	rl.mu.Lock()
	rl.records[ip] = &socksAuthFailureRecord{
		timestamps: []time.Time{time.Now().Add(-5 * time.Minute)},
	}
	rl.mu.Unlock()

	// Trigger purge.
	rl.mu.Lock()
	rl.purgeLocked(time.Now())
	rl.mu.Unlock()

	rl.mu.Lock()
	_, exists := rl.records[ip]
	rl.mu.Unlock()

	if exists {
		t.Fatal("stale record should have been purged")
	}
}
