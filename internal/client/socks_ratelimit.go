// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the StormDNS client.
// This file (socks_ratelimit.go) implements IP-based rate limiting for SOCKS5
// authentication failures to mitigate brute-force credential stuffing attacks.
// ==============================================================================
package client

import (
	"net"
	"sync"
	"time"
)

const (
	// socksRateLimitWindow is the sliding window duration for counting auth failures.
	socksRateLimitWindow = 2 * time.Minute

	// socksRateLimitMaxFailures is the maximum number of auth failures allowed
	// within the window before the IP is temporarily banned.
	// Set high enough (10) so a legitimate user who fat-fingers their password
	// a few times is not affected, while brute-forcers still trigger quickly.
	socksRateLimitMaxFailures = 10

	// socksRateLimitBaseBan is the ban duration after the *first* threshold breach.
	// Kept short (1 minute) so an honest user just pauses and rechecks their password.
	// Subsequent bans double each time (exponential back-off).
	socksRateLimitBaseBan = 1 * time.Minute

	// socksRateLimitMaxBanDuration caps the maximum ban duration.
	socksRateLimitMaxBanDuration = 15 * time.Minute

	// socksRateLimitBanDecayAfter resets the escalation counter back to zero
	// if the IP stays clean for this long after a ban expires.
	// Forgives legitimate users who fixed their mistake and moved on.
	socksRateLimitBanDecayAfter = 10 * time.Minute

	// socksRateLimitPurgeInterval controls how often stale entries are cleaned up.
	socksRateLimitPurgeInterval = 60 * time.Second
)

type socksAuthFailureRecord struct {
	timestamps []time.Time
	banUntil   time.Time
	banCount   int
}

type socksRateLimiter struct {
	mu        sync.Mutex
	records   map[string]*socksAuthFailureRecord
	lastPurge time.Time
}

func newSocksRateLimiter() *socksRateLimiter {
	return &socksRateLimiter{
		records:   make(map[string]*socksAuthFailureRecord),
		lastPurge: time.Now(),
	}
}

func isLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

// extractIP returns the bare IP address string from a net.Conn, stripping the port.
func extractIP(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// IsBlocked returns true if the given IP is currently banned due to excessive
// authentication failures. Safe for concurrent use.
func (r *socksRateLimiter) IsBlocked(ip string) bool {
	if ip == "" || isLoopbackIP(ip) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.records[ip]
	if !ok {
		return false
	}
	if rec.banUntil.IsZero() {
		return false
	}
	return time.Now().Before(rec.banUntil)
}

// RecordFailure records an authentication failure for the given IP. If the
// failure count within the sliding window exceeds the threshold, the IP is
// banned for an escalating duration.
// Returns true if the IP is now banned as a result of this failure.
func (r *socksRateLimiter) RecordFailure(ip string) bool {
	if ip == "" || isLoopbackIP(ip) {
		return false
	}
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Periodic cleanup of stale entries.
	if now.Sub(r.lastPurge) >= socksRateLimitPurgeInterval {
		r.purgeLocked(now)
		r.lastPurge = now
	}

	rec, ok := r.records[ip]
	if !ok {
		rec = &socksAuthFailureRecord{}
		r.records[ip] = rec
	}

	// If already banned, just extend awareness.
	if !rec.banUntil.IsZero() && now.Before(rec.banUntil) {
		return true
	}

	// Decay escalation if the IP stayed clean long enough after a previous ban.
	if rec.banCount > 0 && !rec.banUntil.IsZero() && now.After(rec.banUntil) {
		if now.Sub(rec.banUntil) >= socksRateLimitBanDecayAfter {
			rec.banCount = 0
		}
	}

	// Trim timestamps outside the sliding window.
	cutoff := now.Add(-socksRateLimitWindow)
	trimmed := rec.timestamps[:0]
	for _, ts := range rec.timestamps {
		if ts.After(cutoff) {
			trimmed = append(trimmed, ts)
		}
	}
	rec.timestamps = append(trimmed, now)

	if len(rec.timestamps) >= socksRateLimitMaxFailures {
		rec.banCount++
		// Exponential back-off: 1m, 2m, 4m, 8m, capped at 15m.
		banDuration := socksRateLimitBaseBan
		for i := 1; i < rec.banCount; i++ {
			banDuration *= 2
			if banDuration >= socksRateLimitMaxBanDuration {
				banDuration = socksRateLimitMaxBanDuration
				break
			}
		}
		rec.banUntil = now.Add(banDuration)
		rec.timestamps = rec.timestamps[:0] // Reset window after ban.
		return true
	}
	return false
}

// RecordSuccess clears accumulated failure/banning state for the given IP after
// a successful authentication.
func (r *socksRateLimiter) RecordSuccess(ip string) {
	if ip == "" || isLoopbackIP(ip) {
		return
	}

	r.mu.Lock()
	delete(r.records, ip)
	r.mu.Unlock()
}

// Reset clears all accumulated SOCKS auth rate-limit state in place.
func (r *socksRateLimiter) Reset() {
	if r == nil {
		return
	}

	r.mu.Lock()
	r.records = make(map[string]*socksAuthFailureRecord)
	r.lastPurge = time.Now()
	r.mu.Unlock()
}

// purgeLocked removes expired records to prevent unbounded memory growth.
// Must be called with r.mu held.
func (r *socksRateLimiter) purgeLocked(now time.Time) {
	cutoff := now.Add(-socksRateLimitWindow)
	for ip, rec := range r.records {
		// Remove if not banned and no recent failures.
		if !rec.banUntil.IsZero() && now.Before(rec.banUntil) {
			continue
		}
		// Check if all timestamps are expired.
		hasRecent := false
		for _, ts := range rec.timestamps {
			if ts.After(cutoff) {
				hasRecent = true
				break
			}
		}
		if !hasRecent && (rec.banUntil.IsZero() || now.After(rec.banUntil)) {
			delete(r.records, ip)
		}
	}
}
