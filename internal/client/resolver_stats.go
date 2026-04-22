package client

import (
	"encoding/binary"
	"net"
	"sort"
	"time"
)

const (
	resolverPendingSoftCap   = 8192
	resolverPendingHardCap   = 12288
	resolverPendingTargetCap = 8192
)

type resolverSampleKey struct {
	resolverAddr string
	localAddr    string
	dnsID        uint16
}

type resolverSample struct {
	serverKey  string
	sentAt     time.Time
	timedOut   bool
	timedOutAt time.Time
	evictAfter time.Time
}

type resolverTimeoutObservation struct {
	serverKey string
	at        time.Time
}

func (c *Client) resolverSampleTTL() time.Duration {
	if c == nil {
		return 15 * time.Second
	}

	ttl := c.tunnelPacketTimeout * 3
	if ttl < 10*time.Second {
		ttl = 10 * time.Second
	}
	if ttl > 45*time.Second {
		ttl = 45 * time.Second
	}
	return ttl
}

func (c *Client) noteResolverSend(serverKey string) {
	if c == nil || serverKey == "" || c.balancer == nil {
		return
	}
	c.balancer.ReportSend(serverKey)
}

func (c *Client) noteResolverSuccess(serverKey string, rtt time.Duration) {
	if c == nil || serverKey == "" || c.balancer == nil {
		return
	}
	if rtt < 0 {
		rtt = 0
	}
	c.balancer.ReportSuccess(serverKey, rtt)
	c.recordResolverHealthEvent(serverKey, true, c.now())
}

func (c *Client) trackResolverSend(packet []byte, resolverAddr string, localAddr string, serverKey string, sentAt time.Time) {
	if c == nil || len(packet) < 2 || resolverAddr == "" || serverKey == "" {
		return
	}

	key := resolverSampleKey{
		resolverAddr: resolverAddr,
		localAddr:    localAddr,
		dnsID:        binary.BigEndian.Uint16(packet[:2]),
	}

	var timeoutObservations []resolverTimeoutObservation
	c.resolverStatsMu.Lock()
	if len(c.resolverPending) >= resolverPendingSoftCap {
		timeoutObservations = c.pruneResolverSamplesLocked(sentAt)
		if overflow := len(c.resolverPending) - resolverPendingHardCap; overflow >= 0 {
			c.evictResolverPendingLocked(overflow + 1)
		}
	}
	c.resolverPending[key] = resolverSample{
		serverKey: serverKey,
		sentAt:    sentAt,
	}
	c.resolverStatsMu.Unlock()

	for _, observation := range timeoutObservations {
		c.noteResolverTimeout(observation.serverKey, observation.at)
	}
	c.noteResolverSend(serverKey)
}

func (c *Client) trackResolverSuccess(packet []byte, addr *net.UDPAddr, localAddr string, receivedAt time.Time) {
	if c == nil || len(packet) < 2 || addr == nil {
		return
	}

	key := resolverSampleKey{
		resolverAddr: addr.String(),
		localAddr:    localAddr,
		dnsID:        binary.BigEndian.Uint16(packet[:2]),
	}

	c.resolverStatsMu.Lock()
	sample, ok := c.resolverPending[key]
	if ok {
		delete(c.resolverPending, key)
	}
	c.resolverStatsMu.Unlock()

	if !ok || sample.serverKey == "" {
		return
	}

	if sample.timedOut && !sample.timedOutAt.IsZero() {
		c.retractResolverTimeoutEvent(sample.serverKey, sample.timedOutAt, receivedAt)
	}

	c.noteResolverSuccess(sample.serverKey, receivedAt.Sub(sample.sentAt))
}

func (c *Client) trackResolverFailure(packet []byte, addr *net.UDPAddr, localAddr string, failedAt time.Time) {
	if c == nil || len(packet) < 2 || addr == nil {
		return
	}

	key := resolverSampleKey{
		resolverAddr: addr.String(),
		localAddr:    localAddr,
		dnsID:        binary.BigEndian.Uint16(packet[:2]),
	}

	c.resolverStatsMu.Lock()
	sample, ok := c.resolverPending[key]
	if ok {
		delete(c.resolverPending, key)
	}
	c.resolverStatsMu.Unlock()

	if !ok || sample.serverKey == "" {
		return
	}
	if sample.timedOut {
		return
	}

	c.recordResolverHealthEvent(sample.serverKey, false, failedAt)
}

func (c *Client) collectExpiredResolverTimeouts(now time.Time) {
	if c == nil {
		return
	}
	c.resolverStatsMu.Lock()
	timeoutObservations := c.pruneResolverSamplesLocked(now)
	c.resolverStatsMu.Unlock()
	for _, observation := range timeoutObservations {
		c.noteResolverTimeout(observation.serverKey, observation.at)
	}
}

func (c *Client) resolverRequestTimeout() time.Duration {
	if c == nil {
		return 5 * time.Second
	}
	timeout := c.tunnelPacketTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if checkInterval := c.autoDisableCheckInterval(); checkInterval > 0 && checkInterval < timeout {
		timeout = checkInterval
	}
	if window := c.autoDisableTimeoutWindow(); window > 0 && window < timeout {
		timeout = window
	}
	if timeout < 500*time.Millisecond {
		timeout = 500 * time.Millisecond
	}
	return timeout
}

func (c *Client) resolverLateResponseGrace(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		timeout = c.resolverRequestTimeout()
	}
	grace := timeout * 3
	if grace < time.Second {
		grace = time.Second
	}
	maxTTL := c.resolverSampleTTL()
	if grace > maxTTL {
		grace = maxTTL
	}
	return grace
}

func (c *Client) pruneResolverSamplesLocked(now time.Time) []resolverTimeoutObservation {
	if c == nil || len(c.resolverPending) == 0 {
		return nil
	}

	timeoutBefore := now.Add(-c.resolverRequestTimeout())
	absoluteCutoff := now.Add(-c.resolverSampleTTL())
	requestTimeout := c.resolverRequestTimeout()
	lateGrace := c.resolverLateResponseGrace(requestTimeout)
	var timeoutObservations []resolverTimeoutObservation
	for key, sample := range c.resolverPending {
		if !sample.timedOut {
			if !sample.sentAt.After(timeoutBefore) {
				sample.timedOut = true
				sample.timedOutAt = sample.sentAt.Add(requestTimeout)
				if sample.timedOutAt.After(now) {
					sample.timedOutAt = now
				}
				sample.evictAfter = sample.timedOutAt.Add(lateGrace)
				c.resolverPending[key] = sample
				if sample.serverKey != "" {
					timeoutObservations = append(timeoutObservations, resolverTimeoutObservation{
						serverKey: sample.serverKey,
						at:        sample.timedOutAt,
					})
				}
			}
			if sample.sentAt.Before(absoluteCutoff) {
				delete(c.resolverPending, key)
			}
			continue
		}

		if !sample.evictAfter.IsZero() && !sample.evictAfter.After(now) {
			delete(c.resolverPending, key)
			continue
		}
		if sample.sentAt.Before(absoluteCutoff) {
			delete(c.resolverPending, key)
		}
	}
	return timeoutObservations
}

func (c *Client) evictResolverPendingLocked(evictCount int) {
	if c == nil || evictCount <= 0 || len(c.resolverPending) == 0 {
		return
	}

	type pendingEntry struct {
		key    resolverSampleKey
		sample resolverSample
	}

	entries := make([]pendingEntry, 0, len(c.resolverPending))
	for key, sample := range c.resolverPending {
		entries = append(entries, pendingEntry{key: key, sample: sample})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].sample.timedOut != entries[j].sample.timedOut {
			return entries[i].sample.timedOut
		}
		if !entries[i].sample.sentAt.Equal(entries[j].sample.sentAt) {
			return entries[i].sample.sentAt.Before(entries[j].sample.sentAt)
		}
		if entries[i].key.resolverAddr != entries[j].key.resolverAddr {
			return entries[i].key.resolverAddr < entries[j].key.resolverAddr
		}
		return entries[i].key.dnsID < entries[j].key.dnsID
	})

	if evictCount > len(entries) {
		evictCount = len(entries)
	}
	for i := 0; i < evictCount; i++ {
		delete(c.resolverPending, entries[i].key)
	}
}
