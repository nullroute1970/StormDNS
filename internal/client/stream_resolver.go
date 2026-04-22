package client

import (
	"time"

	"stormdns-go/internal/arq"
	Enums "stormdns-go/internal/enums"
)

// directionalDuplicationCounts returns the effective upload/download and
// upload-setup/download-setup duplication counts. After config normalization
// all four fields are guaranteed to be >= 1, so we just read them directly and
// apply a safety floor of 1 for callers that construct the config in tests
// without going through validation.
func (c *Client) directionalDuplicationCounts() (uploadData, downloadData, uploadSetup, downloadSetup int) {
	uploadData = c.cfg.UploadPacketDuplicationCount
	if uploadData < 1 {
		uploadData = 1
	}
	downloadData = c.cfg.DownloadPacketDuplicationCount
	if downloadData < 1 {
		downloadData = 1
	}
	uploadSetup = c.cfg.UploadSetupPacketDuplicationCount
	if uploadSetup < uploadData {
		uploadSetup = uploadData
	}
	downloadSetup = c.cfg.DownloadSetupPacketDuplicationCount
	if downloadSetup < downloadData {
		downloadSetup = downloadData
	}
	return uploadData, downloadData, uploadSetup, downloadSetup
}

func (c *Client) runtimePacketDuplicationCount(packetType uint8) int {
	if c == nil {
		return 1
	}

	uploadData, downloadData, uploadSetup, downloadSetup := c.directionalDuplicationCounts()

	var count int
	switch packetType {
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		count = uploadData
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_DATA_NACK:
		count = downloadData
	case Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN:
		count = uploadSetup
	case Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Enums.PACKET_STREAM_CLOSE_READ,
		Enums.PACKET_STREAM_CLOSE_WRITE:
		count = downloadSetup
	case Enums.PACKET_PING:
		// Ping reliability tracks the stronger of the two directional counts
		// since it probes both legs of the path, but is capped at 2 to avoid
		// spamming probes when duplication is turned up high.
		count = uploadData
		if downloadData > count {
			count = downloadData
		}
		return min(count, 2)
	default:
		count = uploadData
	}

	if count < 1 {
		count = 1
	}
	return count
}

func (c *Client) selectTargetConnectionsForPacket(packetType uint8, streamID uint16) ([]Connection, error) {
	targetCount := c.runtimePacketDuplicationCount(packetType)

	if c == nil || c.balancer == nil || streamID == 0 || c.balancer.ValidCount() <= 0 {
		return c.selectUniqueRuntimeConnections(targetCount)
	}

	if packetType != Enums.PACKET_STREAM_DATA && packetType != Enums.PACKET_STREAM_RESEND {
		return c.selectUniqueRuntimeConnections(targetCount)
	}

	stream, ok := c.getStream(streamID)
	if !ok || stream == nil {
		return c.selectUniqueRuntimeConnections(targetCount)
	}

	var (
		preferred Connection
		found     bool
	)

	if packetType == Enums.PACKET_STREAM_RESEND {
		preferred, found = c.selectStreamPreferredConnectionForResend(stream)
	} else {
		preferred, found = c.ensureStreamPreferredConnection(stream)
	}

	if !found {
		return c.selectUniqueRuntimeConnections(targetCount)
	}

	if targetCount <= 1 {
		return []Connection{preferred}, nil
	}

	if cached, ok := c.getCachedStreamConnectionPlan(stream, preferred.Key, targetCount); ok {
		return cached, nil
	}

	selected := make([]Connection, 0, targetCount)
	selected = append(selected, preferred)

	for _, connection := range c.balancer.GetUniqueConnections(targetCount) {
		if !connection.IsValid || connection.Key == "" {
			continue
		}
		dup := false
		for _, s := range selected {
			if s.Key == connection.Key {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		selected = append(selected, connection)
		if len(selected) >= targetCount {
			return selected, nil
		}
	}

	if len(selected) == 0 {
		return nil, ErrNoValidConnections
	}

	c.cacheStreamConnectionPlan(stream, preferred.Key, targetCount, selected)
	return selected, nil
}

func (c *Client) selectUniqueRuntimeConnections(requiredCount int) ([]Connection, error) {
	if c == nil {
		return nil, ErrNoValidConnections
	}

	if c.balancer == nil {
		return nil, ErrNoValidConnections
	}

	connections := c.balancer.GetUniqueConnections(requiredCount)
	if len(connections) == 0 {
		return nil, ErrNoValidConnections
	}

	// Filter out runtime-disabled resolvers so control packets
	// (SYN, CLOSE, RST, ACK, etc.) are not sent to known-bad resolvers.
	filtered := connections[:0]
	for _, conn := range connections {
		if !c.isRuntimeDisabledResolver(conn.Key) {
			filtered = append(filtered, conn)
		}
	}
	if len(filtered) == 0 {
		return nil, ErrNoValidConnections
	}

	return filtered, nil
}

func (c *Client) selectStreamPreferredConnectionForResend(stream *Stream_client) (Connection, bool) {
	if c == nil || stream == nil {
		return Connection{}, false
	}

	stream.resolverMu.Lock()
	stream.ResolverResendStreak++
	streak := stream.ResolverResendStreak
	stream.resolverMu.Unlock()

	if streak >= c.streamResolverFailoverResendThreshold {
		return c.maybeFailoverStreamPreferredConnection(stream)
	}
	return c.ensureStreamPreferredConnection(stream)
}

func (c *Client) getValidStreamPreferredConnection(stream *Stream_client) (Connection, bool) {
	if c == nil || stream == nil {
		return Connection{}, false
	}
	stream.resolverMu.Lock()
	preferredKey := stream.PreferredServerKey
	stream.resolverMu.Unlock()
	if preferredKey == "" {
		return Connection{}, false
	}
	if c.isRuntimeDisabledResolver(preferredKey) {
		return Connection{}, false
	}
	connection, ok := c.GetConnectionByKey(preferredKey)
	if !ok || !connection.IsValid {
		return Connection{}, false
	}
	return connection, true
}

func (c *Client) selectAlternateStreamConnection(excludeKey string) (Connection, bool) {
	if c == nil || c.balancer == nil {
		return Connection{}, false
	}

	if excludeKey != "" {
		if replacement, ok := c.balancer.GetBestConnectionExcluding(excludeKey); ok && !c.isRuntimeDisabledResolver(replacement.Key) {
			return replacement, true
		}
	}

	for _, connection := range c.balancer.GetAllValidConnections() {
		if !connection.IsValid || connection.Key == "" {
			continue
		}
		if c.isRuntimeDisabledResolver(connection.Key) {
			continue
		}
		if excludeKey != "" && connection.Key == excludeKey {
			continue
		}
		return connection, true
	}

	return Connection{}, false
}

func (c *Client) assignStreamPreferredConnection(stream *Stream_client, connection Connection, markFailover bool) (Connection, bool) {
	if c == nil || stream == nil {
		return Connection{}, false
	}
	if !connection.IsValid || connection.Key == "" {
		stream.resolverMu.Lock()
		stream.PreferredServerKey = ""
		stream.resolverMu.Unlock()
		return Connection{}, false
	}

	stream.resolverMu.Lock()
	stream.PreferredServerKey = connection.Key
	stream.ResolverResendStreak = 0
	stream.CachedResolverPlan = nil
	stream.CachedResolverPlanFor = ""
	stream.CachedResolverPlanSize = 0
	stream.CachedResolverVersion = 0
	if markFailover {
		stream.LastResolverFailoverAt = time.Now()
	}
	stream.resolverMu.Unlock()
	return connection, true
}

func (c *Client) ensureStreamPreferredConnection(stream *Stream_client) (Connection, bool) {
	if preferred, ok := c.getValidStreamPreferredConnection(stream); ok {
		return preferred, true
	}

	stream.resolverMu.Lock()
	excludeKey := stream.PreferredServerKey
	stream.resolverMu.Unlock()
	if fallback, ok := c.selectAlternateStreamConnection(excludeKey); ok {
		return c.assignStreamPreferredConnection(stream, fallback, false)
	}
	return Connection{}, false
}

func (c *Client) maybeFailoverStreamPreferredConnection(stream *Stream_client) (Connection, bool) {
	current, ok := c.getValidStreamPreferredConnection(stream)
	if !ok {
		return c.ensureStreamPreferredConnection(stream)
	}

	stream.resolverMu.Lock()
	lastSwitch := stream.LastResolverFailoverAt
	stream.resolverMu.Unlock()
	if !lastSwitch.IsZero() && time.Since(lastSwitch) < c.streamResolverFailoverCooldown {
		return current, true
	}

	replacement, ok := c.selectAlternateStreamConnection(current.Key)
	if !ok {
		return current, true
	}
	return c.assignStreamPreferredConnection(stream, replacement, true)
}

func (c *Client) noteStreamProgress(streamID uint16) {
	if c == nil || streamID == 0 {
		return
	}
	stream, ok := c.getStream(streamID)
	if !ok || stream == nil {
		return
	}
	stream.resolverMu.Lock()
	stream.ResolverResendStreak = 0
	stream.resolverMu.Unlock()
}

func (c *Client) getCachedStreamConnectionPlan(stream *Stream_client, preferredKey string, targetCount int) ([]Connection, bool) {
	if c == nil || stream == nil || c.balancer == nil || preferredKey == "" || targetCount <= 1 {
		return nil, false
	}

	version := c.balancer.SnapshotVersion()
	stream.resolverMu.Lock()
	defer stream.resolverMu.Unlock()

	if stream.CachedResolverVersion != version ||
		stream.CachedResolverPlanFor != preferredKey ||
		stream.CachedResolverPlanSize != targetCount ||
		len(stream.CachedResolverPlan) == 0 {
		return nil, false
	}

	return stream.CachedResolverPlan, true
}

func (c *Client) cacheStreamConnectionPlan(stream *Stream_client, preferredKey string, targetCount int, selected []Connection) {
	if c == nil || stream == nil || c.balancer == nil || preferredKey == "" || targetCount <= 1 || len(selected) == 0 {
		return
	}

	cached := make([]Connection, len(selected))
	copy(cached, selected)
	version := c.balancer.SnapshotVersion()

	stream.resolverMu.Lock()
	stream.CachedResolverPlan = cached
	stream.CachedResolverPlanFor = preferredKey
	stream.CachedResolverPlanSize = targetCount
	stream.CachedResolverVersion = version
	stream.resolverMu.Unlock()
}

func (c *Client) shouldTransmitQueuedStreamPacket(stream *Stream_client, item *clientStreamTXPacket) bool {
	if c == nil || stream == nil || item == nil {
		return false
	}

	if item.PacketType != Enums.PACKET_STREAM_DATA && item.PacketType != Enums.PACKET_STREAM_RESEND {
		return true
	}

	arqObj, ok := stream.Stream.(*arq.ARQ)
	if !ok || arqObj == nil {
		return false
	}

	return arqObj.HasPendingSequence(item.SequenceNum)
}

func (c *Client) GetConnectionByKey(key string) (Connection, bool) {
	if c == nil || key == "" {
		return Connection{}, false
	}
	if c.balancer != nil {
		if conn, ok := c.balancer.GetConnectionByKey(key); ok {
			return conn, true
		}
	}
	idx, ok := c.connectionsByKey[key]
	if !ok || idx < 0 || idx >= len(c.connections) {
		return Connection{}, false
	}
	return c.connections[idx], true
}
