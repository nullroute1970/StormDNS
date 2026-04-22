// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"time"

	"stormdns-go/internal/arq"
	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/logger"
	SocksProto "stormdns-go/internal/socksproto"
	VpnProto "stormdns-go/internal/vpnproto"
)

type deferredDispatchResult uint8

const (
	deferredDispatchDropped deferredDispatchResult = iota
	deferredDispatchEnqueued
	deferredDispatchAlreadyPending
)

func (s *Server) handlePostSessionPacket(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if s.rejectProtocolMismatchedSyn(vpnPacket.PacketType) {
		return false
	}

	if handled := s.preprocessInboundPacket(vpnPacket); handled {
		return true
	}

	if vpnPacket.PacketType == Enums.PACKET_PACKED_CONTROL_BLOCKS {
		s.handlePackedControlBlocksRequest(vpnPacket, sessionRecord)
		return true
	}

	s.dispatchPostSessionPacket(vpnPacket, sessionRecord)
	return true
}

func (s *Server) dispatchPostSessionPacket(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	switch vpnPacket.PacketType {
	case Enums.PACKET_PING:
		return true
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		return s.handleStreamDataRequest(vpnPacket)
	case Enums.PACKET_STREAM_DATA_NACK:
		return s.handleStreamDataNackRequest(vpnPacket)
	case Enums.PACKET_DNS_QUERY_REQ:
		return s.handleDNSQueryRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_SYN:
		return s.handleStreamSynRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_SOCKS5_SYN:
		return s.handleSOCKS5SynRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_CLOSE_READ:
		return s.handleStreamCloseReadRequest(vpnPacket)
	case Enums.PACKET_STREAM_CLOSE_WRITE:
		return s.handleStreamCloseWriteRequest(vpnPacket)
	case Enums.PACKET_STREAM_RST:
		return s.handleStreamRSTRequest(vpnPacket)
	default:
		return false
	}
}

func (s *Server) enqueueMissingStreamReset(record *sessionRecord, vpnPacket VpnProto.Packet) bool {
	if s == nil || record == nil || vpnPacket.StreamID == 0 ||
		vpnPacket.PacketType == Enums.PACKET_STREAM_SYN ||
		vpnPacket.PacketType == Enums.PACKET_SOCKS5_SYN ||
		vpnPacket.PacketType == Enums.PACKET_PACKED_CONTROL_BLOCKS ||
		vpnPacket.PacketType == Enums.PACKET_PING ||
		vpnPacket.PacketType == Enums.PACKET_DNS_QUERY_REQ {
		return false
	}

	if vpnPacket.PacketType == Enums.PACKET_STREAM_DATA_ACK || vpnPacket.PacketType == Enums.PACKET_STREAM_DATA_NACK {
		return true
	}

	if _, ok := Enums.ReverseControlAckFor(vpnPacket.PacketType); ok {
		return true
	}

	if vpnPacket.PacketType == Enums.PACKET_STREAM_RST {
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST_ACK, vpnPacket.StreamID, vpnPacket.SequenceNum)
		return true
	}

	ack_answer, ok := Enums.GetPacketCloseStream(vpnPacket.PacketType)
	if ok {
		record.enqueueOrphanReset(ack_answer, vpnPacket.StreamID, 0)
	} else {
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
	}
	return true
}

func (s *Server) ackRecentlyClosedStreamPacket(record *sessionRecord, vpnPacket VpnProto.Packet) bool {
	if s == nil || record == nil || vpnPacket.StreamID == 0 {
		return false
	}

	if vpnPacket.PacketType == Enums.PACKET_STREAM_DATA_ACK || vpnPacket.PacketType == Enums.PACKET_STREAM_DATA_NACK {
		return true
	}

	if _, ok := Enums.ReverseControlAckFor(vpnPacket.PacketType); ok {
		return true
	}

	if ackType, ok := Enums.ControlAckFor(vpnPacket.PacketType); ok {
		record.enqueueOrphanReset(ackType, vpnPacket.StreamID, vpnPacket.SequenceNum)
		return true
	}

	return false
}

func isStreamCreationPacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN:
		return true
	default:
		return false
	}
}

func (s *Server) consumeInboundStreamAck(vpnPacket VpnProto.Packet, stream *Stream_server) bool {
	if s == nil || stream == nil || stream.ARQ == nil {
		return false
	}

	handledAck := stream.ARQ.HandleAckPacket(vpnPacket.PacketType, vpnPacket.SequenceNum, vpnPacket.FragmentID)
	now := time.Now()

	if _, ok := Enums.GetPacketCloseStream(vpnPacket.PacketType); handledAck && ok {
		if stream.ARQ.IsClosed() {
			stream.ClearTXQueue()
			if record, exists := s.sessions.Get(vpnPacket.SessionID); exists && record != nil {
				record.deactivateStream(vpnPacket.StreamID)
			}
			s.clearDeferredPacketsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
			stream.mu.Lock()
			stream.Status = "CLOSED"
			if stream.CloseTime.IsZero() {
				stream.CloseTime = now
			}
			stream.mu.Unlock()
		}
	}

	return handledAck
}

func (s *Server) queueImmediateControlAck(record *sessionRecord, packet VpnProto.Packet) bool {
	if s == nil || record == nil {
		return false
	}

	ackType, ok := Enums.ControlAckFor(packet.PacketType)
	if !ok {
		return false
	}

	ackPacket := VpnProto.Packet{
		PacketType:     ackType,
		StreamID:       packet.StreamID,
		SequenceNum:    packet.SequenceNum,
		FragmentID:     packet.FragmentID,
		TotalFragments: packet.TotalFragments,
	}

	if packet.StreamID == 0 {
		return s.queueSessionPacket(record.ID, ackPacket)
	}

	stream, exists := record.getStream(packet.StreamID)
	if (!exists || stream == nil) && isStreamCreationPacketType(packet.PacketType) {
		stream = record.getOrCreateStream(packet.StreamID, s.streamARQConfig(record.DownloadCompression), nil, s.log)
		exists = stream != nil
	}

	if !exists || stream == nil {
		return false
	}

	if (packet.PacketType == Enums.PACKET_SOCKS5_SYN || packet.PacketType == Enums.PACKET_STREAM_SYN) && stream.ARQ != nil {
		return stream.ARQ.SendControlPacketWithTTL(
			ackType,
			packet.SequenceNum,
			packet.FragmentID,
			packet.TotalFragments,
			nil,
			Enums.DefaultPacketPriority(ackType),
			false,
			nil,
			s.cfg.StreamSetupAckTTL(),
		)
	}

	return stream.PushTXPacket(
		Enums.DefaultPacketPriority(ackType),
		ackType,
		packet.SequenceNum,
		packet.FragmentID,
		packet.TotalFragments,
		0,
		0,
		nil,
	)
}

func (s *Server) preprocessInboundPacket(vpnPacket VpnProto.Packet) bool {
	if s == nil {
		return true
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}

	existingStream, streamExists := record.getStream(vpnPacket.StreamID)
	if vpnPacket.StreamID != 0 && (!streamExists || existingStream == nil) && record.isRecentlyClosed(vpnPacket.StreamID, time.Now()) {
		switch vpnPacket.PacketType {
		case Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN:
			record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
			return true
		case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
			record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
			return true
		default:
			if s.ackRecentlyClosedStreamPacket(record, vpnPacket) {
				return true
			}
			if record.shouldSuppressOrphanForClosedStream(vpnPacket.StreamID, time.Now()) {
				return true
			}
			return s.enqueueMissingStreamReset(record, vpnPacket)
		}
	}

	if vpnPacket.StreamID != 0 && (!streamExists || existingStream == nil) {
		return s.enqueueMissingStreamReset(record, vpnPacket)
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND, Enums.PACKET_DNS_QUERY_REQ, Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN:
	default:
		_ = s.queueImmediateControlAck(record, vpnPacket)
	}

	if s.consumeInboundStreamAck(vpnPacket, existingStream) {
		return true
	}

	return false
}

func (s *Server) handlePackedControlBlocksRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil || len(vpnPacket.Payload) < VpnProto.PackedControlBlockSize {
		return false
	}

	handled := false
	sawBlock := false
	VpnProto.ForEachPackedControlBlock(vpnPacket.Payload, func(packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8) bool {
		if packetType == Enums.PACKET_PACKED_CONTROL_BLOCKS {
			return true
		}

		if s.rejectProtocolMismatchedSyn(packetType) {
			return true
		}

		sawBlock = true
		block := VpnProto.Packet{
			SessionID:      vpnPacket.SessionID,
			SessionCookie:  vpnPacket.SessionCookie,
			PacketType:     packetType,
			StreamID:       streamID,
			HasStreamID:    true,
			SequenceNum:    sequenceNum,
			HasSequenceNum: true,
			FragmentID:     fragmentID,
			TotalFragments: totalFragments,
		}

		if s.preprocessInboundPacket(block) {
			handled = true
			return true
		}

		if s.dispatchPostSessionPacket(block, sessionRecord) {
			handled = true
		}

		return true
	})
	return handled || sawBlock
}

func (s *Server) dispatchDeferredSessionPacketOrDrop(vpnPacket VpnProto.Packet, reason string, run func(context.Context)) bool {
	result := s.dispatchDeferredSessionPacketTracked(vpnPacket, reason, run)
	return result != deferredDispatchDropped
}

func deferredTrackedPacketKey(packet VpnProto.Packet) uint64 {
	return uint64(packet.SessionID)<<48 |
		uint64(packet.StreamID)<<32 |
		uint64(packet.PacketType)<<24 |
		uint64(packet.SequenceNum)<<8 |
		uint64(packet.FragmentID)
}

func (s *Server) tryBeginDeferredPacket(packet VpnProto.Packet) bool {
	if s == nil {
		return false
	}
	key := deferredTrackedPacketKey(packet)
	s.deferredInflightMu.Lock()
	defer s.deferredInflightMu.Unlock()
	if s.deferredInflight == nil {
		s.deferredInflight = make(map[uint64]struct{}, 128)
	}
	if _, exists := s.deferredInflight[key]; exists {
		return false
	}
	s.deferredInflight[key] = struct{}{}
	return true
}

func (s *Server) finishDeferredPacket(packet VpnProto.Packet) {
	if s == nil {
		return
	}
	key := deferredTrackedPacketKey(packet)
	s.deferredInflightMu.Lock()
	delete(s.deferredInflight, key)
	s.deferredInflightMu.Unlock()
}

func (s *Server) isDeferredPacketStillTracked(packet VpnProto.Packet) bool {
	if s == nil {
		return false
	}
	key := deferredTrackedPacketKey(packet)
	s.deferredInflightMu.Lock()
	_, exists := s.deferredInflight[key]
	s.deferredInflightMu.Unlock()
	return exists
}

func (s *Server) clearDeferredPacketsForSession(sessionID uint8) {
	if s == nil || sessionID == 0 {
		return
	}
	s.clearDeferredInflightForSession(sessionID)
}

func (s *Server) clearDeferredInflightForSession(sessionID uint8) {
	if s == nil || sessionID == 0 {
		return
	}
	s.deferredInflightMu.Lock()
	for key := range s.deferredInflight {
		if uint8(key>>48) == sessionID {
			delete(s.deferredInflight, key)
		}
	}
	s.deferredInflightMu.Unlock()
}

func (s *Server) clearDeferredPacketsForStream(sessionID uint8, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.clearDeferredInflightForStream(sessionID, streamID)
	if s.deferredConnectSession != nil {
		s.deferredConnectSession.RemoveLane(deferredSessionLane{
			sessionID: sessionID,
			streamID:  streamID,
		})
	}
}

func (s *Server) finalizeDeferredPacketsForStream(sessionID uint8, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.clearDeferredInflightForStream(sessionID, streamID)
	if s.deferredConnectSession != nil {
		s.deferredConnectSession.FinalizeLane(deferredSessionLane{
			sessionID: sessionID,
			streamID:  streamID,
		})
	}
}

func (s *Server) clearDeferredInflightForStream(sessionID uint8, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.deferredInflightMu.Lock()
	for key := range s.deferredInflight {
		if uint8(key>>48) == sessionID && uint16(key>>32) == streamID {
			delete(s.deferredInflight, key)
		}
	}
	s.deferredInflightMu.Unlock()
}

func (s *Server) shouldExecuteDeferredPacket(packet VpnProto.Packet) bool {
	if s == nil {
		return false
	}

	lookup, known := s.sessions.Lookup(packet.SessionID)
	if !known || lookup.State != sessionLookupActive || lookup.Cookie != packet.SessionCookie {
		return false
	}

	if packet.StreamID == 0 {
		return true
	}

	record, ok := s.sessions.Get(packet.SessionID)
	if !ok || record == nil {
		return false
	}

	if record.isRecentlyClosed(packet.StreamID, time.Now()) {
		return false
	}

	stream, exists := record.getStream(packet.StreamID)
	if !exists || stream == nil {
		return true
	}

	if stream.ARQ != nil && (stream.ARQ.IsClosed() || stream.ARQ.IsReset()) {
		return false
	}

	stream.mu.RLock()
	closed := stream.Status == "CLOSED" || !stream.CloseTime.IsZero()
	stream.mu.RUnlock()
	return !closed
}

func (s *Server) dispatchDeferredSessionPacketTracked(vpnPacket VpnProto.Packet, reason string, run func(context.Context)) deferredDispatchResult {
	if s == nil {
		return deferredDispatchDropped
	}

	if !s.tryBeginDeferredPacket(vpnPacket) {
		return deferredDispatchAlreadyPending
	}

	wrappedRun := func(ctx context.Context) {
		defer s.finishDeferredPacket(vpnPacket)
		if ctx.Err() != nil || !s.isDeferredPacketStillTracked(vpnPacket) || !s.shouldExecuteDeferredPacket(vpnPacket) {
			return
		}
		run(ctx)
	}

	if s.dispatchDeferredSessionPacket(vpnPacket, wrappedRun) {
		return deferredDispatchEnqueued
	}

	s.finishDeferredPacket(vpnPacket)

	total := s.deferredDroppedPackets.Add(1)
	now := logger.NowUnixNano()
	last := s.lastDeferredDropLogUnix.Load()
	interval := s.dropLogIntervalNanos
	if interval <= 0 {
		interval = 2_000_000_000
	}

	if now-last >= interval && s.lastDeferredDropLogUnix.CompareAndSwap(last, now) && s.log != nil {
		s.log.Warnf(
			"\U0001F6A8 <yellow>Deferred Session Queue Overloaded</yellow> <magenta>|</magenta> <blue>Dropped</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Packet</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Reason</blue>: <cyan>%s</cyan>",
			total,
			vpnPacket.SessionID,
			vpnPacket.StreamID,
			Enums.PacketTypeName(vpnPacket.PacketType),
			reason,
		)
	}

	return deferredDispatchDropped
}

func (s *Server) handleDNSQueryRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil {
		return false
	}

	totalFragments := vpnPacket.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}

	now := time.Now()
	assembledQuery, ready, completed := s.collectDNSQueryFragments(
		vpnPacket.SessionID,
		vpnPacket.SequenceNum,
		vpnPacket.Payload,
		vpnPacket.FragmentID,
		totalFragments,
		now,
	)

	if completed {
		return true
	}

	if !ready {
		if s.log != nil && totalFragments == 1 {
			s.log.Debugf(
				"\U0001F9E9 <green>Tunnel DNS Fragment Buffered</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan>",
				vpnPacket.SessionID,
				vpnPacket.SequenceNum,
				vpnPacket.FragmentID+1,
				max(1, int(totalFragments)),
			)
		}
		return true
	}

	run := func(ctx context.Context) {
		s.processDeferredDNSQuery(
			ctx,
			vpnPacket.SessionID,
			vpnPacket.SessionCookie,
			vpnPacket.SequenceNum,
			sessionRecord.DownloadCompression,
			sessionRecord.DownloadMTUBytes,
			assembledQuery,
		)
	}

	result := s.dispatchDeferredSessionPacketTracked(vpnPacket, "dns-query", run)
	if result == deferredDispatchDropped {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok || record == nil {
		return true
	}
	_ = s.queueImmediateControlAck(record, vpnPacket)
	return true
}

func (s *Server) tryHandleImmediateConnectedStreamSyn(vpnPacket VpnProto.Packet) bool {
	if s == nil || vpnPacket.SessionID == 0 || vpnPacket.StreamID == 0 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok || record == nil {
		return false
	}

	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil || stream.ARQ == nil {
		return false
	}

	stream.mu.RLock()
	connected := stream.Connected
	targetMatches := stream.TargetHost == s.cfg.ForwardIP && stream.TargetPort == uint16(s.cfg.ForwardPort)
	stream.mu.RUnlock()
	if !connected || !targetMatches {
		return false
	}

	stream.ARQ.SendControlPacketWithTTL(
		Enums.PACKET_STREAM_CONNECTED,
		vpnPacket.SequenceNum,
		0,
		0,
		nil,
		Enums.DefaultPacketPriority(Enums.PACKET_STREAM_CONNECTED),
		true,
		nil,
		s.cfg.StreamResultPacketTTL(),
	)
	s.clearDeferredPacketsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	return true
}

func (s *Server) tryHandleImmediateConnectedSOCKS5Syn(vpnPacket VpnProto.Packet) bool {
	if s == nil || vpnPacket.SessionID == 0 || vpnPacket.StreamID == 0 {
		return false
	}
	if vpnPacket.TotalFragments > 1 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok || record == nil {
		return false
	}

	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil || stream.ARQ == nil {
		return false
	}

	stream.mu.RLock()
	connected := stream.Connected
	currentHost := stream.TargetHost
	currentPort := stream.TargetPort
	stream.mu.RUnlock()
	if !connected {
		return false
	}

	target, err := SocksProto.ParseTargetPayload(vpnPacket.Payload)
	if err != nil {
		return false
	}

	packetType := uint8(Enums.PACKET_SOCKS5_CONNECTED)
	if currentHost != target.Host || currentPort != target.Port {
		packetType = Enums.PACKET_SOCKS5_CONNECT_FAIL
	}

	stream.ARQ.SendControlPacketWithTTL(
		packetType,
		vpnPacket.SequenceNum,
		0,
		0,
		nil,
		Enums.DefaultPacketPriority(packetType),
		true,
		nil,
		s.cfg.StreamResultPacketTTL(),
	)
	s.cleanupStreamArtifacts(vpnPacket.SessionID, vpnPacket.StreamID)
	return true
}

func (s *Server) tryHandleImmediateRejectedSOCKS5Syn(vpnPacket VpnProto.Packet) bool {
	if s == nil || vpnPacket.SessionID == 0 || vpnPacket.StreamID == 0 {
		return false
	}
	if vpnPacket.TotalFragments > 1 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok || record == nil {
		return false
	}

	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil || stream.ARQ == nil {
		return false
	}

	target, err := SocksProto.ParseTargetPayload(vpnPacket.Payload)
	if err != nil {
		return false
	}
	if err := validateSOCKSTargetHost(target.Host); err != nil {
		packetType := s.mapSOCKSConnectError(err)
		stream.ARQ.SendControlPacketWithTTL(
			packetType,
			vpnPacket.SequenceNum,
			0,
			0,
			nil,
			Enums.DefaultPacketPriority(packetType),
			true,
			nil,
			s.cfg.StreamFailurePacketTTL(),
		)
		s.cleanupStreamArtifacts(vpnPacket.SessionID, vpnPacket.StreamID)
		return true
	}

	return false
}

func (s *Server) handleStreamSynRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || sessionRecord == nil {
		return false
	}

	if s.tryHandleImmediateConnectedStreamSyn(vpnPacket) {
		record, ok := s.sessions.Get(vpnPacket.SessionID)
		if !ok || record == nil {
			return true
		}
		_ = s.queueImmediateControlAck(record, vpnPacket)
		return true
	}

	run := func(ctx context.Context) {
		s.processDeferredStreamSyn(ctx, vpnPacket)
	}

	result := s.dispatchDeferredSessionPacketTracked(vpnPacket, "stream-syn", run)
	if result == deferredDispatchDropped {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok || record == nil {
		return true
	}
	_ = s.queueImmediateControlAck(record, vpnPacket)
	return true
}

func (s *Server) rejectProtocolMismatchedSyn(packetType uint8) bool {
	if s == nil {
		return false
	}

	switch s.cfg.ProtocolType {
	case "TCP":
		return packetType == Enums.PACKET_SOCKS5_SYN
	case "SOCKS5":
		return packetType == Enums.PACKET_STREAM_SYN
	default:
		return false
	}
}

func (s *Server) handleSOCKS5SynRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || sessionRecord == nil {
		return false
	}

	if s.tryHandleImmediateConnectedSOCKS5Syn(vpnPacket) {
		record, ok := s.sessions.Get(vpnPacket.SessionID)
		if !ok || record == nil {
			return true
		}
		_ = s.queueImmediateControlAck(record, vpnPacket)
		return true
	}
	if s.tryHandleImmediateRejectedSOCKS5Syn(vpnPacket) {
		record, ok := s.sessions.Get(vpnPacket.SessionID)
		if !ok || record == nil {
			return true
		}
		_ = s.queueImmediateControlAck(record, vpnPacket)
		return true
	}

	run := func(ctx context.Context) {
		s.processDeferredSOCKS5Syn(ctx, vpnPacket)
	}

	result := s.dispatchDeferredSessionPacketTracked(vpnPacket, "socks5-syn", run)
	if result == deferredDispatchDropped {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok || record == nil {
		return true
	}
	_ = s.queueImmediateControlAck(record, vpnPacket)
	return true
}

func (s *Server) handleStreamDataRequest(vpnPacket VpnProto.Packet) bool {
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return true
	}

	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil {
		return true
	}

	if stream.ARQ == nil {
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
		return true
	}

	if stream.ARQ.IsClosed() || stream.ARQ.IsReset() {
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
		return true
	}

	stream.enqueueInboundData(vpnPacket.PacketType, vpnPacket.SequenceNum, vpnPacket.FragmentID, vpnPacket.Payload)
	return true
}

func (s *Server) handleStreamDataNackRequest(vpnPacket VpnProto.Packet) bool {
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return true
	}

	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil || stream.ARQ == nil {
		return true
	}

	stream.ARQ.HandleDataNack(vpnPacket.SequenceNum)
	return true
}

func (s *Server) handleStreamCloseReadRequest(vpnPacket VpnProto.Packet) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return true
	}

	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil {
		return true
	}

	s.clearDeferredPacketsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	stream.ARQ.MarkCloseReadReceived()
	return true
}

func (s *Server) handleStreamCloseWriteRequest(vpnPacket VpnProto.Packet) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return true
	}

	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil {
		return true
	}

	s.clearDeferredPacketsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	stream.ARQ.MarkCloseWriteReceived()
	return true
}

func (s *Server) handleStreamRSTRequest(vpnPacket VpnProto.Packet) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return true
	}

	now := time.Now()
	stream, ok := record.getStream(vpnPacket.StreamID)
	if ok && stream != nil {
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST_ACK, vpnPacket.StreamID, vpnPacket.SequenceNum)

		if stream.ARQ != nil && stream.ARQ.IsClosed() {
			stream.ClearTXQueue()
			record.deactivateStream(vpnPacket.StreamID)
			s.clearDeferredPacketsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
			return true
		}

		stream.ClearTXQueue()
		record.deactivateStream(vpnPacket.StreamID)
		s.clearDeferredPacketsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
		stream.ARQ.MarkRstReceived()
		stream.ARQ.Close("peer reset before/while connect", arq.CloseOptions{Force: true})
		stream.mu.Lock()
		stream.Status = "CLOSED"
		stream.CloseTime = now
		stream.mu.Unlock()
	} else {
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST_ACK, vpnPacket.StreamID, vpnPacket.SequenceNum)
		record.noteStreamClosed(vpnPacket.StreamID, now, false)
		s.clearDeferredPacketsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	}

	s.removeSOCKS5SynFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	return true
}
