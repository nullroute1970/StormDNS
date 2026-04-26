// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"stormdns-go/internal/logger"
)

func (s *Server) configureSocketBuffers(conn *net.UDPConn) {
	if err := conn.SetReadBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("\U0001F4E1 <yellow>UDP Read Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}

	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("\U0001F4E1 <yellow>UDP Write Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}
}

func (s *Server) startDNSWorkers(ctx context.Context, conn *net.UDPConn, reqCh <-chan request, workerWG *sync.WaitGroup) {
	for i := range s.cfg.DNSRequestWorkers {
		workerWG.Add(1)
		go func(workerID int) {
			defer workerWG.Done()
			s.dnsWorker(ctx, conn, reqCh, workerID)
		}(i + 1)
	}
}

func (s *Server) startReaders(ctx context.Context, conn *net.UDPConn, reqCh chan<- request, readErrCh chan<- error, readerWG *sync.WaitGroup) {
	for i := range s.cfg.UDPReaders {
		readerWG.Add(1)
		go func(readerID int) {
			defer readerWG.Done()
			if err := s.readLoop(ctx, conn, reqCh, readerID); err != nil {
				select {
				case readErrCh <- err:
				default:
				}
			}
		}(i + 1)
	}
}

func (s *Server) sessionCleanupLoop(ctx context.Context) {
	interval := s.cfg.SessionCleanupInterval()
	if interval <= 0 {
		interval = 30 * time.Second
	}
	recentlyClosedSweepInterval := 5 * time.Minute
	sessionTimeout := s.cfg.SessionTimeout()
	closedRetention := s.cfg.ClosedSessionRetention()
	invalidCookieWindow := s.invalidCookieWindow

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastRecentlyClosedSweep := time.Time{}

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			// Run one tick under recover() so a panic in any single sweep
			// (e.g. a malformed entry in the recently-closed table) cannot
			// take down the entire background cleanup goroutine for the
			// rest of the process lifetime.
			s.runSessionCleanupTick(now, sessionTimeout, closedRetention, invalidCookieWindow, recentlyClosedSweepInterval, &lastRecentlyClosedSweep, interval)
		}
	}
}

func (s *Server) runSessionCleanupTick(
	now time.Time,
	sessionTimeout time.Duration,
	closedRetention time.Duration,
	invalidCookieWindow time.Duration,
	recentlyClosedSweepInterval time.Duration,
	lastRecentlyClosedSweep *time.Time,
	cleanupInterval time.Duration,
) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.cleanupPanicsRecovered.Add(1)
			if s.log != nil {
				s.log.Errorf(
					"\U0001F4A5 <red>Session Cleanup Tick Panic Recovered, <yellow>%v</yellow></red>",
					recovered,
				)
			}
		}
	}()

	expired := s.sessions.Cleanup(now, sessionTimeout, closedRetention)
	idleDeferred := s.sessions.CollectIdleDeferredSessions(now, s.deferredIdleCleanupTimeout(cleanupInterval, sessionTimeout))
	s.sessions.SweepTerminalStreams(now, s.cfg.TerminalStreamRetention())
	if lastRecentlyClosedSweep.IsZero() || now.Sub(*lastRecentlyClosedSweep) >= recentlyClosedSweepInterval {
		s.sessions.SweepRecentlyClosedStreams(now)
		*lastRecentlyClosedSweep = now
	}
	s.invalidCookieTracker.Cleanup(now, invalidCookieWindow)
	s.purgeDNSQueryFragments(now)
	s.purgeSOCKS5SynFragments(now)
	for _, idleSession := range idleDeferred {
		s.cleanupIdleDeferredSession(idleSession.ID, idleSession.lastActivityNano, now)
	}
	if len(expired) == 0 {
		return
	}
	for _, expiredSession := range expired {
		s.cleanupClosedSession(expiredSession.ID, expiredSession.record)
	}
	s.log.Infof(
		"\U0001F4E1 <green>Expired Sessions Cleaned, Count: <cyan>%d</cyan></green>",
		len(expired),
	)
}

func (s *Server) deferredIdleCleanupTimeout(cleanupInterval time.Duration, sessionTimeout time.Duration) time.Duration {
	timeout := s.deferredConnectAttemptTimeout()
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 30 * time.Second
	}
	idle := timeout + cleanupInterval
	if sessionTimeout > 0 && sessionTimeout < idle {
		return sessionTimeout
	}
	return idle
}

func (s *Server) readLoop(ctx context.Context, conn *net.UDPConn, reqCh chan<- request, readerID int) error {
	for {
		buffer := s.packetPool.Get().([]byte)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			s.packetPool.Put(buffer)

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			s.log.Debugf(
				"\U0001F4A5 <yellow>UDP Read Error, Reader: <cyan>%d</cyan>, Error: <cyan>%v</cyan></yellow>",
				readerID,
				err,
			)
			return err
		}

		select {
		case reqCh <- request{buf: buffer, size: n, addr: addr}:
		case <-ctx.Done():
			s.packetPool.Put(buffer)
			return nil
		default:
			s.packetPool.Put(buffer)
			s.onDrop(addr, len(reqCh), cap(reqCh))
		}
	}
}

func (s *Server) dnsWorker(ctx context.Context, conn *net.UDPConn, reqCh <-chan request, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-reqCh:
			if !ok {
				return
			}

			response := s.safeHandlePacket(req.buf[:req.size])
			if len(response) != 0 {
				if _, err := conn.WriteToUDP(response, req.addr); err != nil {
					s.log.Debugf(
						"\U0001F4A5 <yellow>UDP Write Error, Worker: <cyan>%d</cyan>, Remote: <cyan>%v</cyan>, Error: <cyan>%v</cyan></yellow>",
						workerID,
						req.addr,
						err,
					)
				}
			}

			s.packetPool.Put(req.buf)
		}
	}
}

func (s *Server) safeHandlePacket(packet []byte) (response []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if s.log != nil {
				s.log.Errorf(
					"\U0001F4A5 <red>Packet Handler Panic Recovered, <yellow>%v</yellow></red>",
					recovered,
				)
			}
			response = nil
		}
	}()

	return s.handlePacket(packet)
}

func (s *Server) onDrop(addr *net.UDPAddr, queueLen int, queueCap int) {
	total := s.droppedPackets.Add(1)

	now := logger.NowUnixNano()
	last := s.lastDropLogUnix.Load()
	interval := s.dropLogIntervalNanos
	if interval <= 0 {
		interval = 2_000_000_000
	}
	if now-last < interval {
		return
	}
	if !s.lastDropLogUnix.CompareAndSwap(last, now) {
		return
	}

	s.log.Warnf(
		"\U0001F6A8 <yellow>Request Queue Overloaded</yellow> <magenta>|</magenta> <blue>Dropped</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Queue</blue>: <cyan>%d/%d</cyan> <magenta>|</magenta> <blue>Remote</blue>: <cyan>%v</cyan>",
		total,
		queueLen,
		queueCap,
		addr,
	)
}
