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
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"stormdns-go/internal/config"
	Enums "stormdns-go/internal/enums"
	fragmentStore "stormdns-go/internal/fragmentstore"
	VpnProto "stormdns-go/internal/vpnproto"
)

type testNetConn struct {
	closed bool
}

func (t *testNetConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (t *testNetConn) Write(p []byte) (int, error)        { return len(p), nil }
func (t *testNetConn) Close() error                       { t.closed = true; return nil }
func (t *testNetConn) LocalAddr() net.Addr                { return testAddr("local") }
func (t *testNetConn) RemoteAddr() net.Addr               { return testAddr("remote") }
func (t *testNetConn) SetDeadline(_ time.Time) error      { return nil }
func (t *testNetConn) SetReadDeadline(_ time.Time) error  { return nil }
func (t *testNetConn) SetWriteDeadline(_ time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

type scriptedSOCKS5Conn struct {
	testNetConn
	readBufs       [][]byte
	readIndex      int
	writes         [][]byte
	deadlineActive bool
}

func (c *scriptedSOCKS5Conn) Read(p []byte) (int, error) {
	if c.readIndex >= len(c.readBufs) {
		return 0, io.EOF
	}
	chunk := c.readBufs[c.readIndex]
	c.readIndex++
	copy(p, chunk)
	return len(chunk), nil
}

func (c *scriptedSOCKS5Conn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *scriptedSOCKS5Conn) SetDeadline(t time.Time) error {
	c.deadlineActive = !t.IsZero()
	return nil
}

func newTestServerForStreamSyn(protocol string) *Server {
	return &Server{
		cfg: config.ServerConfig{
			ProtocolType:                  protocol,
			ForwardIP:                     "127.0.0.1",
			ForwardPort:                   9000,
			StreamResultPacketTTLSeconds:  300.0,
			StreamFailurePacketTTLSeconds: 120.0,
			ARQWindowSize:                 64,
			ARQInitialRTOSeconds:          0.2,
			ARQMaxRTOSeconds:              1.0,
			ARQControlInitialRTOSeconds:   0.2,
			ARQControlMaxRTOSeconds:       1.0,
			ARQMaxControlRetries:          10,
			ARQInactivityTimeoutSeconds:   60.0,
			ARQDataPacketTTLSeconds:       60.0,
			ARQControlPacketTTLSeconds:    60.0,
			ARQMaxDataRetries:             100,
			ARQTerminalDrainTimeoutSec:    30.0,
			ARQTerminalAckWaitTimeoutSec:  10.0,
		},
		sessions:               newSessionStore(8, 32),
		deferredDNSSession:     newDeferredSessionProcessor(1, 8, nil),
		deferredConnectSession: newDeferredSessionProcessor(1, 8, nil),
		deferredInflight:       make(map[uint64]struct{}, 8),
		dnsFragments:           fragmentStore.New[dnsFragmentKey](8),
		socks5Fragments:        fragmentStore.New[socks5FragmentKey](8),
	}
}

func TestQueueImmediateControlAckCreatesStreamForStreamSyn(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(21)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record

	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, 1)
	if !s.queueImmediateControlAck(record, packet) {
		t.Fatal("expected STREAM_SYN immediate ACK to be queued")
	}

	stream, ok := record.getStream(1)
	if !ok || stream == nil {
		t.Fatal("expected STREAM_SYN to create stream before queueing SYN_ACK")
	}

	key := Enums.PacketIdentityKey(stream.ID, Enums.PACKET_STREAM_SYN_ACK, packet.SequenceNum, packet.FragmentID)
	if _, ok := stream.TXQueue.Get(key); !ok {
		t.Fatal("expected STREAM_SYN_ACK to be queued on created stream")
	}
}

func TestProcessDeferredStreamSynQueuesConnectedAndEnablesIO(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(22)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record

	local, remote := net.Pipe()
	defer remote.Close()

	s.dialStreamUpstreamFn = func(network string, address string, timeoutSeconds time.Duration) (net.Conn, error) {
		return local, nil
	}

	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, 2)
	s.processDeferredStreamSyn(context.Background(), packet)

	stream, ok := record.getStream(2)
	if !ok || stream == nil {
		t.Fatal("expected stream to exist after STREAM_SYN processing")
	}
	defer stream.Abort("test cleanup")

	stream.mu.RLock()
	connected := stream.Connected
	status := stream.Status
	stream.mu.RUnlock()
	if !connected {
		t.Fatal("expected stream to be marked connected")
	}
	if status != "CONNECTED" {
		t.Fatalf("expected stream status CONNECTED, got %q", status)
	}

	key := Enums.PacketIdentityKey(stream.ID, Enums.PACKET_STREAM_CONNECTED, packet.SequenceNum, 0)
	if pkt, ok := stream.TXQueue.Get(key); !ok || pkt == nil {
		t.Fatal("expected STREAM_CONNECTED to be queued after successful connect")
	}
}

func TestProcessDeferredStreamSynDoesNotAttachAfterCancellation(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(46)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record

	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	conn := &testNetConn{}
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		close(dialStarted)
		<-releaseDial
		return conn, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, 16)
	go func() {
		defer close(done)
		s.processDeferredStreamSyn(ctx, packet)
	}()

	select {
	case <-dialStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for deferred stream dial to start")
	}

	cancel()
	close(releaseDial)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for deferred stream processing to finish")
	}

	stream, ok := record.getStream(packet.StreamID)
	if !ok || stream == nil {
		t.Fatal("expected stream to remain allocated for cancelled attempt")
	}

	stream.mu.RLock()
	connected := stream.Connected
	upstream := stream.UpstreamConn
	stream.mu.RUnlock()
	if connected {
		t.Fatal("expected cancelled deferred stream connect to avoid attaching upstream")
	}
	if upstream != nil {
		t.Fatal("expected cancelled deferred stream connect to leave no upstream connection attached")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn.closed {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected cancelled deferred stream connect to close late dial result")
}

func TestHandleStreamSynFastPathsAlreadyConnectedStream(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(40)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record

	stream := record.getOrCreateStream(7, s.streamARQConfig(record.DownloadCompression), nil, s.log)
	if stream == nil {
		t.Fatal("expected stream to exist")
	}
	stream.mu.Lock()
	stream.Connected = true
	stream.TargetHost = s.cfg.ForwardIP
	stream.TargetPort = uint16(s.cfg.ForwardPort)
	stream.Status = "CONNECTED"
	stream.mu.Unlock()

	lane := deferredSessionLane{sessionID: record.ID, streamID: stream.ID}
	if !s.deferredConnectSession.Enqueue(lane, func(context.Context) {}) {
		t.Fatal("expected queued duplicate lane")
	}

	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, stream.ID)
	if !s.handleStreamSynRequest(packet, viewForRecord(record)) {
		t.Fatal("expected connected stream SYN to be handled")
	}

	if pending := s.deferredConnectSession.workers[0].pending.Load(); pending != 0 {
		t.Fatalf("expected fast-path handling to clear queued duplicates, got pending=%d", pending)
	}

	key := Enums.PacketIdentityKey(stream.ID, Enums.PACKET_STREAM_CONNECTED, packet.SequenceNum, 0)
	if pkt, ok := stream.TXQueue.Get(key); !ok || pkt == nil {
		t.Fatal("expected STREAM_CONNECTED to be queued by fast-path")
	}
}

func TestHandleSOCKS5SynFastPathsAlreadyConnectedStream(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	record := newTestSessionRecord(43)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record

	stream := record.getOrCreateStream(6, s.streamARQConfig(record.DownloadCompression), nil, s.log)
	if stream == nil {
		t.Fatal("expected stream to exist")
	}
	stream.mu.Lock()
	stream.Connected = true
	stream.TargetHost = "149.154.167.92"
	stream.TargetPort = 443
	stream.Status = "CONNECTED"
	stream.mu.Unlock()

	lane := deferredSessionLane{sessionID: record.ID, streamID: stream.ID}
	if !s.deferredConnectSession.Enqueue(lane, func(context.Context) {}) {
		t.Fatal("expected queued duplicate lane")
	}

	packet := packetWithSession(Enums.PACKET_SOCKS5_SYN, record.ID, record.Cookie, stream.ID)
	packet.Payload = []byte{0x01, 149, 154, 167, 92, 0x01, 0xBB}
	packet.TotalFragments = 1
	if !s.handleSOCKS5SynRequest(packet, viewForRecord(record)) {
		t.Fatal("expected connected SOCKS5 stream SYN to be handled")
	}

	if pending := s.deferredConnectSession.workers[0].pending.Load(); pending != 0 {
		t.Fatalf("expected fast-path SOCKS5 handling to clear queued duplicates, got pending=%d", pending)
	}

	key := Enums.PacketIdentityKey(stream.ID, Enums.PACKET_SOCKS5_CONNECTED, packet.SequenceNum, 0)
	if pkt, ok := stream.TXQueue.Get(key); !ok || pkt == nil {
		t.Fatal("expected SOCKS5_CONNECTED to be queued by fast-path")
	}
}

func TestProcessDeferredSOCKS5SynDoesNotAttachAfterCancellation(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	record := newTestSessionRecord(47)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record

	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	conn := &testNetConn{}
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		close(dialStarted)
		<-releaseDial
		return conn, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	packet := packetWithSession(Enums.PACKET_SOCKS5_SYN, record.ID, record.Cookie, 17)
	packet.Payload = []byte{0x01, 149, 154, 167, 92, 0x01, 0xBB}
	packet.TotalFragments = 1
	go func() {
		defer close(done)
		s.processDeferredSOCKS5Syn(ctx, packet)
	}()

	select {
	case <-dialStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for deferred SOCKS5 dial to start")
	}

	cancel()
	close(releaseDial)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for deferred SOCKS5 processing to finish")
	}

	stream, ok := record.getStream(packet.StreamID)
	if !ok || stream == nil {
		t.Fatal("expected stream to remain allocated for cancelled SOCKS5 attempt")
	}

	stream.mu.RLock()
	connected := stream.Connected
	upstream := stream.UpstreamConn
	stream.mu.RUnlock()
	if connected {
		t.Fatal("expected cancelled deferred SOCKS5 connect to avoid attaching upstream")
	}
	if upstream != nil {
		t.Fatal("expected cancelled deferred SOCKS5 connect to leave no upstream connection attached")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn.closed {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected cancelled deferred SOCKS5 connect to close late dial result")
}

func TestHandleSOCKS5SynFastPathRejectsDifferentTarget(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	record := newTestSessionRecord(44)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record

	stream := record.getOrCreateStream(7, s.streamARQConfig(record.DownloadCompression), nil, s.log)
	if stream == nil {
		t.Fatal("expected stream to exist")
	}
	stream.mu.Lock()
	stream.Connected = true
	stream.TargetHost = "149.154.167.92"
	stream.TargetPort = 443
	stream.Status = "CONNECTED"
	stream.mu.Unlock()

	packet := packetWithSession(Enums.PACKET_SOCKS5_SYN, record.ID, record.Cookie, stream.ID)
	packet.Payload = []byte{0x01, 149, 154, 167, 92, 0x00, 0x50}
	packet.TotalFragments = 1
	if !s.handleSOCKS5SynRequest(packet, viewForRecord(record)) {
		t.Fatal("expected mismatched SOCKS5 target to be handled")
	}

	key := Enums.PacketIdentityKey(stream.ID, Enums.PACKET_SOCKS5_CONNECT_FAIL, packet.SequenceNum, 0)
	if pkt, ok := stream.TXQueue.Get(key); !ok || pkt == nil {
		t.Fatal("expected SOCKS5_CONNECT_FAIL to be queued for mismatched fast-path target")
	}
}

func TestHandleSOCKS5SynImmediateRejectsBlockedTarget(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	record := newTestSessionRecord(45)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record

	stream := record.getOrCreateStream(8, s.streamARQConfig(record.DownloadCompression), nil, s.log)
	if stream == nil {
		t.Fatal("expected stream to exist")
	}

	packet := packetWithSession(Enums.PACKET_SOCKS5_SYN, record.ID, record.Cookie, stream.ID)
	packet.Payload = []byte{0x01, 0, 0, 0, 0, 0x01, 0xBB}
	packet.TotalFragments = 1
	if !s.handleSOCKS5SynRequest(packet, viewForRecord(record)) {
		t.Fatal("expected blocked target SOCKS5 SYN to be handled")
	}

	if pending := s.deferredConnectSession.workers[0].pending.Load(); pending != 0 {
		t.Fatalf("expected blocked target to avoid deferred enqueue, got pending=%d", pending)
	}

	key := Enums.PacketIdentityKey(stream.ID, Enums.PACKET_SOCKS5_RULESET_DENIED, packet.SequenceNum, 0)
	if pkt, ok := stream.TXQueue.Get(key); !ok || pkt == nil {
		t.Fatal("expected SOCKS5_RULESET_DENIED to be queued for blocked target")
	}
}

func TestHandleStreamSynDedupesPendingDeferredDuplicates(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(22)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record

	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, 9)
	if !s.handleStreamSynRequest(packet, viewForRecord(record)) {
		t.Fatal("expected first STREAM_SYN to be accepted")
	}
	if !s.handleStreamSynRequest(packet, viewForRecord(record)) {
		t.Fatal("expected duplicate pending STREAM_SYN to be acknowledged")
	}

	if pending := s.deferredConnectSession.workers[0].pending.Load(); pending != 1 {
		t.Fatalf("expected exactly one deferred STREAM_SYN task, got %d", pending)
	}

	stream, ok := record.getStream(9)
	if !ok || stream == nil {
		t.Fatal("expected STREAM_SYN ACK path to create stream")
	}

	key := Enums.PacketIdentityKey(stream.ID, Enums.PACKET_STREAM_SYN_ACK, packet.SequenceNum, packet.FragmentID)
	if _, ok := stream.TXQueue.Get(key); !ok {
		t.Fatal("expected STREAM_SYN_ACK to be queued for accepted duplicate")
	}
}

func TestClearDeferredPacketsForStreamAllowsFreshRequeue(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	packet := packetWithSession(Enums.PACKET_STREAM_SYN, 7, 3, 9)

	if !s.tryBeginDeferredPacket(packet) {
		t.Fatal("expected first deferred marker to be recorded")
	}
	if s.tryBeginDeferredPacket(packet) {
		t.Fatal("expected duplicate deferred marker to be rejected while pending")
	}

	s.clearDeferredPacketsForStream(packet.SessionID, packet.StreamID)

	if !s.tryBeginDeferredPacket(packet) {
		t.Fatal("expected stream deferred markers to be cleared")
	}
	s.finishDeferredPacket(packet)
}

func TestDeferredSessionProcessorRemoveLaneCompactsQueuedTask(t *testing.T) {
	processor := newDeferredSessionProcessor(1, 1, nil)
	if processor == nil {
		t.Fatal("expected deferred processor")
	}

	lane := deferredSessionLane{sessionID: 7, streamID: 9}
	if !processor.Enqueue(lane, func(context.Context) {}) {
		t.Fatal("expected first task to enqueue")
	}
	if pending := processor.workers[0].pending.Load(); pending != 1 {
		t.Fatalf("expected pending=1 before compaction, got %d", pending)
	}

	processor.RemoveLane(lane)

	if pending := processor.workers[0].pending.Load(); pending != 0 {
		t.Fatalf("expected pending=0 after compaction, got %d", pending)
	}
	if len(processor.workers[0].jobs) != 0 {
		t.Fatalf("expected worker queue to be empty after compaction, got %d", len(processor.workers[0].jobs))
	}

	otherLane := deferredSessionLane{sessionID: 7, streamID: 10}
	if !processor.Enqueue(otherLane, func(context.Context) {}) {
		t.Fatal("expected capacity to be freed for a new queued task")
	}
}

func TestDeferredSessionProcessorClearsLaneMappingAfterTaskRun(t *testing.T) {
	processor := newDeferredSessionProcessor(1, 2, nil)
	if processor == nil {
		t.Fatal("expected deferred processor")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	processor.Start(ctx)

	lane := deferredSessionLane{sessionID: 8, streamID: 11}
	done := make(chan struct{})
	if !processor.Enqueue(lane, func(context.Context) {
		close(done)
	}) {
		t.Fatal("expected task to enqueue")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for deferred task to run")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		processor.mu.Lock()
		_, exists := processor.laneWorker[lane]
		processor.mu.Unlock()
		if !exists {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("expected laneWorker mapping to be cleared after task completion")
}

func TestDeferredSessionProcessorRemoveLaneCancelsRunningTask(t *testing.T) {
	processor := newDeferredSessionProcessor(1, 2, nil)
	if processor == nil {
		t.Fatal("expected deferred processor")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	processor.Start(ctx)

	lane := deferredSessionLane{sessionID: 9, streamID: 12}
	started := make(chan struct{})
	cancelled := make(chan struct{})
	if !processor.Enqueue(lane, func(taskCtx context.Context) {
		close(started)
		<-taskCtx.Done()
		close(cancelled)
	}) {
		t.Fatal("expected task to enqueue")
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for deferred task to start")
	}

	processor.RemoveLane(lane)

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("expected running deferred task to be cancelled")
	}
}

func TestDeferredSessionProcessorFinalizeLaneKeepsRunningTaskAlive(t *testing.T) {
	processor := newDeferredSessionProcessor(1, 2, nil)
	if processor == nil {
		t.Fatal("expected deferred processor")
	}

	lane := deferredSessionLane{sessionID: 10, streamID: 13}
	taskCtx, cancel := processor.beginTaskContext(context.Background(), lane)
	defer cancel()

	processor.mu.Lock()
	processor.laneWorker[lane] = 0
	processor.mu.Unlock()

	processor.FinalizeLane(lane)

	select {
	case <-taskCtx.Done():
		t.Fatal("expected finalized running task context to remain active")
	default:
	}

	processor.mu.Lock()
	_, laneExists := processor.laneWorker[lane]
	_, runningExists := processor.running[lane]
	processor.mu.Unlock()
	if laneExists {
		t.Fatal("expected finalized lane mapping to be removed")
	}
	if !runningExists {
		t.Fatal("expected running task cancel func to remain until finish")
	}
}

func TestDeferredSessionProcessorSessionCapRejectsExcessSingleSessionLoad(t *testing.T) {
	processor := newDeferredSessionProcessor(2, 32, nil)
	if processor == nil {
		t.Fatal("expected deferred processor")
	}

	sessionID := uint8(11)
	for i := 0; i < int(processor.sessionCap()); i++ {
		lane := deferredSessionLane{sessionID: sessionID, streamID: uint16(i + 1)}
		if !processor.Enqueue(lane, func(context.Context) {}) {
			t.Fatalf("expected enqueue %d to fit under session cap", i+1)
		}
	}

	if processor.Enqueue(deferredSessionLane{sessionID: sessionID, streamID: 999}, func(context.Context) {}) {
		t.Fatal("expected enqueue beyond session cap to be rejected")
	}
}

func TestDeferredSessionProcessorSessionCapScalesForDNSSizedQueue(t *testing.T) {
	processor := newDeferredSessionProcessor(1, 256, nil)
	if processor == nil {
		t.Fatal("expected deferred processor")
	}

	if got := processor.sessionCap(); got != 128 {
		t.Fatalf("expected dns-sized deferred session cap of 128, got %d", got)
	}
}

func TestDeferredSessionProcessorFastFailsWhenWorkerQueueIsFull(t *testing.T) {
	processor := newDeferredSessionProcessor(1, 1, nil)
	if processor == nil {
		t.Fatal("expected deferred processor")
	}

	firstLane := deferredSessionLane{sessionID: 12, streamID: 1}
	secondLane := deferredSessionLane{sessionID: 13, streamID: 2}

	if !processor.Enqueue(firstLane, func(context.Context) {}) {
		t.Fatal("expected first task to enqueue")
	}

	if processor.Enqueue(secondLane, func(context.Context) {}) {
		t.Fatal("expected second task to fail fast when worker queue is full")
	}

	if pending := processor.workers[0].pending.Load(); pending != 1 {
		t.Fatalf("expected pending count to stay at 1 after fast-fail, got %d", pending)
	}

	if got := processor.sessionPending[secondLane.sessionID]; got != 0 {
		t.Fatalf("expected rejected session pending count to be rolled back, got %d", got)
	}
}

func TestDeferredSessionProcessorCompactKeepsCancelledMarkerForInFlightTask(t *testing.T) {
	processor := newDeferredSessionProcessor(1, 4, nil)
	if processor == nil {
		t.Fatal("expected deferred processor")
	}

	lane := deferredSessionLane{sessionID: 14, streamID: 3}
	duplicate := deferredSessionTask{lane: lane, run: func(context.Context) {}}

	processor.mu.Lock()
	processor.cancelled[lane] = struct{}{}
	processor.laneWorker[lane] = 0
	processor.sessionPending[lane.sessionID] = 1
	processor.workers[0].pending.Store(1)
	processor.workers[0].jobs <- duplicate
	dropped := processor.compactWorkerLocked(0, func(candidate deferredSessionLane) bool {
		return candidate == lane
	})
	_, stillCancelled := processor.cancelled[lane]
	processor.mu.Unlock()

	if dropped != 1 {
		t.Fatalf("expected one duplicate task to be compacted, got %d", dropped)
	}
	if !stillCancelled {
		t.Fatal("expected cancelled marker to survive queue compaction for in-flight task safety")
	}

	taskCtx, cancel := processor.beginTaskContext(context.Background(), lane)
	defer cancel()
	select {
	case <-taskCtx.Done():
	default:
		t.Fatal("expected beginTaskContext to see preserved cancelled marker")
	}
}

func TestInvalidSessionDropLogConfigRecentlyClosedIgnoresReceivedCookie(t *testing.T) {
	key1, interval1 := invalidSessionDropLogConfig("recently closed session", 3, 10, 241, 0)
	key2, interval2 := invalidSessionDropLogConfig("recently closed session", 3, 99, 241, 0)
	if key1 != key2 {
		t.Fatalf("expected recently closed session log key to ignore received cookie, got %q vs %q", key1, key2)
	}
	if interval1 != 3*time.Second || interval2 != 3*time.Second {
		t.Fatalf("expected recently closed session interval to be 3s, got %s and %s", interval1, interval2)
	}
}

func TestProcessDeferredSOCKS5SynSkipsDialForRecentlyClosedStream(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	record := newTestSessionRecord(25)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record
	record.noteStreamClosed(10, time.Now(), false)

	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		t.Fatalf("unexpected dial for recently closed stream")
		return nil, nil
	}

	packet := packetWithSession(Enums.PACKET_SOCKS5_SYN, record.ID, record.Cookie, 10)
	packet.Payload = []byte{0x01, 127, 0, 0, 1, 0x01, 0xBB}
	packet.TotalFragments = 1

	s.processDeferredSOCKS5Syn(context.Background(), packet)
}

func TestProcessDeferredSOCKS5SynClearsQueuedDuplicatesAfterConnectFailure(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	record := newTestSessionRecord(42)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("dial failed")
	}

	lane := deferredSessionLane{sessionID: record.ID, streamID: 15}
	if !s.deferredConnectSession.Enqueue(lane, func(context.Context) {}) {
		t.Fatal("expected queued duplicate lane")
	}

	packet := packetWithSession(Enums.PACKET_SOCKS5_SYN, record.ID, record.Cookie, 15)
	packet.Payload = []byte{0x01, 127, 0, 0, 1, 0x01, 0xBB}
	packet.TotalFragments = 1

	s.processDeferredSOCKS5Syn(context.Background(), packet)

	if pending := s.deferredConnectSession.workers[0].pending.Load(); pending != 0 {
		t.Fatalf("expected SOCKS5 failure to clear queued duplicates, got pending=%d", pending)
	}
	if queued := len(s.deferredConnectSession.workers[0].jobs); queued != 0 {
		t.Fatalf("expected SOCKS5 failure to compact worker queue, got queued=%d", queued)
	}
}

func TestProcessDeferredStreamSynQueuesConnectFailOnDialError(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(23)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("dial failed")
	}

	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, 3)
	s.processDeferredStreamSyn(context.Background(), packet)

	stream, ok := record.getStream(3)
	if !ok || stream == nil {
		t.Fatal("expected stream to exist after failed STREAM_SYN processing")
	}
	defer stream.Abort("test cleanup")

	key := Enums.PacketIdentityKey(stream.ID, Enums.PACKET_STREAM_CONNECT_FAIL, packet.SequenceNum, 0)
	pkt, ok := stream.TXQueue.Get(key)
	if !ok || pkt == nil {
		t.Fatal("expected STREAM_CONNECT_FAIL to be queued after dial failure")
	}
	if pkt.TTL != s.cfg.StreamFailurePacketTTL() {
		t.Fatalf("unexpected STREAM_CONNECT_FAIL TTL: got=%s want=%s", pkt.TTL, s.cfg.StreamFailurePacketTTL())
	}
}

func TestProcessDeferredStreamSynIgnoresLateDialCompletionAfterSessionClose(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(23)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record

	conn := &testNetConn{}
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		record.markClosed()
		return conn, nil
	}

	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, 30)
	s.processDeferredStreamSyn(context.Background(), packet)

	record.StreamsMu.RLock()
	stream := record.Streams[30]
	record.StreamsMu.RUnlock()
	if stream == nil {
		t.Fatal("expected stream to exist after STREAM_SYN processing")
	}

	stream.mu.RLock()
	connected := stream.Connected
	upstream := stream.UpstreamConn
	stream.mu.RUnlock()

	if connected {
		t.Fatal("expected late dial completion not to mark stream connected")
	}
	if upstream != nil {
		t.Fatal("expected no upstream connection to be attached after session close")
	}
	if !conn.closed {
		t.Fatal("expected late dialed connection to be closed")
	}

	key := Enums.PacketIdentityKey(stream.ID, Enums.PACKET_STREAM_CONNECTED, packet.SequenceNum, 0)
	if pkt, ok := stream.TXQueue.Get(key); ok || pkt != nil {
		t.Fatal("expected no STREAM_CONNECTED packet after late dial completion")
	}
}

func TestProcessDeferredStreamSynTimesOutBlockedDial(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	s.socksConnectTimeout = 50 * time.Millisecond
	record := newTestSessionRecord(26)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		time.Sleep(500 * time.Millisecond)
		return nil, nil
	}

	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, 4)
	startedAt := time.Now()
	s.processDeferredStreamSyn(context.Background(), packet)
	if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
		t.Fatalf("expected blocked STREAM_SYN dial to time out quickly, took %s", elapsed)
	}

	stream, ok := record.getStream(4)
	if !ok || stream == nil {
		t.Fatal("expected stream to exist after timed out STREAM_SYN processing")
	}
	defer stream.Abort("test cleanup")

	key := Enums.PacketIdentityKey(stream.ID, Enums.PACKET_STREAM_CONNECT_FAIL, packet.SequenceNum, 0)
	if pkt, ok := stream.TXQueue.Get(key); !ok || pkt == nil {
		t.Fatal("expected STREAM_CONNECT_FAIL to be queued after hard timeout")
	}
}

func TestProcessDeferredStreamSynClearsQueuedDuplicatesAfterDialFailure(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(41)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("dial failed")
	}

	lane := deferredSessionLane{sessionID: record.ID, streamID: 12}
	if !s.deferredConnectSession.Enqueue(lane, func(context.Context) {}) {
		t.Fatal("expected queued duplicate lane")
	}

	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, 12)
	s.processDeferredStreamSyn(context.Background(), packet)

	if pending := s.deferredConnectSession.workers[0].pending.Load(); pending != 0 {
		t.Fatalf("expected dial failure to clear queued duplicates, got pending=%d", pending)
	}
	if queued := len(s.deferredConnectSession.workers[0].jobs); queued != 0 {
		t.Fatalf("expected dial failure to compact worker queue, got queued=%d", queued)
	}
}

func TestDeferredConnectAttemptTimeoutClampsExcessiveConfig(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	s.socksConnectTimeout = 120 * time.Second
	if got := s.deferredConnectAttemptTimeout(); got != maxDeferredConnectAttemptTimeout {
		t.Fatalf("unexpected deferred connect timeout clamp: got=%s want=%s", got, maxDeferredConnectAttemptTimeout)
	}
}

func TestDialTCPTargetContextPassesEffectiveDeadlineToDialer(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	s.socksConnectTimeout = 120 * time.Second

	var received time.Duration
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		received = timeout
		return nil, context.DeadlineExceeded
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _ = s.dialTCPTargetContext(ctx, "149.154.167.92:443")
	if received <= 0 || received > 200*time.Millisecond {
		t.Fatalf("expected effective dial timeout to follow context deadline, got %s", received)
	}
}

func TestProcessDeferredSOCKS5SynTimesOutBlockedDial(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	s.socksConnectTimeout = 50 * time.Millisecond
	record := newTestSessionRecord(27)
	record.DownloadCompression = 0
	s.sessions.byID[record.ID] = record
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		time.Sleep(500 * time.Millisecond)
		return nil, nil
	}

	packet := packetWithSession(Enums.PACKET_SOCKS5_SYN, record.ID, record.Cookie, 5)
	packet.Payload = []byte{0x01, 149, 154, 167, 92, 0x01, 0xBB}
	packet.TotalFragments = 1
	startedAt := time.Now()
	s.processDeferredSOCKS5Syn(context.Background(), packet)
	if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
		t.Fatalf("expected blocked SOCKS5 dial to time out quickly, took %s", elapsed)
	}

	stream, ok := record.getStream(5)
	if !ok || stream == nil {
		t.Fatal("expected stream to exist after timed out SOCKS5 processing")
	}
	defer stream.Abort("test cleanup")

	key := Enums.PacketIdentityKey(stream.ID, Enums.PACKET_SOCKS5_TTL_EXPIRED, packet.SequenceNum, 0)
	if pkt, ok := stream.TXQueue.Get(key); !ok || pkt == nil {
		t.Fatal("expected SOCKS5 TTL_EXPIRED to be queued after hard timeout")
	}
}

func TestHandlePostSessionPacketRejectsMismatchedSynProtocol(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	record := newTestSessionRecord(24)
	s.sessions.byID[record.ID] = record

	packet := packetWithSession(Enums.PACKET_STREAM_SYN, record.ID, record.Cookie, 4)
	if handled := s.handlePostSessionPacket(packet, viewForRecord(record)); handled {
		t.Fatal("expected TCP STREAM_SYN to be rejected when server protocol is SOCKS5")
	}
	if _, ok := record.getStream(4); ok {
		t.Fatal("expected mismatched STREAM_SYN to be ignored without creating stream")
	}
}

func TestValidateSOCKSTargetHostRejectsLocalAndPrivateTargets(t *testing.T) {
	cases := []string{
		"127.0.0.1",
		"localhost",
		"api.localhost",
		"10.0.0.5",
		"172.16.1.9",
		"192.168.1.10",
		"169.254.1.1",
		"100.64.0.1",
		"198.18.0.1",
		"::1",
		"fe80::1",
		"fc00::1",
	}

	for _, host := range cases {
		if err := validateSOCKSTargetHost(host); err == nil {
			t.Fatalf("expected host %q to be rejected", host)
		}
	}
}

func TestValidateSOCKSTargetHostAllowsPublicTargets(t *testing.T) {
	cases := []string{
		"149.154.167.255",
		"8.8.8.8",
		"example.com",
	}

	for _, host := range cases {
		if err := validateSOCKSTargetHost(host); err != nil {
			t.Fatalf("expected host %q to be allowed, got %v", host, err)
		}
	}
}

func TestDialSOCKSStreamTargetRejectsBlockedTargetBeforeDial(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	s.useExternalSOCKS5 = true
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		t.Fatalf("unexpected dial attempt to %s", address)
		return nil, nil
	}

	if _, err := s.dialSOCKSStreamTarget("127.0.0.1", 80, []byte{0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50}); err == nil {
		t.Fatal("expected blocked target error")
	}
}

func TestDialSOCKSStreamTargetBypassesExternalProxyForTCPModeConnects(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	s.useExternalSOCKS5 = true
	s.externalSOCKS5Address = "203.0.113.10:1080"

	var gotNetwork string
	var gotAddress string
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		gotNetwork = network
		gotAddress = address
		return &testNetConn{}, nil
	}

	conn, err := s.dialTCPTargetContext(context.Background(), net.JoinHostPort(s.cfg.ForwardIP, strconv.Itoa(s.cfg.ForwardPort)))
	if err != nil {
		t.Fatalf("unexpected direct dial error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected direct TCP dial connection")
	}

	if gotNetwork != "tcp" {
		t.Fatalf("unexpected network: got=%q want=%q", gotNetwork, "tcp")
	}
	wantAddress := net.JoinHostPort(s.cfg.ForwardIP, strconv.Itoa(s.cfg.ForwardPort))
	if gotAddress != wantAddress {
		t.Fatalf("unexpected dial address: got=%q want=%q", gotAddress, wantAddress)
	}
	if gotAddress == s.externalSOCKS5Address {
		t.Fatal("expected TCP mode connect path to bypass external SOCKS5 address")
	}
}

func TestDialSOCKSStreamTargetUsesExternalProxyWhenEnabled(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	s.useExternalSOCKS5 = true
	s.externalSOCKS5Address = "203.0.113.10:1080"

	conn := &scriptedSOCKS5Conn{
		readBufs: [][]byte{
			{0x05, 0x00},                 // greeting reply: no-auth
			{0x05, 0x00, 0x00, 0x01},     // connect reply header
			{203, 0, 113, 1, 0x04, 0x38}, // bound addr + port
		},
	}

	var gotNetwork string
	var gotAddress string
	s.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		gotNetwork = network
		gotAddress = address
		return conn, nil
	}

	targetPayload := []byte{0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb}
	upstream, err := s.dialSOCKSStreamTargetContext(context.Background(), "example.com", 443, targetPayload)
	if err != nil {
		t.Fatalf("unexpected external SOCKS5 dial error: %v", err)
	}
	if upstream != conn {
		t.Fatal("expected external SOCKS5 path to return the proxy-backed connection")
	}
	if gotNetwork != "tcp" {
		t.Fatalf("unexpected network: got=%q want=%q", gotNetwork, "tcp")
	}
	if gotAddress != s.externalSOCKS5Address {
		t.Fatalf("unexpected external proxy dial address: got=%q want=%q", gotAddress, s.externalSOCKS5Address)
	}
	if len(conn.writes) != 2 {
		t.Fatalf("expected greeting and connect request writes, got %d writes", len(conn.writes))
	}
	if got := conn.writes[0]; len(got) != 3 || got[0] != 0x05 || got[1] != 0x01 || got[2] != 0x00 {
		t.Fatalf("unexpected greeting bytes: %v", got)
	}
	if got := conn.writes[1]; len(got) != 3+len(targetPayload) || got[0] != 0x05 || got[1] != 0x01 || got[2] != 0x00 {
		t.Fatalf("unexpected connect request header: %v", got)
	}
	if got := conn.writes[1][3:]; !equalBytes(got, targetPayload) {
		t.Fatalf("unexpected target payload forwarded to external proxy: got=%v want=%v", got, targetPayload)
	}
	if conn.deadlineActive {
		t.Fatal("expected SOCKS5 path to clear connection deadline after successful handshake")
	}
}

func TestMapSOCKSConnectErrorMapsBlockedTargetToRulesetDenied(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	if got := s.mapSOCKSConnectError(&blockedSOCKSTargetError{host: "127.0.0.1"}); got != Enums.PACKET_SOCKS5_RULESET_DENIED {
		t.Fatalf("unexpected packet type: got=%d want=%d", got, Enums.PACKET_SOCKS5_RULESET_DENIED)
	}
}

func packetWithSession(packetType uint8, sessionID uint8, cookie uint8, streamID uint16) VpnProto.Packet {
	return VpnProto.Packet{
		SessionID:      sessionID,
		SessionCookie:  cookie,
		PacketType:     packetType,
		StreamID:       streamID,
		HasStreamID:    true,
		SequenceNum:    1,
		HasSequenceNum: true,
	}
}

func viewForRecord(record *sessionRecord) *sessionRuntimeView {
	if record == nil {
		return nil
	}
	view := record.runtimeView()
	return &view
}

func equalBytes(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
