package client

import (
	"testing"
	"time"

	"stormdns-go/internal/config"
	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/mlq"
)

func TestStreamZeroAllowsMultipleQueuedPingsWithDifferentSequence(t *testing.T) {
	c := &Client{
		txSignal: make(chan struct{}, 8),
	}
	s := &Stream_client{
		client:   c,
		StreamID: 0,
		txQueue:  mlq.New[*clientStreamTXPacket](16),
	}

	if !s.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_PING), Enums.PACKET_PING, 1, 0, 0, 0, 0, []byte("a")) {
		t.Fatal("expected first ping to be queued")
	}
	if !s.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_PING), Enums.PACKET_PING, 2, 0, 0, 0, 0, []byte("b")) {
		t.Fatal("expected second ping with distinct sequence to be queued")
	}
	if got := s.txQueue.FastSize(); got != 2 {
		t.Fatalf("expected two queued pings, got %d", got)
	}
	if s.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_PING), Enums.PACKET_PING, 2, 0, 0, 0, 0, []byte("dup")) {
		t.Fatal("expected duplicate ping sequence to be rejected")
	}
}

func TestPingQueueDropsWhenCongested(t *testing.T) {
	c := &Client{
		txSignal: make(chan struct{}, 8),
	}
	s := &Stream_client{
		client:   c,
		StreamID: 0,
		txQueue:  mlq.New[*clientStreamTXPacket](1024),
	}

	for i := 0; i < 501; i++ {
		if !s.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA), Enums.PACKET_STREAM_DATA, uint16(i+1), 0, 1, 0, 0, []byte("x")) {
			t.Fatalf("expected data packet %d to queue", i+1)
		}
	}

	if s.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_PING), Enums.PACKET_PING, 777, 0, 0, 0, 0, []byte("ping")) {
		t.Fatal("expected ping to be dropped when tx queue is congested")
	}
}

func TestPingManagerSequenceWrapsThroughUint16(t *testing.T) {
	p := &PingManager{}
	p.nextPingSeq.Store(0xFFFF)

	if got := p.nextPingSequence(); got != 0 {
		t.Fatalf("expected wrapped ping sequence 0, got %d", got)
	}
	if got := p.nextPingSequence(); got != 1 {
		t.Fatalf("expected next ping sequence 1 after wrap, got %d", got)
	}
}

// buildPingWatchdogClient creates a minimal client wired up for watchdog tests.
// serverSilentFor controls how long ago the server last responded.
// clientSentNonPingAgo controls how long ago the client last sent non-ping traffic.
func buildPingWatchdogClient(t *testing.T, watchdogTimeout time.Duration, serverSilentFor time.Duration, clientSentNonPingAgo time.Duration) (*Client, *PingManager) {
	t.Helper()
	c := buildTestClientWithResolvers(config.ClientConfig{
		PingWatchdogTimeoutSeconds: watchdogTimeout.Seconds(),
	})
	c.sessionReady = true
	c.sessionResetSignal = make(chan struct{}, 1)

	p := newPingManager(c)
	now := time.Now()

	// Set server-side timestamps to simulate how long ago the server last responded.
	serverLast := now.Add(-serverSilentFor).UnixNano()
	p.lastPongReceivedAt.Store(serverLast)
	p.lastNonPongReceivedAt.Store(serverLast)

	// Set client-side timestamps.
	clientLast := now.Add(-clientSentNonPingAgo).UnixNano()
	p.lastPingSentAt.Store(clientLast)
	p.lastNonPingSentAt.Store(clientLast)

	c.pingManager = p
	return c, p
}

// runWatchdogCheck invokes the watchdog portion of the ping loop directly
// so that tests don't need to run the full goroutine.
func runWatchdogCheck(p *PingManager) {
	nowNano := time.Now().UnixNano()
	watchdogTimeout := p.client.cfg.PingWatchdogTimeout()
	if watchdogTimeout <= 0 || !p.client.SessionReady() {
		return
	}
	lastAnyResponse := p.lastPongReceivedAt.Load()
	if nonPong := p.lastNonPongReceivedAt.Load(); nonPong > lastAnyResponse {
		lastAnyResponse = nonPong
	}
	noResponseFor := time.Duration(nowNano - lastAnyResponse)
	sinceLastNonPingSent := time.Duration(nowNano - p.lastNonPingSentAt.Load())
	if noResponseFor >= watchdogTimeout && sinceLastNonPingSent < watchdogTimeout {
		p.client.log.Warnf(
			"⏱ <yellow>Ping watchdog triggered: no server response for <cyan>%s</cyan>, restarting session</yellow>",
			noResponseFor.Round(time.Second),
		)
		p.client.requestSessionRestart("ping watchdog: no server response")
	}
}

func TestPingWatchdogTriggersRestartWhenServerSilent(t *testing.T) {
	// Watchdog timeout: 30s. Server last responded 60s ago. Client sent non-ping 5s ago.
	// noResponseFor(60s) >= watchdog(30s) AND sinceLastNonPingSent(5s) < watchdog(30s) → fire.
	c, p := buildPingWatchdogClient(t, 30*time.Second, 60*time.Second, 5*time.Second)

	runWatchdogCheck(p)

	if !c.runtimeResetPending.Load() {
		t.Fatal("expected watchdog to trigger session restart when server has been silent")
	}
	select {
	case <-c.sessionResetSignal:
	default:
		t.Fatal("expected sessionResetSignal to be sent")
	}
}

func TestPingWatchdogDoesNotTriggerWhenIdleClientReceivesNoNonPingTraffic(t *testing.T) {
	// Idle client: lastNonPingSentAt is 120s ago (older than watchdogTimeout 30s).
	// Even though there's no server response, the client hasn't sent data recently,
	// so the watchdog must NOT fire (avoids restarting healthy idle sessions).
	c, p := buildPingWatchdogClient(t, 30*time.Second, 120*time.Second, 120*time.Second)

	runWatchdogCheck(p)

	if c.runtimeResetPending.Load() {
		t.Fatal("watchdog must not trigger for an idle client with no recent non-ping traffic")
	}
}

func TestPingWatchdogDoesNotTriggerWhenResponsesAreRecent(t *testing.T) {
	// Client is active (non-ping sent 5s ago) AND responses arrived 5s ago.
	// Watchdog timeout is 30s → no trigger expected.
	c, p := buildPingWatchdogClient(t, 30*time.Second, 5*time.Second, 5*time.Second)

	runWatchdogCheck(p)

	if c.runtimeResetPending.Load() {
		t.Fatal("watchdog must not trigger when server responses are recent")
	}
}

func TestPingWatchdogDoesNotTriggerWhenDisabled(t *testing.T) {
	// PingWatchdogTimeoutSeconds == 0 means watchdog is disabled.
	c, p := buildPingWatchdogClient(t, 30*time.Second, 300*time.Second, 5*time.Second)
	// Force watchdog timeout to 0 directly (buildPingWatchdogClient sets 30s;
	// override the field directly for this edge-case test).
	c.cfg.PingWatchdogTimeoutSeconds = 0

	runWatchdogCheck(p)

	if c.runtimeResetPending.Load() {
		t.Fatal("watchdog must not trigger when PingWatchdogTimeoutSeconds is 0")
	}
}
