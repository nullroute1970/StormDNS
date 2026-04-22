// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"stormdns-go/internal/arq"
	"stormdns-go/internal/config"
	DnsParser "stormdns-go/internal/dnsparser"
	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/logger"
	"stormdns-go/internal/security"
)

func createTestClient(t *testing.T) *Client {
	cfg := config.ClientConfig{
		LogLevel: "debug",
		Domains:  []string{"example.com"},
		Resolvers: []config.ResolverAddress{
			{IP: "8.8.8.8", Port: 53},
		},
		TXChannelSize:        10,
		RXChannelSize:        10,
		RX_TX_Workers:        1,
		TunnelProcessWorkers: 1,
		DataEncryptionMethod: 1,
		EncryptionKey:        "testkey",
	}
	log := logger.New("TestLogger", "debug")
	codec, err := security.NewCodec(1, "testkey")
	if err != nil {
		t.Fatalf("failed to create codec: %v", err)
	}

	return New(cfg, log, codec)
}

func TestResetRuntimeBindings(t *testing.T) {
	c := createTestClient(t)
	c.last_stream_id = 10
	c.sessionID = 1
	c.sessionReady = true
	c.socksRateLimit.RecordFailure("10.0.0.1")
	oldLimiter := c.socksRateLimit

	c.resetRuntimeBindings(true)

	if c.last_stream_id != 0 {
		t.Errorf("expected last_stream_id 0, got %d", c.last_stream_id)
	}

	if c.sessionID != 0 {
		t.Errorf("expected sessionID 0, got %d", c.sessionID)
	}

	if c.sessionReady {
		t.Error("expected sessionReady false")
	}

	if c.socksRateLimit == nil {
		t.Fatal("expected socksRateLimit to be reinitialized")
	}

	if c.socksRateLimit != oldLimiter {
		t.Fatal("expected socksRateLimit instance to be reset in place")
	}

	if c.socksRateLimit.IsBlocked("10.0.0.1") {
		t.Fatal("expected reset to clear prior SOCKS rate-limit state")
	}
}

func TestClearTxSignal(t *testing.T) {
	c := createTestClient(t)
	c.txSignal = make(chan struct{}, 5)
	c.txSignal <- struct{}{}
	c.txSignal <- struct{}{}

	c.clearTxSignal()

	select {
	case <-c.txSignal:
		t.Fatal("txSignal should be empty")
	default:
	}
}

func TestClearTxSpaceSignal(t *testing.T) {
	c := createTestClient(t)
	c.txSpaceSignal = make(chan struct{}, 5)
	c.txSpaceSignal <- struct{}{}
	c.txSpaceSignal <- struct{}{}

	c.clearTxSpaceSignal()

	select {
	case <-c.txSpaceSignal:
		t.Fatal("txSpaceSignal should be empty")
	default:
	}
}

func TestOnRXDropIncrementsCounter(t *testing.T) {
	c := createTestClient(t)
	addr := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}

	c.onRXDrop(addr)

	if got := c.rxDroppedPackets.Load(); got != 1 {
		t.Fatalf("expected rxDroppedPackets=1, got %d", got)
	}
}

func TestTrackResolverSendBoundsResolverPendingGrowth(t *testing.T) {
	c := createTestClient(t)
	base := time.Now()

	c.resolverStatsMu.Lock()
	for i := 0; i < resolverPendingHardCap+32; i++ {
		c.resolverPending[resolverSampleKey{
			resolverAddr: "127.0.0.1:5300",
			dnsID:        uint16(i),
		}] = resolverSample{
			serverKey: "resolver-a",
			sentAt:    base.Add(-time.Minute),
		}
	}
	c.resolverStatsMu.Unlock()

	packet := []byte{0x12, 0x34}
	c.trackResolverSend(packet, "127.0.0.1:5300", "", "resolver-a", base)

	c.resolverStatsMu.RLock()
	pendingCount := len(c.resolverPending)
	_, inserted := c.resolverPending[resolverSampleKey{
		resolverAddr: "127.0.0.1:5300",
		dnsID:        binary.BigEndian.Uint16(packet),
	}]
	c.resolverStatsMu.RUnlock()

	if pendingCount > resolverPendingHardCap {
		t.Fatalf("expected resolverPending to stay bounded, got=%d hardCap=%d", pendingCount, resolverPendingHardCap)
	}
	if !inserted {
		t.Fatal("expected latest resolver sample to remain tracked")
	}
}

func TestDrainQueues(t *testing.T) {
	c := createTestClient(t)
	c.txChannel = make(chan rawOutboundTask, 5)
	c.encodedTXChannel = make(chan encodedOutboundTask, 5)
	c.rxChannel = make(chan asyncReadPacket, 5)

	c.txChannel <- rawOutboundTask{}
	c.encodedTXChannel <- encodedOutboundTask{}
	c.rxChannel <- asyncReadPacket{data: make([]byte, 10)}

	c.drainQueues()

	if len(c.txChannel) != 0 {
		t.Errorf("expected txChannel empty, got %d", len(c.txChannel))
	}
	if len(c.encodedTXChannel) != 0 {
		t.Errorf("expected encodedTXChannel empty, got %d", len(c.encodedTXChannel))
	}
	if len(c.rxChannel) != 0 {
		t.Errorf("expected rxChannel empty, got %d", len(c.rxChannel))
	}
}

func TestRequestSessionRestart(t *testing.T) {
	c := createTestClient(t)
	c.sessionResetSignal = make(chan struct{}, 1)

	c.requestSessionRestart("test reason")
	if !c.runtimeResetPending.Load() {
		t.Error("expected runtimeResetPending true")
	}

	select {
	case <-c.sessionResetSignal:
	default:
		t.Fatal("sessionResetSignal should have received a signal")
	}

	c.clearRuntimeResetRequest()
	if c.runtimeResetPending.Load() {
		t.Error("expected runtimeResetPending false")
	}
}

func TestStopAsyncRuntime(t *testing.T) {
	c := createTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	c.asyncCancel = cancel

	c.asyncWG.Add(1)
	go func() {
		defer c.asyncWG.Done()
		<-ctx.Done()
	}()

	c.StopAsyncRuntime()

	if c.asyncCancel != nil {
		t.Error("expected asyncCancel nil")
	}
}

func TestAsyncStreamCleanupWorker(t *testing.T) {
	c := createTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.streamsMu.Lock()
	stream := &Stream_client{
		StreamID: 1,
	}
	a := arq.NewARQ(1, 1, nil, nil, 1400, nil, arq.Config{
		WindowSize: 300,
		RTO:        1.0,
		MaxRTO:     8.0,
	})
	stream.Stream = a
	c.active_streams[1] = stream
	c.streamsMu.Unlock()

	c.asyncWG.Add(1)
	go c.asyncStreamCleanupWorker(ctx)

	// Wait for a tick
	time.Sleep(1200 * time.Millisecond)

	cancel()
	c.asyncWG.Wait()
}

func TestStartAsyncRuntime(t *testing.T) {
	c := createTestClient(t)
	c.cfg.ListenIP = "127.0.0.1"
	c.cfg.ListenPort = 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := c.StartAsyncRuntime(ctx)
	if err != nil {
		t.Logf("StartAsyncRuntime failed (expected if ports are busy): %v", err)
		return
	}

	if len(c.tunnelConns) != c.tunnelRX_TX_Workers {
		t.Fatalf("expected %d tunnel sockets, got %d", c.tunnelRX_TX_Workers, len(c.tunnelConns))
	}

	if c.asyncCancel == nil {
		t.Error("expected asyncCancel not nil")
	}

	c.StopAsyncRuntime()
}

func TestStartAsyncRuntimeCleansUpOnListenerStartFailure(t *testing.T) {
	c := createTestClient(t)
	c.cfg.ListenIP = ""
	c.cfg.ListenPort = 0

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := c.StartAsyncRuntime(ctx)
	if err == nil {
		t.Fatal("expected StartAsyncRuntime to fail for invalid listener address")
	}
	if c.asyncCancel != nil {
		t.Fatal("expected asyncCancel to be cleared after startup failure")
	}
	if len(c.tunnelConns) != 0 {
		t.Fatal("expected tunnel sockets to be closed after startup failure")
	}
}

func TestStartAsyncRuntimeCollectsResolverTimeoutsEvenWhenHealthFeaturesDisabled(t *testing.T) {
	c := createTestClient(t)
	c.cfg.ListenIP = "127.0.0.1"
	c.cfg.ListenPort = 0
	c.cfg.AutoDisableTimeoutServers = false
	c.cfg.RecheckInactiveServersEnabled = false
	c.initResolverRecheckMeta()

	now := time.Now()
	c.nowFn = func() time.Time {
		return now
	}

	addr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	serverKey := ""
	if len(c.connections) > 0 {
		serverKey = c.connections[0].Key
	}
	key := resolverSampleKey{
		resolverAddr: addr.String(),
		dnsID:        0x1337,
	}

	c.resolverStatsMu.Lock()
	c.resolverPending[key] = resolverSample{
		serverKey: serverKey,
		sentAt:    now.Add(-10 * time.Second),
	}
	c.resolverStatsMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.StartAsyncRuntime(ctx); err != nil {
		t.Fatalf("StartAsyncRuntime returned error: %v", err)
	}
	defer c.StopAsyncRuntime()

	waitForResolverHealthCondition(t, 3*time.Second, func() bool {
		c.resolverStatsMu.RLock()
		sample, ok := c.resolverPending[key]
		c.resolverStatsMu.RUnlock()
		return ok && sample.timedOut
	}, "expected resolver timeout sample to be collected even without auto-disable/recheck enabled")
}

func TestHandleInboundPacketTreatsMissingTXTAsResolverSuccess(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()
	addr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}

	query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", 16, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	response, err := DnsParser.BuildEmptyNoErrorResponse(query)
	if err != nil {
		t.Fatalf("BuildEmptyNoErrorResponse returned error: %v", err)
	}

	dnsID := binary.BigEndian.Uint16(response[:2])
	c.resolverPending[resolverSampleKey{
		resolverAddr: addr.String(),
		dnsID:        dnsID,
	}] = resolverSample{
		serverKey: "a",
		sentAt:    time.Now().Add(-200 * time.Millisecond),
	}

	c.handleInboundPacket(response, addr, "")

	if len(c.resolverPending) != 0 {
		t.Fatalf("expected resolverPending to be cleared after empty DNS success, got=%d", len(c.resolverPending))
	}
}

func TestHandleInboundPacketTreatsServerFailureWithoutTXTAsResolverFailure(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()
	addr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}

	query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	response, err := DnsParser.BuildServerFailureResponse(query)
	if err != nil {
		t.Fatalf("BuildServerFailureResponse returned error: %v", err)
	}

	dnsID := binary.BigEndian.Uint16(response[:2])
	c.resolverPending[resolverSampleKey{
		resolverAddr: addr.String(),
		dnsID:        dnsID,
	}] = resolverSample{
		serverKey: "a",
		sentAt:    time.Now().Add(-200 * time.Millisecond),
	}

	c.handleInboundPacket(response, addr, "")

	if len(c.resolverPending) != 0 {
		t.Fatalf("expected resolverPending to be cleared after SERVFAIL response, got=%d", len(c.resolverPending))
	}

	c.resolverHealthMu.Lock()
	state := c.resolverHealth["a"]
	c.resolverHealthMu.Unlock()
	if state == nil {
		t.Fatal("expected resolver health state to exist")
	}
	if len(state.Events) != 1 {
		t.Fatalf("expected one failure health event after SERVFAIL response, got=%d", len(state.Events))
	}
}
