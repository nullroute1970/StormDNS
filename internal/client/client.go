// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic and initialization for the StormDNS client.
// This file (client.go) defines the main Client struct and bootstrapping process.
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"stormdns-go/internal/arq"
	"stormdns-go/internal/config"
	dnsCache "stormdns-go/internal/dnscache"
	Enums "stormdns-go/internal/enums"
	fragmentStore "stormdns-go/internal/fragmentstore"
	"stormdns-go/internal/logger"
	"stormdns-go/internal/mlq"
	"stormdns-go/internal/security"
	VpnProto "stormdns-go/internal/vpnproto"
)

const (
	EDnsSafeUDPSize = 4096
)

type Client struct {
	cfg      config.ClientConfig
	log      *logger.Logger
	codec    *security.Codec
	balancer *Balancer

	connections         []Connection
	connectionsByKey    map[string]int
	successMTUChecks    bool
	udpBufferPool       sync.Pool
	resolverConnsMu     sync.Mutex
	resolverConns       map[string]chan pooledUDPConn
	resolverAddrMu      sync.RWMutex
	resolverAddrCache   map[string]*net.UDPAddr
	resolverStatsMu     sync.RWMutex
	resolverPending     map[resolverSampleKey]resolverSample
	resolverHealthMu    sync.RWMutex
	resolverHealth      map[string]*resolverHealthState
	resolverRecheck     map[string]resolverRecheckState
	runtimeDisabled     map[string]resolverDisabledState
	resolverRecheckSem  chan struct{}
	nowFn               func() time.Time
	recheckConnectionFn func(conn *Connection) bool

	// MTU States
	syncedUploadMTU                       int
	syncedDownloadMTU                     int
	syncedUploadChars                     int
	safeUploadMTU                         int
	maxPackedBlocks                       int
	uploadCompression                     uint8
	downloadCompression                   uint8
	mtuCryptoOverhead                     int
	mtuProbeCounter                       atomic.Uint32
	mtuTestRetries                        int
	mtuTestTimeout                        time.Duration
	streamResolverFailoverResendThreshold int
	streamResolverFailoverCooldown        time.Duration

	// Resolver cache log (per-session structured log of working resolvers + MTU values)
	resolverCacheLogFile *os.File
	resolverCacheLogMu   sync.Mutex

	// Log-based startup state
	connectionsHavePreknownMTU bool
	logBasedMTUVerify          bool

	// Session States
	sessionID           uint8
	sessionCookie       uint8
	responseMode        uint8
	sessionReady        bool
	initStateMu         sync.Mutex
	sessionInitReady    bool
	sessionInitBase64   bool
	sessionInitPayload  []byte
	sessionInitVerify   [4]byte
	sessionInitCursor   int
	sessionInitBusyUnix atomic.Int64
	sessionResetPending atomic.Bool
	runtimeResetPending atomic.Bool
	sessionResetSignal  chan struct{}
	rxDroppedPackets    atomic.Uint64
	lastRXDropLogUnix   atomic.Int64

	// Traffic byte counters (per-session, reset on resetRuntimeBindings)
	txTotalBytes atomic.Uint64
	rxTotalBytes atomic.Uint64

	// Async Runtime Workers & Channels
	asyncWG              sync.WaitGroup
	asyncCancel          context.CancelFunc
	tunnelConns          []*net.UDPConn
	txChannel            chan rawOutboundTask
	encodedTXChannel     chan encodedOutboundTask
	rxChannel            chan asyncReadPacket
	tunnelRX_TX_Workers  int
	tunnelProcessWorkers int
	tunnelPacketTimeout  time.Duration

	// Local Proxy Daemons
	tcpListener *TCPListener
	dnsListener *DNSListener

	// Stream Management
	streamsMu             sync.RWMutex
	active_streams        map[uint16]*Stream_client
	last_stream_id        uint16
	streamSetVersion      atomic.Uint64
	orphanQueue           *mlq.MultiLevelQueue[VpnProto.Packet]
	recentlyClosedMu      sync.Mutex
	recentlyClosedStreams map[uint16]time.Time

	// Signals to wake up dispatcher.
	txSignal      chan struct{}
	txSpaceSignal chan struct{}

	// Autonomous Ping Manager
	pingManager *PingManager

	// DNS Management
	localDNSCache          *dnsCache.Store
	dnsResponses           *fragmentStore.Store[dnsFragmentKey]
	localDNSCachePersist   bool
	localDNSCachePath      string
	localDNSCacheFlushTick time.Duration
	localDNSCacheLoadOnce  sync.Once
	localDNSCacheFlushOnce sync.Once

	// SOCKS5 brute-force rate limiter
	socksRateLimit *socksRateLimiter
}

// clientStreamTXPacket represents a queued packet pending transmission or retransmission.
type clientStreamTXPacket struct {
	PacketType      uint8
	SequenceNum     uint16
	FragmentID      uint8
	TotalFragments  uint8
	CompressionType uint8
	Payload         []byte
	CreatedAt       time.Time
	TTL             time.Duration
	LastSentAt      time.Time
	RetryDelay      time.Duration
	RetryAt         time.Time
	RetryCount      int
	Scheduled       bool
}

// rawOutboundTask holds payload and stream information for parallel packet encoding.
type rawOutboundTask struct {
	packetType uint8
	payload    []byte
	opts       VpnProto.BuildOptions
	wasPacked  bool
	item       *clientStreamTXPacket
	selected   *Stream_client
	conns      []Connection
}

type encodedOutboundDatagram struct {
	addr      *net.UDPAddr
	serverKey string
	packet    []byte
}

type encodedOutboundTask struct {
	wasPacked bool
	item      *clientStreamTXPacket
	selected  *Stream_client
	frames    []encodedOutboundDatagram
}

// Connection represents a unique domain-resolver pair with its associated metadata and MTU states.
type Connection struct {
	Domain           string
	Resolver         string
	ResolverPort     int
	ResolverLabel    string
	Key              string
	IsValid          bool
	UploadMTUBytes   int
	UploadMTUChars   int
	DownloadMTUBytes int
	MTUResolveTime   time.Duration
}

// Bootstrap initializes a new Client by loading configuration, setting up logging,
// and preparing the connection map.
func Bootstrap(configPath string, overrides config.ClientConfigOverrides) (*Client, error) {
	cfg, err := config.LoadClientConfigWithOverrides(configPath, overrides)
	if err != nil {
		return nil, err
	}

	log := logger.New("StormDNS Client", cfg.LogLevel)

	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("client codec setup failed: %w", err)
	}

	c := New(cfg, log, codec)
	if err := c.BuildConnectionMap(); err != nil {
		if c.log != nil {
			c.log.Errorf("<red>%v</red>", err)
		}
		return nil, err
	}

	if cacheLogPath := cfg.ResolvedResolverCacheLogPath(); cacheLogPath != "" {
		c.openResolverCacheLog(cacheLogPath)
	}

	return c, nil
}

// BootstrapFromLogs initializes a new Client using working resolvers recovered from
// previous session logs, skipping the full MTU scan when LOG_BASED_MTU_VERIFY is false.
// When entries is empty it falls back to the normal Bootstrap path.
func BootstrapFromLogs(configPath string, entries []ResolverCacheEntry, overrides config.ClientConfigOverrides) (*Client, error) {
	if len(entries) == 0 {
		return Bootstrap(configPath, overrides)
	}

	// Build a deduplicated resolver list from the log entries.
	seen := make(map[string]struct{}, len(entries))
	resolvers := make([]config.ResolverAddress, 0, len(entries))
	for _, e := range entries {
		epKey := e.IP + "|" + strconv.Itoa(e.Port)
		if _, exists := seen[epKey]; exists {
			continue
		}
		seen[epKey] = struct{}{}
		resolvers = append(resolvers, config.ResolverAddress{IP: e.IP, Port: e.Port})
	}
	overrides.Resolvers = resolvers

	cfg, err := config.LoadClientConfigWithOverrides(configPath, overrides)
	if err != nil {
		return nil, err
	}

	log := logger.New("StormDNS Client", cfg.LogLevel)

	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("client codec setup failed: %w", err)
	}

	c := New(cfg, log, codec)
	c.connectionsHavePreknownMTU = true
	c.logBasedMTUVerify = cfg.LogBasedMTUVerify

	if err := c.BuildConnectionMap(); err != nil {
		if c.log != nil {
			c.log.Errorf("<red>%v</red>", err)
		}
		return nil, err
	}

	// Pre-fill MTU values from log entries into the connection map.
	mtuLookup := buildResolverCacheMTULookup(entries)
	for i := range c.connections {
		conn := &c.connections[i]
		key := makeConnectionKey(conn.Resolver, conn.ResolverPort, conn.Domain)
		if e, ok := mtuLookup[key]; ok && e.UploadMTU > 0 && e.DownloadMTU > 0 {
			conn.IsValid = true
			conn.UploadMTUBytes = e.UploadMTU
			conn.DownloadMTUBytes = e.DownloadMTU
			conn.UploadMTUChars = c.encodedCharsForPayload(e.UploadMTU)
		}
	}

	if cacheLogPath := cfg.ResolvedResolverCacheLogPath(); cacheLogPath != "" {
		c.openResolverCacheLog(cacheLogPath)
	}

	return c, nil
}

// buildResolverCacheMTULookup builds a connection-key → ResolverCacheEntry map.
// When the same key appears multiple times (different domains), the most recently
// seen entry wins.
func buildResolverCacheMTULookup(entries []ResolverCacheEntry) map[string]ResolverCacheEntry {
	lookup := make(map[string]ResolverCacheEntry, len(entries))
	for _, e := range entries {
		key := makeConnectionKey(e.IP, e.Port, e.Domain)
		if existing, ok := lookup[key]; !ok || e.LastSeen.After(existing.LastSeen) {
			lookup[key] = e
		}
	}
	return lookup
}

func New(cfg config.ClientConfig, log *logger.Logger, codec *security.Codec) *Client {
	var responseMode uint8
	if cfg.BaseEncodeData {
		responseMode = mtuProbeBase64Reply
	}

	c := &Client{
		cfg:                 cfg,
		log:                 log,
		codec:               codec,
		balancer:            NewBalancer(cfg.ResolverBalancingStrategy),
		uploadCompression:   uint8(cfg.UploadCompressionType),
		downloadCompression: uint8(cfg.DownloadCompressionType),
		mtuCryptoOverhead:   mtuCryptoOverhead(cfg.DataEncryptionMethod),
		maxPackedBlocks:     1,
		responseMode:        responseMode,
		connectionsByKey:    make(map[string]int, len(cfg.Domains)*len(cfg.Resolvers)),
		udpBufferPool: sync.Pool{
			New: func() any {
				return make([]byte, RuntimeUDPReadBufferSize)
			},
		},
		resolverConns:                         make(map[string]chan pooledUDPConn),
		resolverAddrCache:                     make(map[string]*net.UDPAddr),
		resolverPending:                       make(map[resolverSampleKey]resolverSample),
		resolverHealth:                        make(map[string]*resolverHealthState),
		resolverRecheck:                       make(map[string]resolverRecheckState),
		runtimeDisabled:                       make(map[string]resolverDisabledState),
		resolverRecheckSem:                    make(chan struct{}, max(1, cfg.RecheckBatchSize)),
		mtuTestRetries:                        cfg.MTUTestRetries,
		mtuTestTimeout:                        time.Duration(cfg.MTUTestTimeout * float64(time.Second)),
		streamResolverFailoverResendThreshold: cfg.StreamResolverFailoverResendThreshold,
		streamResolverFailoverCooldown:        time.Duration(cfg.StreamResolverFailoverCooldownSec * float64(time.Second)),

		// Workers config
		tunnelRX_TX_Workers:   cfg.RX_TX_Workers,
		tunnelProcessWorkers:  cfg.TunnelProcessWorkers,
		tunnelPacketTimeout:   time.Duration(cfg.TunnelPacketTimeoutSec * float64(time.Second)),
		txChannel:             make(chan rawOutboundTask, cfg.TXChannelSize),
		encodedTXChannel:      make(chan encodedOutboundTask, max(24, cfg.RX_TX_Workers*24)),
		rxChannel:             make(chan asyncReadPacket, cfg.RXChannelSize),
		active_streams:        make(map[uint16]*Stream_client),
		recentlyClosedStreams: make(map[uint16]time.Time),
		txSignal:              make(chan struct{}, 1),
		txSpaceSignal:         make(chan struct{}, 1),

		// DNS Management
		localDNSCache: dnsCache.New(
			cfg.LocalDNSCacheMaxRecords,
			time.Duration(cfg.LocalDNSCacheTTLSeconds)*time.Second,
			time.Duration(cfg.LocalDNSPendingTimeoutSec)*time.Second,
		),
		dnsResponses:           fragmentStore.New[dnsFragmentKey](cfg.DNSResponseFragmentStoreCap),
		localDNSCachePersist:   cfg.LocalDNSCachePersist,
		localDNSCachePath:      cfg.LocalDNSCachePath(),
		localDNSCacheFlushTick: time.Duration(cfg.LocalDNSCacheFlushSec) * time.Second,
		orphanQueue:            mlq.New[VpnProto.Packet](cfg.OrphanQueueInitialCapacity),
		sessionResetSignal:     make(chan struct{}, 1),
		socksRateLimit:         newSocksRateLimiter(),
	}

	if c.streamResolverFailoverResendThreshold < 1 {
		c.streamResolverFailoverResendThreshold = 1
	}

	if c.streamResolverFailoverCooldown <= 0 {
		c.streamResolverFailoverCooldown = time.Second
	}

	c.pingManager = newPingManager(c)
	return c
}

func (c *Client) nextSessionInitRetryDelay(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}

	delay := c.cfg.SessionInitRetryBase()
	if failures > c.cfg.SessionInitRetryLinearAfter {
		delay += time.Duration(failures-c.cfg.SessionInitRetryLinearAfter) * c.cfg.SessionInitRetryStep()
	}

	if delay > c.cfg.SessionInitRetryMax() {
		return c.cfg.SessionInitRetryMax()
	}

	return delay
}

// Run starts the main execution loop of the client.
func (c *Client) Run(ctx context.Context) error {
	c.successMTUChecks = false
	c.log.Infof("\U0001F504 <cyan>Starting main runtime loop...</cyan>")
	sessionInitRetryDelay := time.Duration(0)
	sessionInitRetryFailures := 0

	defer c.closeResolverCacheLog()

	// Ensure local DNS cache is loaded from file if persistence is enabled
	c.ensureLocalDNSCacheLoaded()

	for {
		select {
		case <-ctx.Done():
			c.notifySessionCloseBurst(time.Second)
			c.StopAsyncRuntime()
			return nil
		default:
			if !c.successMTUChecks {
				var mtuErr error
				if c.connectionsHavePreknownMTU && !c.logBasedMTUVerify {
					mtuErr = c.applyPreknownMTUsFromLog(ctx)
					if mtuErr != nil {
						if c.log != nil {
							c.log.Warnf(
								"<yellow>⚠️ Log-based start failed (%v), falling back to full MTU scan</yellow>",
								mtuErr,
							)
						}
						c.connectionsHavePreknownMTU = false
						for i := range c.connections {
							c.prepareConnectionMTUScanState(&c.connections[i])
						}
						mtuErr = c.RunInitialMTUTests(ctx)
					}
				} else {
					mtuErr = c.RunInitialMTUTests(ctx)
				}

				if mtuErr != nil {
					c.log.Errorf("<red>MTU tests failed: %v</red>", mtuErr)
					c.successMTUChecks = false
					select {
					case <-ctx.Done():
						c.notifySessionCloseBurst(time.Second)
						c.StopAsyncRuntime()
						return nil
					case <-time.After(5 * time.Second):
					}
					continue
				}

				if c.syncedUploadMTU <= 0 || c.syncedDownloadMTU <= 0 {
					c.successMTUChecks = false
					c.log.Errorf("<red>❌ MTU tests failed: Upload MTU: %d, Download MTU: %d</red>", c.syncedUploadMTU, c.syncedDownloadMTU)
					select {
					case <-ctx.Done():
						c.notifySessionCloseBurst(time.Second)
						c.StopAsyncRuntime()
						return nil
					case <-time.After(5 * time.Second):
					}
					continue
				}

				c.successMTUChecks = true
				c.ShortPrintBanner()
			}

			if !c.sessionReady {
				retries := c.cfg.MTUTestRetries
				if retries < 1 {
					retries = 3
				}

				if err := c.InitializeSession(retries); err != nil {
					sessionInitRetryFailures++
					sessionInitRetryDelay = c.nextSessionInitRetryDelay(sessionInitRetryFailures)
					c.log.Errorf("<red>❌ Session initialization failed: %v</red>", err)
					c.log.Warnf("<yellow>Session init retry backoff: %s</yellow>", sessionInitRetryDelay)
					select {
					case <-ctx.Done():
						c.notifySessionCloseBurst(time.Second)
						c.StopAsyncRuntime()
						return nil
					case <-time.After(sessionInitRetryDelay):
					}
					continue
				}
				c.log.Infof("<green>✅ Session Initialized Successfully (ID: <cyan>%d</cyan>)</green>", c.sessionID)

				sessionInitRetryFailures = 0
				sessionInitRetryDelay = 0
				if err := c.StartAsyncRuntime(ctx); err != nil {
					c.log.Errorf("<red>❌ Async Runtime failed to launch: %v</red>", err)
					return err
				}

				c.InitVirtualStream0()

				if c.pingManager != nil {
					c.pingManager.Start(ctx)
				}

				c.ensureLocalDNSCachePersistence(ctx)
			}

			select {
			case <-ctx.Done():
				c.notifySessionCloseBurst(time.Second)
				c.StopAsyncRuntime()
				return nil
			case <-c.sessionResetSignal:
				c.StopAsyncRuntime()
				c.resetSessionState(true)
				c.clearRuntimeResetRequest()
				sessionInitRetryFailures++
				sessionInitRetryDelay = c.nextSessionInitRetryDelay(sessionInitRetryFailures)
				c.log.Warnf("<yellow>Session reset requested, retrying in %s</yellow>", sessionInitRetryDelay)
				select {
				case <-ctx.Done():
					c.notifySessionCloseBurst(time.Second)
					c.StopAsyncRuntime()
					return nil
				case <-time.After(sessionInitRetryDelay):
				}
				continue
			case <-time.After(1 * time.Second):
			}
		}
	}
}

func (c *Client) HandleStreamPacket(packet VpnProto.Packet) error {
	if !packet.HasStreamID {
		return nil
	}

	c.streamsMu.RLock()
	s, ok := c.active_streams[packet.StreamID]
	c.streamsMu.RUnlock()

	if !ok || s == nil {
		return nil
	}

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		if (packet.PacketType == Enums.PACKET_STREAM_DATA ||
			packet.PacketType == Enums.PACKET_STREAM_RESEND ||
			packet.PacketType == Enums.PACKET_STREAM_DATA_NACK) && !c.isRecentlyClosedStream(packet.StreamID, c.now()) {
			c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
		}
		return nil
	}

	switch packet.PacketType {
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		if arqObj.IsClosed() {
			c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
			return nil
		}

		if !s.TerminalSince().IsZero() {
			c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
			return nil
		}

		if !arqObj.ReceiveData(packet.SequenceNum, packet.Payload) {
			return nil
		}

	case Enums.PACKET_STREAM_DATA_NACK:
		if arqObj.IsClosed() || !s.TerminalSince().IsZero() {
			return nil
		}

		if arqObj.HandleDataNack(packet.SequenceNum) {
			c.noteStreamProgress(packet.StreamID)
		}
	case Enums.PACKET_STREAM_CONNECTED:
		return c.handleStreamConnected(packet, s, arqObj)
	case Enums.PACKET_STREAM_CONNECT_FAIL:
		return c.handleStreamConnectFail(packet, s, arqObj)
	case Enums.PACKET_STREAM_CLOSE_READ:
		arqObj.MarkCloseReadReceived()
	case Enums.PACKET_STREAM_CLOSE_WRITE:
		arqObj.MarkCloseWriteReceived()
	case Enums.PACKET_STREAM_RST:
		arqObj.MarkRstReceived()
		arqObj.Close("peer reset received", arq.CloseOptions{Force: true})
		s.MarkTerminal(time.Now())
		if s.StatusValue() != streamStatusCancelled {
			s.SetStatus(streamStatusTimeWait)
		}
	default:
		handledAck := arqObj.HandleAckPacket(packet.PacketType, packet.SequenceNum, packet.FragmentID)
		if handledAck {
			c.noteStreamProgress(packet.StreamID)
		}
		if _, ok := Enums.GetPacketCloseStream(packet.PacketType); handledAck && ok {
			if s.StatusValue() == streamStatusCancelled || arqObj.IsClosed() {
				s.MarkTerminal(time.Now())
				if s.StatusValue() != streamStatusCancelled {
					s.SetStatus(streamStatusTimeWait)
				}
			}
		}
	}

	return nil
}

func (c *Client) HandleSessionReject(packet VpnProto.Packet) error {
	c.requestSessionRestart("session reject received")
	return nil
}

func (c *Client) HandleSessionBusy() error {
	c.requestSessionRestart("session busy received")
	return nil
}

func (c *Client) HandleErrorDrop(packet VpnProto.Packet) error {
	c.requestSessionRestart("error drop received")
	return nil
}

func (c *Client) HandleMTUResponse(packet VpnProto.Packet) error {
	return nil
}
