// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"stormdns-go/internal/config"
	dnsCache "stormdns-go/internal/dnscache"
	domainMatcher "stormdns-go/internal/domainmatcher"
	fragmentStore "stormdns-go/internal/fragmentstore"
	"stormdns-go/internal/logger"
	"stormdns-go/internal/security"
)

const (
	mtuProbeModeRaw     = 0
	mtuProbeModeBase64  = 1
	mtuProbeCodeLength  = 4
	mtuProbeMetaLength  = mtuProbeCodeLength + 2
	mtuProbeUpMinSize   = 1 + mtuProbeCodeLength
	mtuProbeDownMinSize = mtuProbeUpMinSize + 2
	mtuProbeMinDownSize = 30
	mtuProbeMaxDownSize = 4096
	sessionAcceptSize   = 7
)

var preSessionPacketTypes = buildPreSessionPacketTypes()

type Server struct {
	cfg                      config.ServerConfig
	log                      *logger.Logger
	codec                    *security.Codec
	domainMatcher            *domainMatcher.Matcher
	sessions                 *sessionStore
	deferredDNSSession       *deferredSessionProcessor
	deferredConnectSession   *deferredSessionProcessor
	invalidCookieTracker     *invalidCookieTracker
	dnsCache                 *dnsCache.Store
	dnsResolveInflight       *dnsResolveInflightManager
	dnsUpstreamServers       []string
	dnsUpstreamBufferPool    sync.Pool
	dnsFragments             *fragmentStore.Store[dnsFragmentKey]
	socks5Fragments          *fragmentStore.Store[socks5FragmentKey]
	dnsFragmentTimeout       time.Duration
	resolveDNSQueryFn        func([]byte) ([]byte, error)
	dialStreamUpstreamFn     func(string, string, time.Duration) (net.Conn, error)
	uploadCompressionMask    uint8
	downloadCompressionMask  uint8
	dropLogIntervalNanos     int64
	invalidCookieWindow      time.Duration
	invalidCookieWindowNanos int64
	invalidCookieThreshold   int
	socksConnectTimeout      time.Duration
	useExternalSOCKS5        bool
	externalSOCKS5Address    string
	externalSOCKS5Auth       bool
	externalSOCKS5User       []byte
	externalSOCKS5Pass       []byte
	streamOutboundTTL        time.Duration
	streamOutboundMaxRetry   int
	mtuProbePayloadPool      sync.Pool
	packetPool               sync.Pool
	deferredInflightMu       sync.Mutex
	deferredInflight         map[uint64]struct{}
	immediateConnectedLog    throttledLogState
	invalidSessionDropLog    throttledLogState
	droppedPackets           atomic.Uint64
	lastDropLogUnix          atomic.Int64
	deferredDroppedPackets   atomic.Uint64
	lastDeferredDropLogUnix  atomic.Int64
	pongNonce                atomic.Uint32
	invalidDropMode          atomic.Uint32

	// Observability counters (Phase 8). Incremented by the corresponding
	// hardening paths so operators can observe how often each guard fires
	// without having to grep logs. Read via Stats(). The stream-cap
	// rejection counter lives on sessionStore (where the cap is enforced)
	// and the fragment-conflict counter lives on each fragmentStore
	// instance; both are surfaced through Stats().
	dnsResponseOversize     atomic.Uint64
	fragmentInvalidHeader   atomic.Uint64
	upstreamPanicsRecovered atomic.Uint64
	cleanupPanicsRecovered  atomic.Uint64
}

// Stats is a point-in-time snapshot of operational counters maintained by the
// server. The values are monotonically non-decreasing for the lifetime of the
// process (counters are never reset). Stats() is safe to call from any
// goroutine.
type Stats struct {
	DroppedPackets          uint64
	DeferredDroppedPackets  uint64
	StreamCapRejections     uint64
	DNSResponseOversize     uint64
	FragmentConflictDrops   uint64
	FragmentInvalidHeader   uint64
	UpstreamPanicsRecovered uint64
	CleanupPanicsRecovered  uint64
}

// Stats returns a consistent snapshot of the server's observability counters.
func (s *Server) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	var fragmentConflicts uint64
	if s.dnsFragments != nil {
		fragmentConflicts += s.dnsFragments.ConflictCount()
	}
	if s.socks5Fragments != nil {
		fragmentConflicts += s.socks5Fragments.ConflictCount()
	}
	return Stats{
		DroppedPackets:          s.droppedPackets.Load(),
		DeferredDroppedPackets:  s.deferredDroppedPackets.Load(),
		StreamCapRejections:     s.sessions.streamCapRejectionsCount(),
		DNSResponseOversize:     s.dnsResponseOversize.Load(),
		FragmentConflictDrops:   fragmentConflicts,
		FragmentInvalidHeader:   s.fragmentInvalidHeader.Load(),
		UpstreamPanicsRecovered: s.upstreamPanicsRecovered.Load(),
		CleanupPanicsRecovered:  s.cleanupPanicsRecovered.Load(),
	}
}

type request struct {
	buf  []byte
	size int
	addr *net.UDPAddr
}

type postSessionValidation struct {
	record   *sessionRuntimeView
	response []byte
	ok       bool
}

func New(cfg config.ServerConfig, log *logger.Logger, codec *security.Codec) *Server {
	invalidCookieWindow := cfg.InvalidCookieWindow()
	if invalidCookieWindow <= 0 {
		invalidCookieWindow = 2 * time.Second
	}
	dnsFragmentTimeout := cfg.DNSFragmentAssemblyTimeout()
	if dnsFragmentTimeout <= 0 {
		dnsFragmentTimeout = 5 * time.Minute
	}
	dropLogInterval := cfg.DropLogInterval()
	if dropLogInterval <= 0 {
		dropLogInterval = 2 * time.Second
	}
	socksConnectTimeout := cfg.SOCKSConnectTimeout()
	if socksConnectTimeout <= 0 {
		socksConnectTimeout = 8 * time.Second
	}
	dnsDeferredWorkers, connectDeferredWorkers, dnsDeferredQueue, connectDeferredQueue := splitDeferredSessionPools(cfg.DeferredSessionWorkers, cfg.DeferredSessionQueueLimit)
	return &Server{
		cfg:                    cfg,
		log:                    log,
		codec:                  codec,
		domainMatcher:          domainMatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		sessions:               newSessionStore(cfg.SessionOrphanQueueInitialCap, cfg.StreamQueueInitialCapacity, cfg.SessionInitReuseTTL(), cfg.RecentlyClosedStreamTTL(), cfg.RecentlyClosedStreamCap, cfg.MaxStreamsPerSession),
		deferredDNSSession:     newDeferredSessionProcessor(dnsDeferredWorkers, dnsDeferredQueue, log),
		deferredConnectSession: newDeferredSessionProcessor(connectDeferredWorkers, connectDeferredQueue, log),
		invalidCookieTracker:   newInvalidCookieTracker(),
		dnsCache: dnsCache.New(
			cfg.DNSCacheMaxRecords,
			time.Duration(cfg.DNSCacheTTLSeconds*float64(time.Second)),
			dnsFragmentTimeout,
		),
		dnsResolveInflight: newDNSResolveInflightManager(dnsFragmentTimeout),
		dnsUpstreamServers: append([]string(nil), cfg.DNSUpstreamServers...),
		dnsFragments:       fragmentStore.New[dnsFragmentKey](cfg.DNSFragmentStoreCapacity),
		socks5Fragments:    fragmentStore.New[socks5FragmentKey](cfg.SOCKS5FragmentStoreCapacity),
		dnsFragmentTimeout: dnsFragmentTimeout,
		dnsUpstreamBufferPool: sync.Pool{
			New: func() any {
				return make([]byte, 65535)
			},
		},
		dialStreamUpstreamFn: func(network string, address string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, address, timeout)
		},
		uploadCompressionMask:    buildCompressionMask(cfg.SupportedUploadCompressionTypes),
		downloadCompressionMask:  buildCompressionMask(cfg.SupportedDownloadCompressionTypes),
		dropLogIntervalNanos:     dropLogInterval.Nanoseconds(),
		invalidCookieWindow:      invalidCookieWindow,
		invalidCookieWindowNanos: invalidCookieWindow.Nanoseconds(),
		invalidCookieThreshold:   cfg.InvalidCookieErrorThreshold,
		socksConnectTimeout:      socksConnectTimeout,
		useExternalSOCKS5:        cfg.UseExternalSOCKS5,
		externalSOCKS5Address:    net.JoinHostPort(cfg.ForwardIP, strconv.Itoa(cfg.ForwardPort)),
		externalSOCKS5Auth:       cfg.SOCKS5Auth,
		externalSOCKS5User:       []byte(cfg.SOCKS5User),
		externalSOCKS5Pass:       []byte(cfg.SOCKS5Pass),
		mtuProbePayloadPool: sync.Pool{
			New: func() any {
				return make([]byte, mtuProbeMaxDownSize)
			},
		},
		deferredInflight: make(map[uint64]struct{}, 128),
		packetPool: sync.Pool{
			New: func() any {
				return make([]byte, cfg.MaxPacketSize)
			},
		},
	}
}

type throttledLogState struct {
	mu   sync.Mutex
	last map[string]int64
}

const (
	throttledLogSoftCap = 1024
	throttledLogHardCap = 1536
)

func (s *throttledLogState) allow(key string, now time.Time, interval time.Duration) bool {
	if s == nil {
		return true
	}
	if interval <= 0 {
		interval = time.Second
	}

	nowUnixNano := now.UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.last == nil {
		s.last = make(map[string]int64, 64)
	}

	if len(s.last) > 0 {
		s.pruneLocked(nowUnixNano, interval)
	}

	last := s.last[key]

	if last != 0 && nowUnixNano-last < interval.Nanoseconds() {
		return false
	}

	s.last[key] = nowUnixNano
	return true
}

func (s *throttledLogState) pruneLocked(nowUnixNano int64, interval time.Duration) {
	if s == nil || len(s.last) == 0 {
		return
	}

	cutoff := nowUnixNano - interval.Nanoseconds()
	for key, last := range s.last {
		if last == 0 || last <= cutoff {
			delete(s.last, key)
		}
	}

	if len(s.last) <= throttledLogHardCap {
		return
	}

	target := throttledLogSoftCap
	for len(s.last) > target {
		oldestKey := ""
		oldestSeen := nowUnixNano
		for key, last := range s.last {
			if oldestKey == "" || last < oldestSeen {
				oldestKey = key
				oldestSeen = last
			}
		}
		if oldestKey == "" {
			return
		}
		delete(s.last, oldestKey)
	}
}

func splitDeferredSessionPools(totalWorkers int, totalQueue int) (dnsWorkers int, connectWorkers int, dnsQueue int, connectQueue int) {
	if totalWorkers <= 0 {
		totalWorkers = 1
	}
	if totalQueue <= 0 {
		totalQueue = 256
	}

	// DNS queries use a dedicated lightweight pool so connect-heavy work keeps
	// the full user-configured deferred capacity.
	dnsWorkers = 1
	connectWorkers = totalWorkers

	connectQueue = totalQueue
	dnsQueue = min(max(totalQueue/4, 64), 256)

	return dnsWorkers, connectWorkers, dnsQueue, connectQueue
}

func (s *Server) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(s.cfg.UDPHost),
		Port: s.cfg.UDPPort,
	})

	if err != nil {
		return err
	}

	defer conn.Close()

	s.configureSocketBuffers(conn)

	s.log.Infof(
		"\U0001F4E1 <green>UDP Listener Ready, Addr: <cyan>%s</cyan>, Readers: <cyan>%d</cyan>, Workers: <cyan>%d</cyan>, Queue: <cyan>%d</cyan></green>",
		s.cfg.Address(),
		s.cfg.UDPReaders,
		s.cfg.DNSRequestWorkers,
		s.cfg.MaxConcurrentRequests,
	)

	reqCh := make(chan request, s.cfg.MaxConcurrentRequests)
	var workerWG sync.WaitGroup
	cleanupDone := make(chan struct{})

	go func() {
		defer close(cleanupDone)
		s.sessionCleanupLoop(runCtx)
	}()

	s.deferredDNSSession.Start(runCtx)
	s.deferredConnectSession.Start(runCtx)
	s.startDNSWorkers(runCtx, conn, reqCh, &workerWG)

	go func() {
		<-runCtx.Done()
		_ = conn.Close()
	}()

	readErrCh := make(chan error, s.cfg.UDPReaders)
	var readerWG sync.WaitGroup
	s.startReaders(runCtx, conn, reqCh, readErrCh, &readerWG)

	readerWG.Wait()
	close(reqCh)
	workerWG.Wait()
	cancel()
	<-cleanupDone

	if ctx.Err() != nil {
		return ctx.Err()
	}

	select {
	case err := <-readErrCh:
		return err
	default:
		return nil
	}
}
