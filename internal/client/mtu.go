// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the StormDNS client.
// This file (mtu.go) handles MTU discovery and probing.
// ==============================================================================
package client

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	DnsParser "stormdns-go/internal/dnsparser"
	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/logger"
	VpnProto "stormdns-go/internal/vpnproto"
)

var ErrNoValidConnections = errors.New("no valid connections after mtu testing")

const (
	mtuProbeCodeLength  = 4
	mtuProbeRawResponse = 0
	mtuProbeBase64Reply = 1
	defaultMTUMinFloor  = 10
	defaultUploadMaxCap = 512
)

var (
	maxUploadProbePacketType = VpnProto.MaxHeaderPacketType()
	mtuDownResponseReserve   = func() int {
		reserve := VpnProto.MaxHeaderRawSize() - VpnProto.HeaderRawSize(Enums.PACKET_MTU_DOWN_RES)
		if reserve < 0 {
			return 0
		}
		return reserve
	}()
)

type mtuRejectReason uint8

const (
	mtuRejectNone mtuRejectReason = iota
	mtuRejectUpload
	mtuRejectDownload
)

type mtuProbeOptions struct {
	IsRetry bool
	Quiet   bool
}

type mtuConnectionProbeResult struct {
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	ResolveTime   time.Duration
}

type mtuScanCounters struct {
	completed      atomic.Int32
	valid          atomic.Int32
	rejectUpload   atomic.Int32
	rejectDownload atomic.Int32
}

// RunInitialMTUTests tests all connections before the client starts.
func (c *Client) RunInitialMTUTests(ctx context.Context) error {
	if len(c.connections) == 0 {
		return ErrNoValidConnections
	}
	return c.runFullMTUTests(ctx)
}

// runFullMTUTests performs the original fully-sequential blocking MTU scan and
// blocks until every connection has been probed before returning.
func (c *Client) runFullMTUTests(ctx context.Context) error {
	uploadCaps := c.precomputeUploadCaps()
	workerCount := min(max(1, c.cfg.MTUTestParallelism), len(c.connections))
	c.logMTUStart(workerCount)
	for idx := range c.connections {
		c.prepareConnectionMTUScanState(&c.connections[idx])
	}

	counters := &mtuScanCounters{}
	c.runAllMTUProbeWorkers(ctx, uploadCaps, workerCount, counters, nil)

	c.balancer.RefreshValidConnections()
	validConns, minUpload, minDownload, minUploadChars := summarizeValidMTUConnections(c.connections)
	if len(validConns) == 0 {
		if c.log != nil {
			c.log.Errorf("<red>No valid connections found after MTU testing!</red>")
		}
		return ErrNoValidConnections
	}

	c.applySyncedMTUState(minUpload, minDownload, minUploadChars)
	c.initResolverRecheckMeta()
	c.logMTUCompletion(validConns)
	return nil
}

// runAllMTUProbeWorkers dispatches MTU probe jobs to workers. When onValid is
// non-nil it is called (with a copy of the connection) after each successful
// probe, from within the worker goroutine.
func (c *Client) runAllMTUProbeWorkers(ctx context.Context, uploadCaps map[string]int, workerCount int, counters *mtuScanCounters, onValid func(Connection)) {
	total := len(c.connections)
	if workerCount <= 1 {
		for idx := range c.connections {
			if ctx.Err() != nil {
				return
			}
			conn := &c.connections[idx]
			c.runConnectionMTUTest(ctx, conn, idx+1, total, uploadCaps[conn.Domain], counters)
			if onValid != nil && conn.IsValid {
				onValid(*conn)
			}
		}
		return
	}

	jobs := make(chan int, total)
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				conn := &c.connections[idx]
				c.runConnectionMTUTest(ctx, conn, idx+1, total, uploadCaps[conn.Domain], counters)
				if onValid != nil && conn.IsValid {
					onValid(*conn)
				}
			}
		}()
	}
	for idx := range c.connections {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- idx:
		}
	}
	close(jobs)
	wg.Wait()
}

// prepareConnectionMTUScanState resets a connection's MTU state before a probe
// run. IsValid is intentionally set to false: probeConnectionMTU sets it to
// false on every rejection/error path, and runConnectionMTUTest explicitly sets
// it to true only on a clean pass. Starting at false ensures the early-start
// tracker's onValid callback (which checks conn.IsValid after the probe) is
// only triggered for genuinely successful probes.
func (c *Client) prepareConnectionMTUScanState(conn *Connection) {
	if conn == nil {
		return
	}
	conn.IsValid = false
	conn.UploadMTUBytes = 0
	conn.UploadMTUChars = 0
	conn.DownloadMTUBytes = 0
	conn.MTUResolveTime = 0
}

func (c *Client) runConnectionMTUTest(ctx context.Context, conn *Connection, serverID int, total int, maxUploadPayload int, counters *mtuScanCounters) {
	if conn == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			conn.IsValid = false
			if c.log != nil {
				c.log.Errorf(
					"💥 <red>MTU Probe Worker Panic: <cyan>%v</cyan> (Resolver: <cyan>%s</cyan>)</red>",
					recovered,
					conn.ResolverLabel,
				)
			}
			if counters != nil {
				completed := counters.completed.Add(1)
				rejectedNow := counters.rejectUpload.Add(1) + counters.rejectDownload.Load()
				if c.log != nil && c.log.Enabled(logger.LevelWarn) {
					c.log.Warnf(
						"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>PANIC</yellow> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
						completed,
						total,
						conn.Domain,
						conn.ResolverLabel,
						counters.valid.Load(),
						rejectedNow,
					)
				}
			}
		}
	}()

	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf(
			"<green>Testing Resolver: <cyan>%s</cyan> for Domain: <cyan>%s</cyan> (<cyan>%d / %d</cyan>)</green>",
			conn.ResolverLabel,
			conn.Domain,
			serverID,
			total,
		)
	}

	result, reason := c.probeConnectionMTU(ctx, conn, maxUploadPayload)
	if counters == nil {
		return
	}

	switch reason {
	case mtuRejectUpload:
		completed := counters.completed.Add(1)
		rejectedNow := counters.rejectUpload.Add(1) + counters.rejectDownload.Load()
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>UPLOAD_MTU</yellow> | value=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				result.UploadBytes,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		return
	case mtuRejectDownload:
		completed := counters.completed.Add(1)
		rejectedNow := counters.rejectUpload.Load() + counters.rejectDownload.Add(1)
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>DOWNLOAD_MTU</yellow> | value=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				result.DownloadBytes,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		return
	}

	conn.IsValid = true
	conn.UploadMTUBytes = result.UploadBytes
	conn.UploadMTUChars = result.UploadChars
	conn.DownloadMTUBytes = result.DownloadBytes
	conn.MTUResolveTime = result.ResolveTime

	completed := counters.completed.Add(1)
	validNow := counters.valid.Add(1)
	rejectedNow := counters.rejectUpload.Load() + counters.rejectDownload.Load()
	if c.log != nil && c.log.Enabled(logger.LevelInfo) {
		c.log.Infof(
			"<green>✅ Accepted (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | upload=<cyan>%d</cyan> | download=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></green>",
			completed,
			total,
			conn.Domain,
			conn.ResolverLabel,
			conn.UploadMTUBytes,
			conn.DownloadMTUBytes,
			validNow,
			rejectedNow,
		)
	}
	c.appendResolverCacheEntry(conn)
}

func (c *Client) probeConnectionMTU(ctx context.Context, conn *Connection, maxUploadPayload int) (mtuConnectionProbeResult, mtuRejectReason) {
	var result mtuConnectionProbeResult

	probeTransport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		conn.IsValid = false
		return result, mtuRejectUpload
	}
	defer probeTransport.conn.Close()

	upOK, upBytes, upChars, upRTT, err := c.testUploadMTU(ctx, conn, probeTransport, maxUploadPayload)
	if err != nil || !upOK {
		conn.IsValid = false
		result.UploadBytes = upBytes
		result.UploadChars = upChars
		return result, mtuRejectUpload
	}
	result.UploadBytes = upBytes
	result.UploadChars = upChars

	downOK, downBytes, downRTT, err := c.testDownloadMTU(ctx, conn, probeTransport, upBytes)
	if err != nil || !downOK {
		conn.IsValid = false
		result.DownloadBytes = downBytes
		return result, mtuRejectDownload
	}
	result.DownloadBytes = downBytes
	result.ResolveTime = averageMTUProbeRTT(upRTT, downRTT)
	return result, mtuRejectNone
}

func (c *Client) precomputeUploadCaps() map[string]int {
	caps := make(map[string]int, len(c.cfg.Domains))
	for _, domain := range c.cfg.Domains {
		if _, exists := caps[domain]; exists {
			continue
		}
		caps[domain] = c.maxUploadMTUPayload(domain)
	}
	return caps
}

func (c *Client) testUploadMTU(ctx context.Context, conn *Connection, probeTransport *udpQueryTransport, maxPayload int) (bool, int, int, time.Duration, error) {
	if maxPayload <= 0 {
		return false, 0, 0, 0, nil
	}
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf("<cyan>[MTU]</cyan> Testing upload MTU for %s", conn.Domain)
	}

	maxLimit := c.cfg.MaxUploadMTU
	if maxLimit <= 0 || maxLimit > defaultUploadMaxCap {
		maxLimit = defaultUploadMaxCap
	}
	if maxPayload > maxLimit {
		maxPayload = maxLimit
	}

	best, bestRTT := c.binarySearchMTU(
		ctx,
		"upload mtu",
		c.cfg.MinUploadMTU,
		maxPayload,
		func(candidate int, isRetry bool) (bool, time.Duration, error) {
			return c.sendUploadMTUProbe(ctx, conn, probeTransport, candidate, mtuProbeOptions{
				IsRetry: isRetry,
			})
		},
	)
	if best < max(defaultMTUMinFloor, c.cfg.MinUploadMTU) {
		return false, 0, 0, 0, nil
	}
	return true, best, c.encodedCharsForPayload(best), bestRTT, nil
}

func (c *Client) testDownloadMTU(ctx context.Context, conn *Connection, probeTransport *udpQueryTransport, uploadMTU int) (bool, int, time.Duration, error) {
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf("<cyan>[MTU]</cyan> Testing download MTU for %s", conn.Domain)
	}
	best, bestRTT := c.binarySearchMTU(
		ctx,
		"download mtu",
		c.cfg.MinDownloadMTU,
		c.cfg.MaxDownloadMTU,
		func(candidate int, isRetry bool) (bool, time.Duration, error) {
			return c.sendDownloadMTUProbe(ctx, conn, probeTransport, candidate, uploadMTU, mtuProbeOptions{
				IsRetry: isRetry,
			})
		},
	)
	if best < max(defaultMTUMinFloor, c.cfg.MinDownloadMTU) {
		return false, 0, 0, nil
	}
	return true, best, bestRTT, nil
}

func (c *Client) binarySearchMTU(ctx context.Context, label string, minValue, maxValue int, testFn func(int, bool) (bool, time.Duration, error)) (int, time.Duration) {
	if maxValue <= 0 {
		return 0, 0
	}

	low := max(minValue, defaultMTUMinFloor)
	high := maxValue
	if high < low {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(
				"<cyan>[MTU]</cyan> Invalid %s range: low=%d, high=%d. Skipping.",
				label,
				low,
				high,
			)
		}
		return 0, 0
	}
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf(
			"<cyan>[MTU]</cyan> Starting binary search for %s. Range: %d-%d",
			label,
			low,
			high,
		)
	}

	check := func(value int) (bool, time.Duration) {
		ok := false
		var rtt time.Duration
		for attempt := 0; attempt < c.mtuTestRetries; attempt++ {
			if err := ctx.Err(); err != nil {
				return false, 0
			}
			passed, measuredRTT, err := testFn(value, attempt > 0)
			if err != nil && c.log != nil && c.log.Enabled(logger.LevelDebug) {
				c.log.Debugf("MTU test callable raised for %d: %v", value, err)
			}
			if err == nil && passed {
				ok = true
				rtt = measuredRTT
				break
			}
		}
		return ok, rtt
	}

	if ok, rtt := check(high); ok {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf("<cyan>[MTU]</cyan> Max MTU %d is valid.", high)
		}
		return high, rtt
	}
	if low == high {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(
				"<cyan>[MTU]</cyan> Only one MTU candidate (%d) existed and it failed.",
				low,
			)
		}
		return 0, 0
	}
	best := low
	bestRTT := time.Duration(0)
	if ok, rtt := check(low); !ok {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(
				"<cyan>[MTU]</cyan> Both boundary MTUs failed (min=%d, max=%d). Skipping middle checks.",
				low,
				high,
			)
		}
		return 0, 0
	} else {
		bestRTT = rtt
	}

	left := low + 1
	right := high - 1
	for left <= right {
		if err := ctx.Err(); err != nil {
			return 0, 0
		}
		mid := (left + right) / 2
		if ok, rtt := check(mid); ok {
			best = mid
			bestRTT = rtt
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf("<cyan>[MTU]</cyan> Binary search result: %d", best)
	}
	return best, bestRTT
}

func (c *Client) sendUploadMTUProbe(ctx context.Context, conn *Connection, probeTransport *udpQueryTransport, mtuSize int, options mtuProbeOptions) (bool, time.Duration, error) {
	if mtuSize < 1+mtuProbeCodeLength {
		return false, 0, nil
	}
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	c.logMTUProbe(
		options.IsRetry,
		options.Quiet,
		"<magenta>[MTU Probe]</magenta> Testing Upload MTU: <yellow>%d</yellow> bytes via <cyan>%s</cyan>",
		mtuSize,
		conn.ResolverLabel,
	)

	payload, code, useBase64, err := c.buildMTUProbePayload(mtuSize)
	if err != nil {
		return false, 0, err
	}

	query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_UP_REQ, payload)
	if err != nil {
		return false, 0, nil
	}

	startedAt := time.Now()
	response, err := c.exchangeUDPQuery(probeTransport, query, c.mtuTestTimeout)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	rtt := time.Since(startedAt)

	packet, err := DnsParser.ExtractVPNResponse(response, useBase64)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if len(packet.Payload) != 6 {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if binary.BigEndian.Uint32(packet.Payload[:mtuProbeCodeLength]) != code {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	ok := int(binary.BigEndian.Uint16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2])) == mtuSize
	if ok {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>🟢 Upload test passed: Upload MTU <green>%d</green> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	} else {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	}
	return ok, rtt, nil
}

func (c *Client) sendDownloadMTUProbe(ctx context.Context, conn *Connection, probeTransport *udpQueryTransport, mtuSize int, uploadMTU int, options mtuProbeOptions) (bool, time.Duration, error) {
	if mtuSize < defaultMTUMinFloor {
		return false, 0, nil
	}
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	c.logMTUProbe(
		options.IsRetry,
		options.Quiet,
		"<magenta>[MTU Probe]</magenta> Testing Download MTU: <yellow>%d</yellow> bytes via <cyan>%s</cyan>",
		mtuSize,
		conn.ResolverLabel,
	)

	effectiveDownloadSize := effectiveDownloadMTUProbeSize(mtuSize)
	if effectiveDownloadSize < defaultMTUMinFloor {
		return false, 0, nil
	}
	requestLen := max(1+mtuProbeCodeLength+2, uploadMTU)
	payload, code, useBase64, err := c.buildMTUProbePayload(requestLen)
	if err != nil {
		return false, 0, err
	}
	binary.BigEndian.PutUint16(payload[1+mtuProbeCodeLength:1+mtuProbeCodeLength+2], uint16(effectiveDownloadSize))

	query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_DOWN_REQ, payload)
	if err != nil {
		return false, 0, nil
	}

	startedAt := time.Now()
	response, err := c.exchangeUDPQuery(probeTransport, query, c.mtuTestTimeout)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (No Response)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	rtt := time.Since(startedAt)

	packet, err := DnsParser.ExtractVPNResponse(response, useBase64)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Unexpected Packet Type)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}

	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Unexpected Packet Type)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if len(packet.Payload) != effectiveDownloadSize {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if len(packet.Payload) < 1+mtuProbeCodeLength+1 {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if binary.BigEndian.Uint32(packet.Payload[:mtuProbeCodeLength]) != code {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	ok := int(binary.BigEndian.Uint16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2])) == effectiveDownloadSize
	if ok {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>🟢 Download test passed: Download MTU <green>%d</green> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	} else {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	}
	return ok, rtt, nil
}

func (c *Client) buildMTUProbeQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQueryRaw(domain, VpnProto.BuildOptions{
		SessionID:      255,
		PacketType:     packetType,
		StreamID:       1,
		SequenceNum:    1,
		FragmentID:     0,
		TotalFragments: 1,
		Payload:        payload,
	})
}

func (c *Client) maxUploadMTUPayload(domain string) int {
	maxChars := DnsParser.CalculateMaxEncodedQNameChars(domain)
	if maxChars <= 0 {
		return 0
	}

	low := 0
	high := maxChars
	best := 0
	for low <= high {
		mid := (low + high) / 2
		if c.canBuildUploadPayload(domain, mid) {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return best
}

func (c *Client) canBuildUploadPayload(domain string, payloadLen int) bool {
	if payloadLen <= 0 {
		return true
	}

	buf := c.udpBufferPool.Get().([]byte)
	defer c.udpBufferPool.Put(buf)

	if payloadLen > len(buf) {
		return false
	}

	payload := buf[:payloadLen]
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:      255,
		PacketType:     Enums.PACKET_MTU_UP_REQ,
		SessionCookie:  255,
		StreamID:       0xFFFF,
		SequenceNum:    0xFFFF,
		FragmentID:     0xFF,
		TotalFragments: 0xFF,
		Payload:        payload,
	}, c.codec)
	if err != nil {
		return false
	}

	_, err = DnsParser.BuildTunnelQuestionName(domain, encoded)
	return err == nil
}

func (c *Client) buildMTUProbePayload(length int) ([]byte, uint32, bool, error) {
	if length <= 0 {
		return nil, 0, false, nil
	}

	payload := make([]byte, length)
	useBase64 := c != nil && c.cfg.BaseEncodeData
	payload[0] = mtuProbeRawResponse
	if useBase64 {
		payload[0] = mtuProbeBase64Reply
	}

	code := c.mtuProbeCounter.Add(1)
	binary.BigEndian.PutUint32(payload[1:1+mtuProbeCodeLength], code)

	return payload, code, useBase64, nil
}

func averageMTUProbeRTT(values ...time.Duration) time.Duration {
	var sum time.Duration
	count := 0
	for _, value := range values {
		if value <= 0 {
			continue
		}
		sum += value
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / time.Duration(count)
}

func summarizeValidMTUConnections(connections []Connection) (validConns []Connection, minUpload int, minDownload int, minUploadChars int) {
	validConns = make([]Connection, 0, len(connections))
	for _, conn := range connections {
		if !conn.IsValid {
			continue
		}
		validConns = append(validConns, conn)

		if conn.UploadMTUBytes > 0 && (minUpload == 0 || conn.UploadMTUBytes < minUpload) {
			minUpload = conn.UploadMTUBytes
		}
		if conn.DownloadMTUBytes > 0 && (minDownload == 0 || conn.DownloadMTUBytes < minDownload) {
			minDownload = conn.DownloadMTUBytes
		}
		if conn.UploadMTUChars > 0 && (minUploadChars == 0 || conn.UploadMTUChars < minUploadChars) {
			minUploadChars = conn.UploadMTUChars
		}
	}
	return validConns, minUpload, minDownload, minUploadChars
}

// applyPreknownMTUsFromLog applies MTU values that were pre-filled from log files,
// skipping the full MTU scan. It writes the pre-known entries to the MTU success
// file and the resolver cache log so future sessions can reuse them.
// Returns ErrNoValidConnections when no connections have pre-filled MTU values.
func (c *Client) applyPreknownMTUsFromLog(ctx context.Context) error {
	if len(c.connections) == 0 {
		return ErrNoValidConnections
	}

	validConns, minUpload, minDownload, minUploadChars := summarizeValidMTUConnections(c.connections)
	if len(validConns) == 0 {
		return ErrNoValidConnections
	}

	// Persist the pre-known working resolvers to the resolver cache log.
	for i := range c.connections {
		conn := &c.connections[i]
		if conn.IsValid {
			c.appendResolverCacheEntry(conn)
		}
	}

	c.balancer.RefreshValidConnections()
	c.applySyncedMTUState(minUpload, minDownload, minUploadChars)
	c.initResolverRecheckMeta()

	if c.log != nil {
		c.log.Infof(
			"<green>⚡ Using <cyan>%d</cyan> resolvers from log files (skipped full MTU scan)</green>",
			len(validConns),
		)
	}
	c.logMTUCompletion(validConns)
	return nil
}

func (c *Client) encodedCharsForPacketPayload(packetType uint8, payloadLen int) int {
	if payloadLen <= 0 {
		return 0
	}

	buf := c.udpBufferPool.Get().([]byte)
	defer c.udpBufferPool.Put(buf)

	if payloadLen > len(buf) {
		return 0
	}

	payload := buf[:payloadLen]
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:       255,
		PacketType:      packetType,
		SessionCookie:   255,
		StreamID:        0xFFFF,
		SequenceNum:     0xFFFF,
		FragmentID:      0xFF,
		TotalFragments:  0xFF,
		CompressionType: 0xFF,
		Payload:         payload,
	}, c.codec)

	if err != nil {
		return 0
	}

	return len(encoded)
}

func (c *Client) encodedCharsForPayload(payloadLen int) int {
	return c.encodedCharsForPacketPayload(maxUploadProbePacketType, payloadLen)
}

func effectiveDownloadMTUProbeSize(downloadMTU int) int {
	if downloadMTU <= 0 {
		return 0
	}

	return downloadMTU + mtuDownResponseReserve
}

func computeSafeUploadMTU(uploadMTU int, cryptoOverhead int) int {
	if uploadMTU <= 0 {
		return 0
	}

	safe := uploadMTU - cryptoOverhead
	if safe < 64 {
		safe = 64
	}

	if safe > uploadMTU {
		return uploadMTU
	}

	return safe
}

func mtuCryptoOverhead(method int) int {
	switch method {
	case 2:
		return 16
	case 3, 4, 5:
		return 28
	default:
		return 0
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
