// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the StormDNS client.
// This file (mtu_logging.go) handles logging for MTU testing.
// ==============================================================================
package client

import (
	"strings"
	"time"

	"stormdns-go/internal/logger"
)

func (c *Client) mtuDebugEnabled() bool {
	return c != nil && c.log != nil && c.log.Enabled(logger.LevelDebug)
}

func (c *Client) mtuInfoEnabled() bool {
	return c != nil && c.log != nil && c.log.Enabled(logger.LevelInfo)
}

func (c *Client) mtuWarnEnabled() bool {
	return c != nil && c.log != nil && c.log.Enabled(logger.LevelWarn)
}

func (c *Client) logMTUProbe(isRetry bool, background bool, format string, args ...any) {
	if isRetry || background || !c.mtuDebugEnabled() {
		return
	}
	c.log.Debugf(format, args...)
}

func (c *Client) logMTUStart(workerCount int) {
	if !c.mtuInfoEnabled() {
		return
	}
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<yellow>Testing MTU sizes for all resolver-domain pairs (parallel=%d)...</yellow>",
		workerCount,
	)
}

func (c *Client) logMTUCompletion(validConns []Connection) {
	if !c.mtuInfoEnabled() {
		return
	}
	maxFoundUpload := 0
	maxFoundDownload := 0
	for _, conn := range validConns {
		if conn.UploadMTUBytes > maxFoundUpload {
			maxFoundUpload = conn.UploadMTUBytes
		}
		if conn.DownloadMTUBytes > maxFoundDownload {
			maxFoundDownload = conn.DownloadMTUBytes
		}
	}

	c.log.Infof("<green>MTU Testing Completed!</green>")
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof("<cyan>Valid Connections After MTU Testing:</cyan>")
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"%-20s %-15s %-15s %-14s %-30s",
		"Resolver",
		"Upload MTU",
		"Download MTU",
		"Resolve Time",
		"Domain",
	)

	c.log.Infof("%s", strings.Repeat("-", 80))
	for _, conn := range validConns {
		resolveTime := "n/a"
		if conn.MTUResolveTime > 0 {
			resolveTime = formatResolverRTT(conn.MTUResolveTime)
		}

		c.log.Infof(
			"<cyan>%-20s</cyan> <green>%-15d</green> <green>%-15d</green> <yellow>%-14s</yellow> <blue>%-30s</blue>",
			conn.ResolverLabel,
			conn.UploadMTUBytes,
			conn.DownloadMTUBytes,
			resolveTime,
			conn.Domain,
		)
	}
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<blue>Total valid resolvers after MTU testing: <cyan>%d</cyan> of <cyan>%d</cyan></blue>",
		len(validConns),
		len(c.connections),
	)
	uploadDup, downloadDup, uploadSetupDup, downloadSetupDup := c.directionalDuplicationCounts()
	c.log.Infof(
		"<blue>Note:</blue> Duplication counts — upload data: <yellow>%d</yellow>, download ACKs: <yellow>%d</yellow>, upload setup: <yellow>%d</yellow>, download setup/control: <yellow>%d</yellow>.",
		uploadDup,
		downloadDup,
		uploadSetupDup,
		downloadSetupDup,
	)

	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<cyan>[MTU RESULTS]</cyan> Max Upload MTU found: <yellow>%d</yellow> | Max Download MTU found: <yellow>%d</yellow>",
		maxFoundUpload,
		maxFoundDownload,
	)
	c.log.Infof(
		"<cyan>[MTU RESULTS]</cyan> Selected Synced Upload MTU: <yellow>%d</yellow> | Selected Synced Download MTU: <yellow>%d</yellow>",
		c.syncedUploadMTU,
		c.syncedDownloadMTU,
	)
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<green>Global MTU Configuration -> Upload: <cyan>%d</cyan>, Download: <cyan>%d</cyan></green>",
		c.syncedUploadMTU,
		c.syncedDownloadMTU,
	)
}

func formatResolverRTT(rtt time.Duration) string {
	if rtt <= 0 {
		return "n/a"
	}

	if rtt < time.Millisecond {
		return "<1ms"
	}

	return rtt.Round(time.Millisecond).String()
}
