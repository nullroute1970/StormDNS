// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the StormDNS client.
// This file (traffic_stats.go) implements the periodic traffic speed and total
// bytes reporter that prints to the console log window.
// ==============================================================================

package client

import (
	"context"
	"fmt"
	"time"
)

// formatBytes formats a raw byte count into a human-readable size string.
func formatBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.2f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// formatSpeed formats a bytes-per-second value into a human-readable speed string.
func formatSpeed(bytesPerSec float64) string {
	switch {
	case bytesPerSec >= float64(1<<30):
		return fmt.Sprintf("%.2f GB/s", bytesPerSec/float64(1<<30))
	case bytesPerSec >= float64(1<<20):
		return fmt.Sprintf("%.2f MB/s", bytesPerSec/float64(1<<20))
	case bytesPerSec >= float64(1<<10):
		return fmt.Sprintf("%.2f KB/s", bytesPerSec/float64(1<<10))
	default:
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	}
}

// runTrafficStatsReporter periodically logs upload/download speed and session
// totals to the console. It runs as a goroutine inside the async runtime and
// exits when ctx is cancelled.
func (c *Client) runTrafficStatsReporter(ctx context.Context) {
	interval := c.cfg.StatsReportInterval()
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastTX, lastRX uint64
	lastTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			currentTX := c.txTotalBytes.Load()
			currentRX := c.rxTotalBytes.Load()

			elapsed := now.Sub(lastTime).Seconds()
			var upSpeed, downSpeed float64
			if elapsed > 0 {
				upSpeed = float64(currentTX-lastTX) / elapsed
				downSpeed = float64(currentRX-lastRX) / elapsed
			}

			lastTX = currentTX
			lastRX = currentRX
			lastTime = now

			if c.log != nil {
				c.log.Infof(
					"\U0001F4CA <cyan>↑</cyan> <yellow>%s</yellow> <gray>(Total: %s)</gray> <magenta>|</magenta> <cyan>↓</cyan> <yellow>%s</yellow> <gray>(Total: %s)</gray>",
					formatSpeed(upSpeed),
					formatBytes(currentTX),
					formatSpeed(downSpeed),
					formatBytes(currentRX),
				)
			}
		}
	}
}
