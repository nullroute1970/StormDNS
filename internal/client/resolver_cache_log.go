// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the StormDNS client.
// This file (resolver_cache_log.go) handles per-session resolver cache logging.
// Each line records a working resolver together with its MTU values so that
// future runs can start quickly by skipping the full MTU scan.
//
// Line format:
//   <RFC3339>  <ip:port>  <domain>  UP=<n>  DOWN=<n>
// Example:
//   2026-04-20T15:04:05Z  8.8.8.8:53  v.domain.com  UP=64  DOWN=120
// ==============================================================================
package client

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// openResolverCacheLog creates (or truncates) the resolver cache log file for
// this session. The parent directory is created if it does not exist. When path
// is empty or any I/O error occurs the feature is silently disabled.
func (c *Client) openResolverCacheLog(path string) {
	if c == nil || path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		if c.mtuWarnEnabled() {
			c.log.Warnf(
				"<yellow>[Cache]</yellow> Failed to create log directory for resolver cache: %v",
				err,
			)
		}
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		if c.mtuWarnEnabled() {
			c.log.Warnf(
				"<yellow>[Cache]</yellow> Failed to open resolver cache log %s: %v",
				path,
				err,
			)
		}
		return
	}

	c.resolverCacheLogMu.Lock()
	c.resolverCacheLogFile = f
	c.resolverCacheLogMu.Unlock()

	if c.mtuInfoEnabled() {
		c.log.Infof(
			"<blue>[Cache]</blue> Resolver cache log: <cyan>%s</cyan>",
			path,
		)
	}
}

// appendResolverCacheEntry writes one line to the resolver cache log for a
// connection that has been confirmed working (MTU values are positive).
// Format: <RFC3339> <ip:port> <domain> UP=<n> DOWN=<n>
func (c *Client) appendResolverCacheEntry(conn *Connection) {
	if c == nil || conn == nil || conn.UploadMTUBytes <= 0 || conn.DownloadMTUBytes <= 0 {
		return
	}

	c.resolverCacheLogMu.Lock()
	f := c.resolverCacheLogFile
	c.resolverCacheLogMu.Unlock()
	if f == nil {
		return
	}

	endpoint := formatResolverEndpoint(conn.Resolver, conn.ResolverPort)
	line := fmt.Sprintf(
		"%s %s %s UP=%d DOWN=%d\n",
		time.Now().UTC().Format(time.RFC3339),
		endpoint,
		conn.Domain,
		conn.UploadMTUBytes,
		conn.DownloadMTUBytes,
	)

	c.resolverCacheLogMu.Lock()
	defer c.resolverCacheLogMu.Unlock()
	if c.resolverCacheLogFile != nil {
		_, _ = c.resolverCacheLogFile.WriteString(line)
	}
}

// closeResolverCacheLog flushes and closes the cache log file.
func (c *Client) closeResolverCacheLog() {
	if c == nil {
		return
	}
	c.resolverCacheLogMu.Lock()
	defer c.resolverCacheLogMu.Unlock()
	if c.resolverCacheLogFile != nil {
		_ = c.resolverCacheLogFile.Close()
		c.resolverCacheLogFile = nil
	}
}
