// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the StormDNS client.
// This file (log_scanner.go) scans resolver cache log files written by previous
// sessions and returns a ranked list of working resolvers so that the next
// session can skip the full MTU scan and start immediately.
// ==============================================================================
package client

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ResolverCacheEntry represents a resolver+domain pair recovered from one or
// more resolver cache log files.
type ResolverCacheEntry struct {
	IP          string
	Port        int
	Domain      string
	UploadMTU   int
	DownloadMTU int
	// LastSeen is the timestamp of the most recent log line for this entry.
	LastSeen time.Time
	// AppearCount is the number of times this entry appeared across all scanned files.
	AppearCount int
}

// resolverCacheEntryKey returns the deduplication key for a ResolverCacheEntry.
// It matches the connection key format used by makeConnectionKey so look-ups are O(1).
func resolverCacheEntryKey(ip string, port int, domain string) string {
	return ip + "|" + strconv.Itoa(port) + "|" + domain
}

// ScanResolverCacheLogs scans resolver_cache_*.log files in logsDir.
//
//   - maxDays: ignore lines older than this many days (0 = no age limit).
//   - maxResolvers: return at most this many entries ranked by quality (0 = all).
//
// Resolvers are ranked by: AppearCount*1000 + DownloadMTU + UploadMTU (desc).
// Within the same score, the more recently seen entry wins.
// Returns nil when no usable entries are found.
func ScanResolverCacheLogs(logsDir string, maxDays int, maxResolvers int) []ResolverCacheEntry {
	if logsDir == "" {
		return nil
	}

	pattern := filepath.Join(logsDir, "resolver_cache_*.log")
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		return nil
	}

	now := time.Now()
	var cutoff time.Time
	if maxDays > 0 {
		cutoff = now.AddDate(0, 0, -maxDays)
	}

	accum := make(map[string]*ResolverCacheEntry)

	for _, file := range files {
		if !cutoff.IsZero() {
			info, statErr := os.Stat(file)
			if statErr != nil || info.ModTime().Before(cutoff) {
				continue
			}
		}
		parseResolverCacheFile(file, cutoff, accum)
	}

	if len(accum) == 0 {
		return nil
	}

	entries := make([]ResolverCacheEntry, 0, len(accum))
	for _, e := range accum {
		entries = append(entries, *e)
	}

	sort.Slice(entries, func(i, j int) bool {
		si := entries[i].AppearCount*1000 + entries[i].DownloadMTU + entries[i].UploadMTU
		sj := entries[j].AppearCount*1000 + entries[j].DownloadMTU + entries[j].UploadMTU
		if si != sj {
			return si > sj
		}
		return entries[i].LastSeen.After(entries[j].LastSeen)
	})

	if maxResolvers > 0 && len(entries) > maxResolvers {
		entries = entries[:maxResolvers]
	}

	return entries
}

// parseResolverCacheFile parses a single cache log file, accumulating entries.
func parseResolverCacheFile(path string, cutoff time.Time, accum map[string]*ResolverCacheEntry) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, ok := parseResolverCacheLine(line)
		if !ok {
			continue
		}
		if !cutoff.IsZero() && entry.LastSeen.Before(cutoff) {
			continue
		}
		key := resolverCacheEntryKey(entry.IP, entry.Port, entry.Domain)
		if existing, found := accum[key]; found {
			existing.AppearCount++
			// Prefer the newest MTU values.
			if entry.LastSeen.After(existing.LastSeen) {
				existing.UploadMTU = entry.UploadMTU
				existing.DownloadMTU = entry.DownloadMTU
				existing.LastSeen = entry.LastSeen
			}
		} else {
			e := entry
			e.AppearCount = 1
			accum[key] = &e
		}
	}
}

// parseResolverCacheLine parses one line in the format:
//
//	<RFC3339> <ip:port> <domain> UP=<n> DOWN=<n>
func parseResolverCacheLine(line string) (ResolverCacheEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return ResolverCacheEntry{}, false
	}

	ts, err := time.Parse(time.RFC3339, fields[0])
	if err != nil {
		return ResolverCacheEntry{}, false
	}

	host, portStr, err := net.SplitHostPort(fields[1])
	if err != nil {
		return ResolverCacheEntry{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return ResolverCacheEntry{}, false
	}

	domain := strings.TrimSpace(fields[2])
	if domain == "" {
		return ResolverCacheEntry{}, false
	}

	upMTU, err := parseCacheKVInt(fields[3], "UP")
	if err != nil || upMTU <= 0 {
		return ResolverCacheEntry{}, false
	}

	downMTU, err := parseCacheKVInt(fields[4], "DOWN")
	if err != nil || downMTU <= 0 {
		return ResolverCacheEntry{}, false
	}

	return ResolverCacheEntry{
		IP:          host,
		Port:        port,
		Domain:      domain,
		UploadMTU:   upMTU,
		DownloadMTU: downMTU,
		LastSeen:    ts,
	}, true
}

// parseCacheKVInt parses "KEY=value" and returns the integer value.
func parseCacheKVInt(field, key string) (int, error) {
	prefix := key + "="
	if !strings.HasPrefix(field, prefix) {
		return 0, fmt.Errorf("expected %s= prefix", key)
	}
	return strconv.Atoi(field[len(prefix):])
}
