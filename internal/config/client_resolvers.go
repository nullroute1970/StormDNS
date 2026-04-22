// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package config

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultResolverPort = 53
	maxResolverHosts    = 65536
)

type ResolverAddress struct {
	IP   string
	Port int
}

type resolverTarget struct {
	addr     netip.Addr
	prefix   netip.Prefix
	isPrefix bool
}

func LoadClientResolvers(filename string) ([]ResolverAddress, map[string]int, error) {
	path, err := filepath.Abs(filename)
	if err != nil {
		return nil, nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("resolver file not found: %s", path)
	}
	defer file.Close()

	endpoints := make([]ResolverAddress, 0, 64)
	resolverMap := make(map[string]int, 64)
	seenIPs := make(map[string]struct{}, 64)

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		target, port, err := parseResolverEntry(line)
		if err != nil {
			continue
		}

		if !target.isPrefix {
			addResolver(&endpoints, resolverMap, seenIPs, target.addr.String(), port)
			continue
		}

		usableHosts, ok := usableHostCount(target.prefix)
		if !ok || usableHosts > maxResolverHosts {
			continue
		}

		appendPrefixResolvers(&endpoints, resolverMap, seenIPs, target.prefix, port)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to read resolver file %s: %w", path, err)
	}
	if len(endpoints) == 0 {
		return nil, nil, fmt.Errorf("no valid resolvers found in %s", path)
	}

	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].IP == endpoints[j].IP {
			return endpoints[i].Port < endpoints[j].Port
		}
		return endpoints[i].IP < endpoints[j].IP
	})

	return endpoints, resolverMap, nil
}

func addResolver(endpoints *[]ResolverAddress, resolverMap map[string]int, seenIPs map[string]struct{}, ip string, port int) {
	if _, exists := seenIPs[ip]; exists {
		return
	}
	seenIPs[ip] = struct{}{}
	if _, exists := resolverMap[ip]; !exists {
		resolverMap[ip] = port
	}
	*endpoints = append(*endpoints, ResolverAddress{
		IP:   ip,
		Port: port,
	})
}

func appendPrefixResolvers(endpoints *[]ResolverAddress, resolverMap map[string]int, seenIPs map[string]struct{}, prefix netip.Prefix, port int) {
	prefix = prefix.Masked()
	first, last := hostRange(prefix)
	if !first.IsValid() || !last.IsValid() {
		return
	}

	for addr := first; ; addr = addr.Next() {
		addResolver(endpoints, resolverMap, seenIPs, addr.String(), port)
		if addr == last {
			return
		}
	}
}

func parseResolverEntry(line string) (resolverTarget, int, error) {
	text := strings.TrimSpace(line)
	if text == "" {
		return resolverTarget{}, 0, fmt.Errorf("empty resolver entry")
	}

	if target, err := parseBareResolverTarget(text); err == nil {
		return target, defaultResolverPort, nil
	}

	hostPart, portPart, err := splitHostPort(text)
	if err != nil {
		return resolverTarget{}, 0, err
	}

	port, err := strconv.Atoi(portPart)
	if err != nil || port < 1 || port > 65535 {
		return resolverTarget{}, 0, fmt.Errorf("resolver port out of range")
	}

	target, err := parseBareResolverTarget(hostPart)
	if err != nil {
		return resolverTarget{}, 0, err
	}
	return target, port, nil
}

func parseBareResolverTarget(text string) (resolverTarget, error) {
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return resolverTarget{}, fmt.Errorf("invalid resolver subnet")
		}
		return resolverTarget{
			prefix:   prefix.Masked(),
			isPrefix: true,
		}, nil
	}

	addr, err := netip.ParseAddr(text)
	if err != nil {
		return resolverTarget{}, fmt.Errorf("invalid resolver IP")
	}
	return resolverTarget{
		addr: addr.Unmap(),
	}, nil
}

func splitHostPort(text string) (string, string, error) {
	if strings.HasPrefix(text, "[") {
		end := strings.IndexByte(text, ']')
		if end == -1 {
			return "", "", fmt.Errorf("invalid bracketed resolver")
		}

		hostPart := strings.TrimSpace(text[1:end])
		remainder := strings.TrimSpace(text[end+1:])
		if !strings.HasPrefix(remainder, ":") {
			return "", "", fmt.Errorf("invalid resolver entry")
		}

		portPart := strings.TrimSpace(remainder[1:])
		if hostPart == "" || portPart == "" {
			return "", "", fmt.Errorf("invalid resolver entry")
		}
		return hostPart, portPart, nil
	}

	lastColon := strings.LastIndexByte(text, ':')
	if lastColon <= 0 || lastColon == len(text)-1 {
		return "", "", fmt.Errorf("invalid resolver entry")
	}

	hostPart := strings.TrimSpace(text[:lastColon])
	portPart := strings.TrimSpace(text[lastColon+1:])
	if hostPart == "" || portPart == "" {
		return "", "", fmt.Errorf("invalid resolver entry")
	}

	return hostPart, portPart, nil
}

func usableHostCount(prefix netip.Prefix) (int, bool) {
	prefix = prefix.Masked()
	addr := prefix.Addr()

	if addr.Is4() {
		hostBits := 32 - prefix.Bits()
		if hostBits >= 31 {
			if hostBits > 31 {
				return 0, false
			}
			return 2, true
		}

		total := 1 << hostBits
		return total - 2, true
	}

	hostBits := 128 - prefix.Bits()
	if hostBits > 16 {
		return 0, false
	}

	total := 1 << hostBits
	if prefix.Bits() < 127 {
		return total - 1, true
	}
	return total, true
}

func hostRange(prefix netip.Prefix) (netip.Addr, netip.Addr) {
	network := prefix.Addr().Unmap()
	last := prefixLastAddr(prefix)

	if network.Is4() && prefix.Bits() < 31 {
		return network.Next(), prevAddr(last)
	}
	if network.Is6() && prefix.Bits() < 127 {
		return network.Next(), last
	}
	return network, last
}

func prefixLastAddr(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()

	if addr.Is4() {
		b := addr.As4()
		hostBits := 32 - prefix.Bits()
		value := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		if hostBits > 0 {
			value |= (uint32(1) << hostBits) - 1
		}
		var out [4]byte
		out[0] = byte(value >> 24)
		out[1] = byte(value >> 16)
		out[2] = byte(value >> 8)
		out[3] = byte(value)
		return netip.AddrFrom4(out)
	}

	b := addr.As16()
	hostBits := 128 - prefix.Bits()
	for i := 15; i >= 0 && hostBits > 0; i-- {
		if hostBits >= 8 {
			b[i] = 0xFF
			hostBits -= 8
			continue
		}
		b[i] |= byte((1 << hostBits) - 1)
		hostBits = 0
	}
	return netip.AddrFrom16(b)
}

func prevAddr(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		value := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		value--
		var out [4]byte
		out[0] = byte(value >> 24)
		out[1] = byte(value >> 16)
		out[2] = byte(value >> 8)
		out[3] = byte(value)
		return netip.AddrFrom4(out)
	}

	b := addr.As16()
	for i := 15; i >= 0; i-- {
		if b[i] > 0 {
			b[i]--
			break
		}
		b[i] = 0xFF
	}
	return netip.AddrFrom16(b)
}
