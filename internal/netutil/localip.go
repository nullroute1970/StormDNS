// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package netutil

import (
	"net"
	"sort"
	"strings"
)

// LocalInterfaceIPs returns the non-loopback unicast IP addresses of the host.
// It works cross-platform (Windows, Linux, macOS).
// If the machine has no usable addresses, it returns nil.
func LocalInterfaceIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var ips []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			ips = append(ips, ip.String())
		}
	}

	// Sort: IPv4 first, then IPv6.
	sort.Slice(ips, func(i, j int) bool {
		iIs4 := !strings.Contains(ips[i], ":")
		jIs4 := !strings.Contains(ips[j], ":")
		if iIs4 != jIs4 {
			return iIs4
		}
		return ips[i] < ips[j]
	})
	return ips
}

// FormatListenHint returns a user-friendly string listing the reachable addresses
// for a listener bound to the given ip and port.
// If ip is a wildcard (0.0.0.0 or ::), it enumerates host interfaces.
// Otherwise it returns an empty string (no extra hint needed).
func FormatListenHint(ip string, port int) string {
	trimmed := strings.TrimSpace(ip)
	if trimmed != "0.0.0.0" && trimmed != "::" && trimmed != "" {
		return ""
	}

	localIPs := LocalInterfaceIPs()
	if len(localIPs) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("Reachable at: ")
	for i, addr := range localIPs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(net.JoinHostPort(addr, itoa(port)))
	}
	return b.String()
}

func itoa(n int) string {
	// Simple int-to-string without importing strconv.
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
