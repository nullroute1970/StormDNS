//go:build !windows

// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package client

import "syscall"

func isConnBrokenErrno(errno syscall.Errno) bool {
	switch errno {
	case syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE:
		return true
	}
	return false
}
