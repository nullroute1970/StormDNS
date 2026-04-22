// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package client

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
)

// isConnBroken reports whether err indicates that the local TCP connection was
// abruptly closed or reset by the peer or the local OS before we could write
// to it. These are expected, non-fatal conditions (e.g. a browser tab closed
// early or the OS aborted an idle connection).
func isConnBroken(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		if errno, ok := sysErr.Err.(syscall.Errno); ok {
			return isConnBrokenErrno(errno)
		}
	}
	return false
}
