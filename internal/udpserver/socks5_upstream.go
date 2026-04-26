// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/logger"
)

type upstreamSOCKS5Error struct {
	packetType uint8
	err        error
}

type blockedSOCKSTargetError struct {
	host string
}

var (
	externalSOCKS5NoAuthGreeting = []byte{0x05, 0x01, 0x00}
	externalSOCKS5UserPassAuth   = []byte{0x05, 0x01, 0x02}
)

type socks5FragmentKey struct {
	sessionID   uint8
	streamID    uint16
	sequenceNum uint16
}

func (e *upstreamSOCKS5Error) Error() string {
	if e == nil || e.err == nil {
		return "upstream socks5 error"
	}
	return e.err.Error()
}

func (e *upstreamSOCKS5Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func (e *blockedSOCKSTargetError) Error() string {
	if e == nil || e.host == "" {
		return "blocked socks target"
	}
	return fmt.Sprintf("blocked socks target: %s", e.host)
}

func (s *Server) dialSOCKSStreamTarget(host string, port uint16, targetPayload []byte) (net.Conn, error) {
	return s.dialSOCKSStreamTargetContext(context.Background(), host, port, targetPayload)
}

func (s *Server) dialSOCKSStreamTargetContext(ctx context.Context, host string, port uint16, targetPayload []byte) (net.Conn, error) {
	if s == nil {
		return nil, &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			err:        errors.New("server unavailable"),
		}
	}

	if err := validateSOCKSTargetHost(host); err != nil {
		return nil, err
	}

	if !s.useExternalSOCKS5 || len(targetPayload) == 0 {
		return s.dialTCPTargetContext(ctx, net.JoinHostPort(host, strconv.Itoa(int(port))))
	}
	return s.dialExternalSOCKS5TargetContext(ctx, targetPayload)
}

func validateSOCKSTargetHost(host string) error {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return &blockedSOCKSTargetError{host: host}
	}

	lower := strings.ToLower(trimmed)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return &blockedSOCKSTargetError{host: host}
	}

	ip := net.ParseIP(trimmed)
	if ip == nil {
		return nil
	}

	if !ip.IsGlobalUnicast() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() {
		return &blockedSOCKSTargetError{host: host}
	}

	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return &blockedSOCKSTargetError{host: host}
		}
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return &blockedSOCKSTargetError{host: host}
		}
	}

	return nil
}

func (s *Server) dialTCPTarget(address string) (net.Conn, error) {
	return s.dialTCPTargetContext(context.Background(), address)
}

func (s *Server) dialTCPTargetContext(ctx context.Context, address string) (net.Conn, error) {
	dialFn := s.dialStreamUpstreamFn
	timeout := s.socksConnectTimeout
	if timeout <= 0 {
		timeout = s.cfg.SOCKSConnectTimeout()
	}
	if deadline, ok := ctx.Deadline(); ok {
		untilDeadline := time.Until(deadline)
		if untilDeadline > 0 && (timeout <= 0 || untilDeadline < timeout) {
			timeout = untilDeadline
		}
	}
	startedAt := logger.NowUnixNano()

	if dialFn == nil {
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		return conn, err
	}
	if ctx == nil {
		conn, err := dialFn("tcp", address, timeout)
		return conn, err
	}
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)
	go func() {
		conn, err := dialFn("tcp", address, timeout)
		resultCh <- dialResult{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		go func() {
			result := <-resultCh
			if result.conn != nil {
				_ = result.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case result := <-resultCh:
		if s != nil && s.log != nil {
			s.log.Debugf(
				"DEFER upstream-connect-finish | address=%s | dur_ms=%d | err=%v",
				address,
				(logger.NowUnixNano()-startedAt)/1_000_000,
				result.err,
			)
		}
		return result.conn, result.err
	}
}

func (s *Server) dialExternalSOCKS5Target(targetPayload []byte) (net.Conn, error) {
	return s.dialExternalSOCKS5TargetContext(context.Background(), targetPayload)
}

func (s *Server) dialExternalSOCKS5TargetContext(ctx context.Context, targetPayload []byte) (net.Conn, error) {
	conn, err := s.dialTCPTargetContext(ctx, s.externalSOCKS5Address)
	if err != nil {
		return nil, err
	}

	// Watchdog: cancel the in-progress SOCKS5 handshake if ctx is cancelled.
	// Stops on function return regardless of outcome so the goroutine never
	// outlives the handshake (previously it lingered until ctx cancellation
	// — i.e. session lifetime — even after a successful handshake handed
	// the connection off to the caller).
	stopWatchdog := make(chan struct{})
	defer close(stopWatchdog)
	if ctx != nil {
		go func(c net.Conn) {
			select {
			case <-ctx.Done():
				_ = c.Close()
			case <-stopWatchdog:
			}
		}(conn)
	}

	timeout := s.socksConnectTimeout
	if timeout <= 0 {
		timeout = s.cfg.SOCKSConnectTimeout()
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	if err := writeAll(conn, s.externalSOCKS5Greeting()); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}

	var greeting [2]byte

	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}
	if greeting[0] != 0x05 {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			err:        errors.New("upstream proxy is not a valid SOCKS5 server"),
		}
	}
	if err := s.handleExternalSOCKS5Auth(conn, greeting[1]); err != nil {
		_ = conn.Close()
		return nil, err
	}

	request := make([]byte, 3+len(targetPayload))
	request[0] = 0x05
	request[1] = 0x01
	request[2] = 0x00
	copy(request[3:], targetPayload)

	if err := writeAll(conn, request); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}

	var header [4]byte

	if _, err := io.ReadFull(conn, header[:]); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}
	if header[0] != 0x05 {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			err:        errors.New("invalid external SOCKS5 connect response"),
		}
	}
	if header[1] != 0x00 {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{
			packetType: socks5ReplyPacketType(header[1]),
			err:        fmt.Errorf("external SOCKS5 failed to connect to target: code %d", header[1]),
		}
	}
	if err := discardSOCKS5BoundAddress(conn, header[3]); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (s *Server) externalSOCKS5Greeting() []byte {
	if s != nil && s.externalSOCKS5Auth {
		return externalSOCKS5UserPassAuth
	}
	return externalSOCKS5NoAuthGreeting
}

func (s *Server) handleExternalSOCKS5Auth(conn net.Conn, method byte) error {
	if !s.externalSOCKS5Auth {
		if method == 0x00 {
			return nil
		}
		return &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_AUTH_FAILED,
			err:        errors.New("external SOCKS5 requires unsupported authentication method"),
		}
	}

	if method != 0x02 {
		return &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_AUTH_FAILED,
			err:        errors.New("external SOCKS5 authentication method mismatch"),
		}
	}

	request := make([]byte, 3+len(s.externalSOCKS5User)+len(s.externalSOCKS5Pass))
	request[0] = 0x01
	request[1] = byte(len(s.externalSOCKS5User))
	offset := 2
	offset += copy(request[offset:], s.externalSOCKS5User)
	request[offset] = byte(len(s.externalSOCKS5Pass))
	offset++
	copy(request[offset:], s.externalSOCKS5Pass)
	if err := writeAll(conn, request); err != nil {
		return &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_AUTH_FAILED, err: err}
	}

	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_AUTH_FAILED, err: err}
	}
	if response[1] != 0x00 {
		return &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_AUTH_FAILED,
			err:        errors.New("external SOCKS5 authentication failed"),
		}
	}
	return nil
}

func discardSOCKS5BoundAddress(conn net.Conn, atyp byte) error {
	length := 0
	switch atyp {
	case 0x01:
		length = 4 + 2
	case 0x03:
		var dlen [1]byte
		if _, err := io.ReadFull(conn, dlen[:]); err != nil {
			return err
		}
		length = int(dlen[0]) + 2
	case 0x04:
		length = 16 + 2
	default:
		return errors.New("unsupported SOCKS5 bound address type")
	}
	if length == 0 {
		return nil
	}
	var buffer [257]byte
	_, err := io.ReadFull(conn, buffer[:length])
	return err
}

func socks5ReplyPacketType(reply byte) uint8 {
	switch reply {
	case 0x02:
		return Enums.PACKET_SOCKS5_RULESET_DENIED
	case 0x03:
		return Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE
	case 0x04:
		return Enums.PACKET_SOCKS5_HOST_UNREACHABLE
	case 0x05:
		return Enums.PACKET_SOCKS5_CONNECTION_REFUSED
	case 0x06:
		return Enums.PACKET_SOCKS5_TTL_EXPIRED
	case 0x07:
		return Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED
	case 0x08:
		return Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED
	default:
		return Enums.PACKET_SOCKS5_CONNECT_FAIL
	}
}

func writeAll(conn net.Conn, payload []byte) error {
	for len(payload) != 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func (s *Server) collectSOCKS5SynFragments(sessionID uint8, streamID uint16, sequenceNum uint16, payload []byte, fragmentID uint8, totalFragments uint8, now time.Time) ([]byte, bool, bool) {
	if totalFragments == 0 {
		totalFragments = 1
	}

	assembled, ready, completed := s.socks5Fragments.Collect(
		socks5FragmentKey{
			sessionID:   sessionID,
			streamID:    streamID,
			sequenceNum: sequenceNum,
		},
		payload,
		fragmentID,
		totalFragments,
		now,
		s.dnsFragmentTimeout,
	)

	return assembled, ready, completed
}

func (s *Server) purgeSOCKS5SynFragments(now time.Time) {
	if s == nil || s.socks5Fragments == nil {
		return
	}
	s.socks5Fragments.Purge(now, s.dnsFragmentTimeout)
}

func (s *Server) removeSOCKS5SynFragmentsForSession(sessionID uint8) {
	if s == nil || s.socks5Fragments == nil || sessionID == 0 {
		return
	}
	s.socks5Fragments.RemoveIf(func(key socks5FragmentKey) bool {
		return key.sessionID == sessionID
	})
}

func (s *Server) removeSOCKS5SynFragmentsForStream(sessionID uint8, streamID uint16) {
	if s == nil || s.socks5Fragments == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.socks5Fragments.RemoveIf(func(key socks5FragmentKey) bool {
		return key.sessionID == sessionID && key.streamID == streamID
	})
}
