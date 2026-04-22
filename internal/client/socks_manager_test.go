package client

import (
	"io"
	"net"
	"testing"
	"time"

	"stormdns-go/internal/config"
	VpnProto "stormdns-go/internal/vpnproto"
)

func TestSupportsSOCKS4Policy(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.ClientConfig
		want bool
	}{
		{
			name: "auth disabled supports socks4",
			cfg:  config.ClientConfig{SOCKS5Auth: false},
			want: true,
		},
		{
			name: "auth enabled with username and password disables socks4",
			cfg:  config.ClientConfig{SOCKS5Auth: true, SOCKS5User: "user", SOCKS5Pass: "pass"},
			want: false,
		},
		{
			name: "auth enabled with username only supports socks4",
			cfg:  config.ClientConfig{SOCKS5Auth: true, SOCKS5User: "user"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{cfg: tt.cfg}
			if got := c.supportsSOCKS4(); got != tt.want {
				t.Fatalf("supportsSOCKS4() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSendSocks4ReplyFormatsResponse(t *testing.T) {
	c := &Client{}
	server, clientConn := net.Pipe()
	defer server.Close()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- c.sendSocks4Reply(server, true)
	}()

	reply := make([]byte, 8)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("failed to read SOCKS4 reply: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("sendSocks4Reply returned error: %v", err)
	}

	want := []byte{0x00, SOCKS4_REPLY_GRANTED, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i := range want {
		if reply[i] != want[i] {
			t.Fatalf("reply[%d] = 0x%02x, want 0x%02x", i, reply[i], want[i])
		}
	}
}

func TestLateSocksResultDoesNotReactivateCancelledStream(t *testing.T) {
	c := &Client{
		active_streams: make(map[uint16]*Stream_client),
	}

	server, clientConn := net.Pipe()
	defer server.Close()
	defer clientConn.Close()

	s := &Stream_client{
		client:            c,
		StreamID:          7,
		LocalSocksVersion: SOCKS5_VERSION,
		NetConn:           server,
		Status:            streamStatusSocksConnecting,
		CreateTime:        time.Now(),
		LastActivityTime:  time.Now(),
	}
	c.active_streams[s.StreamID] = s

	c.handlePendingSOCKSLocalClose(s.StreamID, "test cancel")
	if got := s.StatusValue(); got != streamStatusCancelled {
		t.Fatalf("expected stream status %q after local close, got %q", streamStatusCancelled, got)
	}

	if err := c.HandleSocksConnected(VpnProto.Packet{StreamID: s.StreamID}); err != nil {
		t.Fatalf("HandleSocksConnected returned error: %v", err)
	}

	if got := s.StatusValue(); got != streamStatusCancelled {
		t.Fatalf("expected cancelled stream not to reactivate, got %q", got)
	}
	if s.TerminalSince().IsZero() {
		t.Fatal("expected cancelled stream to remain terminal after late SOCKS result")
	}
}


