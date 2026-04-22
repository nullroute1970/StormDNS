package client

import (
	"errors"
	"net"
	"testing"
)

type dnsTempError struct {
	timeout   bool
	temporary bool
}

func (e dnsTempError) Error() string   { return "dns temp error" }
func (e dnsTempError) Timeout() bool   { return e.timeout }
func (e dnsTempError) Temporary() bool { return e.temporary }

func TestDNSListenerShouldRetryRead(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "closed", err: net.ErrClosed, want: false},
		{name: "timeout", err: dnsTempError{timeout: true}, want: true},
		{name: "temporary", err: dnsTempError{temporary: true}, want: true},
		{name: "permanent", err: errors.New("permission denied"), want: false},
	}

	for _, tt := range tests {
		if got := dnsListenerShouldRetryRead(tt.err); got != tt.want {
			t.Fatalf("%s: got %v want %v", tt.name, got, tt.want)
		}
	}
}
