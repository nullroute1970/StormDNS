package client

import (
	"errors"
	"net"
	"strconv"
	"testing"
)

type listenerTempError struct {
	timeout   bool
	temporary bool
}

func (e listenerTempError) Error() string   { return "listener temp error" }
func (e listenerTempError) Timeout() bool   { return e.timeout }
func (e listenerTempError) Temporary() bool { return e.temporary }

func TestListenerShouldRetryAccept(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "closed", err: net.ErrClosed, want: false},
		{name: "timeout", err: listenerTempError{timeout: true}, want: true},
		{name: "temporary", err: listenerTempError{temporary: true}, want: true},
		{name: "permanent", err: errors.New("permission denied"), want: false},
	}

	for _, tt := range tests {
		if got := listenerShouldRetryAccept(tt.err); got != tt.want {
			t.Fatalf("%s: got %v want %v", tt.name, got, tt.want)
		}
	}
}

func TestListenerAddressesForBindLoopbackIncludesIPv4AndIPv6(t *testing.T) {
	got := listenerAddressesForBind("127.0.0.1", 18000)
	want := []string{
		net.JoinHostPort("127.0.0.1", strconv.Itoa(18000)),
		net.JoinHostPort("::1", strconv.Itoa(18000)),
	}

	if len(got) != len(want) {
		t.Fatalf("unexpected address count: got=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected address at %d: got=%q want=%q", i, got[i], want[i])
		}
	}
}

func TestListenerAddressesForBindLeavesNonLoopbackUntouched(t *testing.T) {
	got := listenerAddressesForBind("0.0.0.0", 18000)
	want := []string{net.JoinHostPort("0.0.0.0", strconv.Itoa(18000))}

	if len(got) != len(want) {
		t.Fatalf("unexpected address count: got=%d want=%d", len(got), len(want))
	}
	if got[0] != want[0] {
		t.Fatalf("unexpected address: got=%q want=%q", got[0], want[0])
	}
}
