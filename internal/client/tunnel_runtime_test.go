// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package client

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestExchangeUDPQueryWithConnReturnsMatchingResponseAfterMismatches(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP server failed: %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.DialUDP("udp", nil, serverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP client failed: %v", err)
	}
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		n, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 2 {
			return
		}

		_, _ = serverConn.WriteToUDP([]byte{0xAA, 0xBB, 0x01}, addr)
		_, _ = serverConn.WriteToUDP([]byte{buf[0], buf[1], 0x02}, addr)
	}()

	c := &Client{}
	resp, err := c.exchangeUDPQueryWithConn(clientConn, []byte{0x12, 0x34, 0x99}, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("exchangeUDPQueryWithConn returned error: %v", err)
	}
	if len(resp) != 3 || resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatalf("unexpected response: %#v", resp)
	}

	<-done
}

func TestExchangeUDPQueryWithConnFailsAfterTooManyMismatches(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP server failed: %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.DialUDP("udp", nil, serverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP client failed: %v", err)
	}
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		_, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		for i := 0; i < runtimeUDPMaxMismatchedResponses; i++ {
			_, _ = serverConn.WriteToUDP([]byte{0xAA, byte(i), 0x01}, addr)
		}
	}()

	c := &Client{}
	_, err = c.exchangeUDPQueryWithConn(clientConn, []byte{0x12, 0x34, 0x99}, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected mismatched response flood to fail")
	}
	if !strings.Contains(err.Error(), "mismatched dns responses") {
		t.Fatalf("unexpected error: %v", err)
	}

	<-done
}

func TestExchangeUDPQueryWithConnDrainsStaleResponsesBeforeSending(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP server failed: %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.DialUDP("udp", nil, serverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP client failed: %v", err)
	}
	defer clientConn.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 512)

		n, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil || n < 2 {
			return
		}

		time.Sleep(40 * time.Millisecond)
		for i := 0; i < runtimeUDPMaxMismatchedResponses+4; i++ {
			_, _ = serverConn.WriteToUDP([]byte{buf[0], buf[1], 0x81, byte(i)}, addr)
		}

		n, addr, err = serverConn.ReadFromUDP(buf)
		if err != nil || n < 2 {
			return
		}

		resp := []byte{buf[0], buf[1], 0x81, 0x00}
		_, _ = serverConn.WriteToUDP(resp, addr)
	}()

	c := &Client{}

	firstQuery := make([]byte, 4)
	binary.BigEndian.PutUint16(firstQuery[0:2], 0x1234)
	_, err = c.exchangeUDPQueryWithConn(clientConn, firstQuery, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected first query to time out before delayed stale responses arrive")
	}

	time.Sleep(60 * time.Millisecond)

	secondQuery := make([]byte, 4)
	binary.BigEndian.PutUint16(secondQuery[0:2], 0x5678)
	resp, err := c.exchangeUDPQueryWithConn(clientConn, secondQuery, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("second query failed after stale drain: %v", err)
	}
	if len(resp) < 2 || binary.BigEndian.Uint16(resp[0:2]) != 0x5678 {
		t.Fatalf("unexpected second response: %#v", resp)
	}

	<-serverDone
}
