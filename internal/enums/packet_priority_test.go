// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package enums

import "testing"

func TestDefaultPacketPriorityMatchesCurrentBehavior(t *testing.T) {
	tests := map[uint8]int{
		PACKET_STREAM_DATA:             PacketPriorityNormal,
		PACKET_STREAM_DATA_ACK:         PacketPriorityCritical,
		PACKET_STREAM_DATA_NACK:        PacketPriorityCritical,
		PACKET_STREAM_RESEND:           PacketPriorityRetry,
		PACKET_DNS_QUERY_REQ:           PacketPriorityRetry,
		PACKET_SOCKS5_SYN:              PacketPriorityCritical,
		PACKET_STREAM_CLOSE_WRITE:      PacketPriorityLow,
		PACKET_STREAM_RST:              PacketPriorityCritical,
		PACKET_PING:                    PacketPriorityIdle,
		PACKET_SOCKS5_CONNECTED_ACK:    PacketPriorityCritical,
		PACKET_DNS_QUERY_REQ_ACK:       PacketPriorityCritical,
		PACKET_SOCKS5_CONNECT_FAIL_ACK: PacketPriorityCritical,
	}

	for packetType, want := range tests {
		if got := DefaultPacketPriority(packetType); got != want {
			t.Fatalf("unexpected priority for %d: got=%d want=%d", packetType, got, want)
		}
	}
}

func TestNormalizePacketPriorityFallsBackToDefault(t *testing.T) {
	if got := NormalizePacketPriority(PACKET_STREAM_DATA, -1); got != PacketPriorityNormal {
		t.Fatalf("unexpected normalized priority for fallback: got=%d want=%d", got, PacketPriorityNormal)
	}

	if got := NormalizePacketPriority(PACKET_STREAM_DATA, PacketPriorityLow); got != PacketPriorityLow {
		t.Fatalf("explicit priority should be preserved: got=%d want=%d", got, PacketPriorityLow)
	}
}
