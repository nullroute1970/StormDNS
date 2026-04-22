// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package enums

import "testing"

func TestPacketEnumValuesAreStable(t *testing.T) {
	if PACKET_SESSION_INIT != 0x05 {
		t.Fatalf("unexpected PACKET_SESSION_INIT value: got=%#x want=%#x", PACKET_SESSION_INIT, 0x05)
	}
	if PACKET_STREAM_DATA != 0x0F {
		t.Fatalf("unexpected PACKET_STREAM_DATA value: got=%#x want=%#x", PACKET_STREAM_DATA, 0x0F)
	}
	if PACKET_DNS_QUERY_REQ != 0x32 {
		t.Fatalf("unexpected PACKET_DNS_QUERY_REQ value: got=%#x want=%#x", PACKET_DNS_QUERY_REQ, 0x32)
	}
	if PACKET_ERROR_DROP != 0xFF {
		t.Fatalf("unexpected PACKET_ERROR_DROP value: got=%#x want=%#x", PACKET_ERROR_DROP, 0xFF)
	}
}

func TestPacketEnumValuesAreUnique(t *testing.T) {
	values := []int{
		PACKET_MTU_UP_REQ,
		PACKET_MTU_UP_RES,
		PACKET_MTU_DOWN_REQ,
		PACKET_MTU_DOWN_RES,
		PACKET_SESSION_INIT,
		PACKET_SESSION_ACCEPT,
		PACKET_PING,
		PACKET_PONG,
		PACKET_STREAM_SYN,
		PACKET_STREAM_SYN_ACK,
		PACKET_STREAM_DATA,
		PACKET_STREAM_DATA_ACK,
		PACKET_STREAM_DATA_NACK,
		PACKET_STREAM_RESEND,
		PACKET_PACKED_CONTROL_BLOCKS,
		PACKET_STREAM_CLOSE_WRITE,
		PACKET_STREAM_CLOSE_WRITE_ACK,
		PACKET_STREAM_CLOSE_READ,
		PACKET_STREAM_CLOSE_READ_ACK,
		PACKET_STREAM_RST,
		PACKET_STREAM_RST_ACK,
		PACKET_SOCKS5_SYN,
		PACKET_SOCKS5_SYN_ACK,
		PACKET_SOCKS5_CONNECT_FAIL,
		PACKET_SOCKS5_CONNECT_FAIL_ACK,
		PACKET_SOCKS5_RULESET_DENIED,
		PACKET_SOCKS5_RULESET_DENIED_ACK,
		PACKET_SOCKS5_NETWORK_UNREACHABLE,
		PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
		PACKET_SOCKS5_HOST_UNREACHABLE,
		PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
		PACKET_SOCKS5_CONNECTION_REFUSED,
		PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
		PACKET_SOCKS5_TTL_EXPIRED,
		PACKET_SOCKS5_TTL_EXPIRED_ACK,
		PACKET_SOCKS5_COMMAND_UNSUPPORTED,
		PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
		PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
		PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
		PACKET_SOCKS5_AUTH_FAILED,
		PACKET_SOCKS5_AUTH_FAILED_ACK,
		PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
		PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
		PACKET_DNS_QUERY_REQ,
		PACKET_DNS_QUERY_RES,
		PACKET_ERROR_DROP,
	}

	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			t.Fatalf("duplicate packet enum value detected: %#x", value)
		}
		seen[value] = struct{}{}
	}
}

func TestDNSRecordAndRCodeValues(t *testing.T) {
	if DNS_RECORD_TYPE_TXT != 16 {
		t.Fatalf("unexpected TXT qtype: got=%d want=%d", DNS_RECORD_TYPE_TXT, 16)
	}
	if DNS_RECORD_TYPE_OPT != 41 {
		t.Fatalf("unexpected OPT qtype: got=%d want=%d", DNS_RECORD_TYPE_OPT, 41)
	}
	if DNSR_CODE_NO_ERROR != 0 || DNSR_CODE_REFUSED != 5 {
		t.Fatalf("unexpected rcode values: noerror=%d refused=%d", DNSR_CODE_NO_ERROR, DNSR_CODE_REFUSED)
	}
	if DNSQ_CLASS_IN != 1 {
		t.Fatalf("unexpected IN qclass: got=%d want=%d", DNSQ_CLASS_IN, 1)
	}
}
