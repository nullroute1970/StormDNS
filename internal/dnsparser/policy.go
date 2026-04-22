// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package dnsparser

import Enums "stormdns-go/internal/enums"

func IsSupportedTunnelDNSQuery(qType uint16, qClass uint16) bool {
	if qClass != Enums.DNSQ_CLASS_IN {
		return false
	}

	switch qType {
	case
		Enums.DNS_RECORD_TYPE_A,
		Enums.DNS_RECORD_TYPE_AAAA,
		Enums.DNS_RECORD_TYPE_CNAME,
		Enums.DNS_RECORD_TYPE_MX,
		Enums.DNS_RECORD_TYPE_NS,
		Enums.DNS_RECORD_TYPE_PTR,
		Enums.DNS_RECORD_TYPE_SRV,
		Enums.DNS_RECORD_TYPE_SVCB,
		Enums.DNS_RECORD_TYPE_CAA,
		Enums.DNS_RECORD_TYPE_NAPTR,
		Enums.DNS_RECORD_TYPE_SOA,
		Enums.DNS_RECORD_TYPE_HTTPS,
		Enums.DNS_RECORD_TYPE_TLSA:
		return true
	default:
		return false
	}
}
