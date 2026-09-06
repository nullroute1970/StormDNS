// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the StormDNS client.
// This file (tunnel_query.go) handles the construction of DNS tunnel queries.
// ==============================================================================
package client

import (
	"math/rand"
	"strings"

	DnsParser "stormdns-go/internal/dnsparser"
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

type preparedTunnelDomain struct {
	normalized string
	qname      []byte
}

// pickTunnelQueryType returns the DNS record type for the next tunnel query
// based on the configured mode: TXT (default), NS, or ROTATE (uniform random).
func (c *Client) pickTunnelQueryType() uint16 {
	mode := "TXT"
	if c != nil {
		mode = strings.TrimSpace(c.cfg.DNSQueryType)
		if mode == "" {
			mode = "TXT"
		}
	}
	switch mode {
	case "NS":
		return Enums.DNS_RECORD_TYPE_NS
	case "ROTATE":
		if rand.Intn(2) == 0 {
			return Enums.DNS_RECORD_TYPE_TXT
		}
		return Enums.DNS_RECORD_TYPE_NS
	default:
		return Enums.DNS_RECORD_TYPE_TXT
	}
}

func (c *Client) buildTunnelQuestionBytes(domain string, encoded []byte) ([]byte, error) {
	return DnsParser.BuildTunnelTXTQuestionPacket(domain, encoded, c.pickTunnelQueryType(), EDnsSafeUDPSize)
}

func (c *Client) buildTunnelQuestionBytesPrepared(domain preparedTunnelDomain, encoded []byte) ([]byte, error) {
	return DnsParser.BuildTunnelTXTQuestionPacketPrepared(domain.normalized, domain.qname, encoded, c.pickTunnelQueryType(), EDnsSafeUDPSize)
}

func prepareTunnelDomain(domain string) (preparedTunnelDomain, error) {
	normalized, qname, err := DnsParser.PrepareTunnelDomainQname(domain)
	if err != nil {
		return preparedTunnelDomain{}, err
	}
	return preparedTunnelDomain{normalized: normalized, qname: qname}, nil
}

func (c *Client) buildTunnelTXTQueryRaw(domain string, options VpnProto.BuildOptions) ([]byte, error) {
	raw, err := VpnProto.BuildRaw(options)
	if err != nil {
		return nil, err
	}
	encoded, err := c.codec.EncryptAndEncodeBytes(raw)
	if err != nil {
		return nil, err
	}
	return c.buildTunnelQuestionBytes(domain, encoded)
}

func (c *Client) buildEncodedAutoWithCompressionTrace(options VpnProto.BuildOptions) ([]byte, error) {
	raw, err := VpnProto.BuildRawAuto(options, c.cfg.CompressionMinSize)
	if err != nil {
		return nil, err
	}

	if c.codec == nil {
		return nil, VpnProto.ErrCodecUnavailable
	}
	return c.codec.EncryptAndEncodeBytes(raw)
}

// buildTunnelTXTQuery builds an encoded tunnel query with automatic option handling.
func (c *Client) buildTunnelTXTQuery(domain string, options VpnProto.BuildOptions) ([]byte, error) {
	encoded, err := c.buildEncodedAutoWithCompressionTrace(options)
	if err != nil {
		return nil, err
	}
	return c.buildTunnelQuestionBytes(domain, encoded)
}
