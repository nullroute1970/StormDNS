// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package dnsparser

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	baseCodec "stormdns-go/internal/basecodec"
	"stormdns-go/internal/compression"
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

var (
	ErrTXTAnswerMissing   = errors.New("dns txt answer missing")
	ErrTXTAnswerMalformed = errors.New("dns txt answer malformed")
	ErrTXTAnswerTooLarge  = errors.New("dns txt answer too large")
)

const (
	maxDNSNameLen       = 253
	maxDNSLabelLen      = 63
	maxTXTAnswerPayload = 255
	maxTXTEncodedChunk  = 191
	// NS answers carry payload units as domain names: lowercase-base36(unit)
	// split into <=63-char labels. maxNSNameChars keeps the wire name <= 255
	// bytes for the worst-case 4-label split (63+63+62+62 => 250+4+1 = 255).
	maxNSNameChars = 250
)

func BuildTXTQuestionPacket(name string, qType uint16, ednsUDPSize uint16) ([]byte, error) {
	qname, err := encodeDNSNameStrict(name)
	if err != nil {
		return nil, err
	}

	requestID := nextDNSRequestID()

	arCount := uint16(0)
	optLen := 0
	if ednsUDPSize > 0 {
		arCount = 1
		optLen = 11
	}

	packet := make([]byte, dnsHeaderSize+len(qname)+4+optLen)
	binary.BigEndian.PutUint16(packet[0:2], requestID)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], arCount)

	offset := dnsHeaderSize
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qType)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	offset += 4

	if ednsUDPSize > 0 {
		packet[offset] = 0x00
		offset++
		binary.BigEndian.PutUint16(packet[offset:offset+2], Enums.DNS_RECORD_TYPE_OPT)
		offset += 2
		binary.BigEndian.PutUint16(packet[offset:offset+2], ednsUDPSize)
		offset += 2
		offset += 4
		binary.BigEndian.PutUint16(packet[offset:offset+2], 0)
	}

	return packet, nil
}

func BuildTunnelTXTQuestionPacket(domain string, encodedFrame []byte, qType uint16, ednsUDPSize uint16) ([]byte, error) {
	normalizedDomain, domainQname, err := PrepareTunnelDomainQname(domain)
	if err != nil {
		return nil, err
	}

	return BuildTunnelTXTQuestionPacketPrepared(normalizedDomain, domainQname, encodedFrame, qType, ednsUDPSize)
}

func BuildTunnelTXTQuestionPacketPrepared(normalizedDomain string, domainQname []byte, encodedFrame []byte, qType uint16, ednsUDPSize uint16) ([]byte, error) {
	if normalizedDomain == "" || len(domainQname) == 0 {
		return nil, ErrInvalidName
	}
	if len(encodedFrame) == 0 {
		return buildTXTQuestionPacketPrepared(domainQname, qType, ednsUDPSize), nil
	}
	if encodedQNameLen(len(encodedFrame), len(normalizedDomain)) > maxDNSNameLen {
		return nil, ErrInvalidName
	}

	labelCount := (len(encodedFrame) + maxDNSLabelLen - 1) / maxDNSLabelLen
	qnameLen := len(encodedFrame) + labelCount + len(domainQname)

	arCount := uint16(0)
	optLen := 0
	if ednsUDPSize > 0 {
		arCount = 1
		optLen = 11
	}

	packet := make([]byte, dnsHeaderSize+qnameLen+4+optLen)
	binary.BigEndian.PutUint16(packet[0:2], nextDNSRequestID())
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], arCount)

	offset := dnsHeaderSize
	for start := 0; start < len(encodedFrame); start += maxDNSLabelLen {
		end := start + maxDNSLabelLen
		if end > len(encodedFrame) {
			end = len(encodedFrame)
		}
		packet[offset] = byte(end - start)
		offset++
		offset += copy(packet[offset:], encodedFrame[start:end])
	}
	offset += copy(packet[offset:], domainQname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qType)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	offset += 4

	if ednsUDPSize > 0 {
		packet[offset] = 0x00
		offset++
		binary.BigEndian.PutUint16(packet[offset:offset+2], Enums.DNS_RECORD_TYPE_OPT)
		offset += 2
		binary.BigEndian.PutUint16(packet[offset:offset+2], ednsUDPSize)
		offset += 2
		offset += 4
		binary.BigEndian.PutUint16(packet[offset:offset+2], 0)
	}

	return packet, nil
}

func PrepareTunnelDomainQname(domain string) (string, []byte, error) {
	normalizedDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if normalizedDomain == "" {
		return "", nil, ErrInvalidName
	}

	domainQname, err := encodeDNSNameStrict(normalizedDomain)
	if err != nil {
		return "", nil, err
	}
	return normalizedDomain, domainQname, nil
}

func buildTXTQuestionPacketPrepared(qname []byte, qType uint16, ednsUDPSize uint16) []byte {
	requestID := nextDNSRequestID()

	arCount := uint16(0)
	optLen := 0
	if ednsUDPSize > 0 {
		arCount = 1
		optLen = 11
	}

	packet := make([]byte, dnsHeaderSize+len(qname)+4+optLen)
	binary.BigEndian.PutUint16(packet[0:2], requestID)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], arCount)

	offset := dnsHeaderSize
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qType)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	offset += 4

	if ednsUDPSize > 0 {
		packet[offset] = 0x00
		offset++
		binary.BigEndian.PutUint16(packet[offset:offset+2], Enums.DNS_RECORD_TYPE_OPT)
		offset += 2
		binary.BigEndian.PutUint16(packet[offset:offset+2], ednsUDPSize)
		offset += 2
		offset += 4
		binary.BigEndian.PutUint16(packet[offset:offset+2], 0)
	}

	return packet
}

func BuildTXTResponsePacket(questionPacket []byte, answerName string, answerPayloads [][]byte) ([]byte, error) {
	if len(answerPayloads) == 1 {
		return buildSingleTXTResponsePacket(questionPacket, answerName, answerPayloads[0])
	}

	if len(questionPacket) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(questionPacket)
	questionBytes, questionCount, questionEndOffset := extractQuestionSection(questionPacket, header)
	optStart, optLen := findOPTRecordRange(questionPacket, header, questionEndOffset)

	nameBytes, err := responseAnswerNameBytes(questionPacket, answerName)
	if err != nil {
		return nil, err
	}

	answerLen := 0
	useAnswerNameCompression := len(answerPayloads) > 1
	for i, payload := range answerPayloads {
		nameLen := len(nameBytes)
		if useAnswerNameCompression && i > 0 {
			nameLen = 2
		}
		answerLen += nameLen + 10 + len(payload)
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+answerLen+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(answerPayloads)))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	firstAnswerNameOffset := offset

	for i, payload := range answerPayloads {
		if useAnswerNameCompression && i > 0 && firstAnswerNameOffset <= 0x3FFF {
			binary.BigEndian.PutUint16(response[offset:offset+2], uint16(0xC000|firstAnswerNameOffset))
			offset += 2
		} else {
			offset += copy(response[offset:], nameBytes)
		}
		binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_TXT)
		binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
		binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
		binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(payload)))
		offset += 10
		offset += copy(response[offset:], payload)
	}

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}

	return response, nil
}

func BuildVPNResponsePacket(questionPacket []byte, answerName string, packet VpnProto.Packet, baseEncode bool) ([]byte, error) {
	rawFrame, err := VpnProto.BuildRawAuto(VpnProto.BuildOptions{
		SessionID:       packet.SessionID,
		PacketType:      packet.PacketType,
		SessionCookie:   packet.SessionCookie,
		StreamID:        packet.StreamID,
		SequenceNum:     packet.SequenceNum,
		FragmentID:      packet.FragmentID,
		TotalFragments:  packet.TotalFragments,
		CompressionType: packet.CompressionType,
		Payload:         packet.Payload,
	}, compression.DefaultMinSize)

	if err != nil {
		return nil, err
	}

	if questionTypeIsNS(questionPacket) {
		return buildNSVPNResponse(questionPacket, answerName, rawFrame)
	}
	if questionTypeIsCNAME(questionPacket) {
		return buildCNAMEVPNResponse(questionPacket, answerName, rawFrame)
	}

	maxChunk := maxTXTAnswerPayload
	if baseEncode {
		maxChunk = maxTXTEncodedChunk
	}
	if len(rawFrame) <= maxChunk {
		return buildSingleTXTResponsePacket(questionPacket, answerName, buildTXTAnswerChunk(rawFrame, baseEncode))
	}

	answerPayloads, err := buildTXTAnswerChunks(rawFrame, baseEncode)
	if err != nil {
		return nil, err
	}

	return BuildTXTResponsePacket(questionPacket, answerName, answerPayloads)
}

// maxNSUnitBytes returns the largest raw chunk size whose base36 text fits in
// maxNSNameChars (~161 bytes). Shared by the NS and CNAME name transports.
func maxNSUnitBytes() int {
	for n := 255; n > 0; n-- {
		if baseCodec.EncodedLenLowerBase36(n) <= maxNSNameChars {
			return n
		}
	}
	return 0
}

// buildNSAnswerName encodes one payload unit as a name-rdata wire name (NS
// record or CNAME target): lowercase-base36 text split into <=63-char labels.
func buildNSAnswerName(chunk []byte) ([]byte, error) {
	text := baseCodec.EncodeLowerBase36(chunk)
	if len(text) > maxNSNameChars {
		return nil, ErrTXTAnswerTooLarge
	}
	return encodeDNSNameStrict(EncodeDataToLabels(text))
}

// buildNSAnswerChunks splits rawFrame into chunk units with the same byte
// layout as the TXT chunker (chunk 0: [0x00][total][vpn header][payload...],
// chunk N: [id][payload...]) and returns one rdata wire name per unit (shared
// by the NS and CNAME name transports).
func buildNSAnswerChunks(rawFrame []byte) ([][]byte, error) {
	if len(rawFrame) == 0 {
		return [][]byte{{0}}, nil // root-name placeholder; real frames are never empty
	}

	header, err := VpnProto.Parse(rawFrame)
	if err != nil {
		return nil, err
	}

	headerLen := header.HeaderLength
	maxUnit := maxNSUnitBytes()
	maxChunk0Data := max(maxUnit-2-headerLen, 0)
	remaining := len(header.Payload) - maxChunk0Data
	maxChunkNData := maxUnit - 1
	totalChunks := 1
	if remaining > 0 {
		totalChunks += (remaining + maxChunkNData - 1) / maxChunkNData
	}
	if totalChunks > 255 {
		return nil, ErrTXTAnswerTooLarge
	}

	chunk0DataLen := min(maxChunk0Data, len(header.Payload))
	rawChunk0 := make([]byte, 2+headerLen+chunk0DataLen)
	rawChunk0[0] = 0x00
	rawChunk0[1] = byte(totalChunks)
	copy(rawChunk0[2:], rawFrame[:headerLen])
	copy(rawChunk0[2+headerLen:], header.Payload[:chunk0DataLen])

	chunks := make([][]byte, 0, totalChunks)
	name0, err := buildNSAnswerName(rawChunk0)
	if err != nil {
		return nil, err
	}
	chunks = append(chunks, name0)

	cursor := chunk0DataLen
	for chunkID := 1; cursor < len(header.Payload); chunkID++ {
		end := min(cursor+maxChunkNData, len(header.Payload))
		rawChunk := make([]byte, 1+end-cursor)
		rawChunk[0] = byte(chunkID)
		copy(rawChunk[1:], header.Payload[cursor:end])
		name, err := buildNSAnswerName(rawChunk)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, name)
		cursor = end
	}
	return chunks, nil
}

// questionTypeIsNS reports whether the packet's first question asks for NS.
func questionTypeIsNS(questionPacket []byte) bool {
	lite, err := ParsePacketLite(questionPacket)
	return err == nil && lite.HasQuestion && lite.FirstQuestion.Type == Enums.DNS_RECORD_TYPE_NS
}

// questionTypeIsCNAME reports whether the packet's first question asks for CNAME.
func questionTypeIsCNAME(questionPacket []byte) bool {
	lite, err := ParsePacketLite(questionPacket)
	return err == nil && lite.HasQuestion && lite.FirstQuestion.Type == Enums.DNS_RECORD_TYPE_CNAME
}

// buildNSVPNResponse builds a single-answer or multi-answer NS response whose
// rdata names carry rawFrame (single) or its chunk units (multi).
func buildNSVPNResponse(questionPacket []byte, answerName string, rawFrame []byte) ([]byte, error) {
	if len(rawFrame) <= maxNSUnitBytes() {
		name, err := buildNSAnswerName(rawFrame)
		if err != nil {
			return nil, err
		}
		return buildSingleNSResponsePacket(questionPacket, answerName, name)
	}

	answerNames, err := buildNSAnswerChunks(rawFrame)
	if err != nil {
		return nil, err
	}
	return BuildNSResponsePacket(questionPacket, answerName, answerNames)
}

// buildCNAMEVPNResponse builds a single-answer or chained CNAME response whose
// rdata target names carry rawFrame (single) or its chunk units (chain).
func buildCNAMEVPNResponse(questionPacket []byte, answerName string, rawFrame []byte) ([]byte, error) {
	if len(rawFrame) <= maxNSUnitBytes() {
		name, err := buildNSAnswerName(rawFrame)
		if err != nil {
			return nil, err
		}
		return buildSingleCNAMEResponsePacket(questionPacket, answerName, name)
	}

	answerNames, err := buildNSAnswerChunks(rawFrame)
	if err != nil {
		return nil, err
	}
	return BuildCNAMEChainResponsePacket(questionPacket, answerName, answerNames)
}

func buildSingleNSResponsePacket(questionPacket []byte, answerName string, answerNameWire []byte) ([]byte, error) {
	if len(questionPacket) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(questionPacket)
	questionBytes, questionCount, questionEndOffset := extractQuestionSection(questionPacket, header)
	optStart, optLen := findOPTRecordRange(questionPacket, header, questionEndOffset)

	nameBytes, err := responseAnswerNameBytes(questionPacket, answerName)
	if err != nil {
		return nil, err
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+len(nameBytes)+10+len(answerNameWire)+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	offset += copy(response[offset:], nameBytes)
	binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_NS)
	binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
	binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(answerNameWire)))
	offset += 10
	offset += copy(response[offset:], answerNameWire)

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}

	return response, nil
}

func buildSingleCNAMEResponsePacket(questionPacket []byte, answerName string, answerNameWire []byte) ([]byte, error) {
	if len(questionPacket) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(questionPacket)
	questionBytes, questionCount, questionEndOffset := extractQuestionSection(questionPacket, header)
	optStart, optLen := findOPTRecordRange(questionPacket, header, questionEndOffset)

	nameBytes, err := responseAnswerNameBytes(questionPacket, answerName)
	if err != nil {
		return nil, err
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+len(nameBytes)+10+len(answerNameWire)+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	offset += copy(response[offset:], nameBytes)
	binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_CNAME)
	binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
	binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(answerNameWire)))
	offset += 10
	offset += copy(response[offset:], answerNameWire)

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}

	return response, nil
}

func BuildNSResponsePacket(questionPacket []byte, answerName string, answerNameWires [][]byte) ([]byte, error) {
	if len(questionPacket) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(questionPacket)
	questionBytes, questionCount, questionEndOffset := extractQuestionSection(questionPacket, header)
	optStart, optLen := findOPTRecordRange(questionPacket, header, questionEndOffset)

	nameBytes, err := responseAnswerNameBytes(questionPacket, answerName)
	if err != nil {
		return nil, err
	}

	answerLen := 0
	useAnswerNameCompression := len(answerNameWires) > 1
	for i, answerNameWire := range answerNameWires {
		nameLen := len(nameBytes)
		if useAnswerNameCompression && i > 0 {
			nameLen = 2
		}
		answerLen += nameLen + 10 + len(answerNameWire)
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+answerLen+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(answerNameWires)))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	firstAnswerNameOffset := offset

	for i, answerNameWire := range answerNameWires {
		if useAnswerNameCompression && i > 0 && firstAnswerNameOffset <= 0x3FFF {
			binary.BigEndian.PutUint16(response[offset:offset+2], uint16(0xC000|firstAnswerNameOffset))
			offset += 2
		} else {
			offset += copy(response[offset:], nameBytes)
		}
		binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_NS)
		binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
		binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
		binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(answerNameWire)))
		offset += 10
		offset += copy(response[offset:], answerNameWire)
	}

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}

	return response, nil
}

// BuildCNAMEChainResponsePacket builds a multi-answer CNAME response shaped as
// one legal alias chain: record 1 owns the qname and aliases it to unit name
// 1; record i+1 owns unit name i (written as a compression pointer to the
// previous record's rdata name when that offset fits a pointer, otherwise the
// full name is repeated) and aliases it to unit name i+1. The final target is
// a terminal name carrying the last unit. Reading the rdata names in answer
// order yields the unit sequence. (RFC 1034 allows a name only one CNAME RR,
// so unlike NS answers the records cannot all own the qname.)
func BuildCNAMEChainResponsePacket(questionPacket []byte, answerName string, answerNameWires [][]byte) ([]byte, error) {
	if len(questionPacket) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}
	if len(answerNameWires) == 0 {
		return nil, ErrTXTAnswerMalformed
	}

	header := parseHeader(questionPacket)
	questionBytes, questionCount, questionEndOffset := extractQuestionSection(questionPacket, header)
	optStart, optLen := findOPTRecordRange(questionPacket, header, questionEndOffset)

	nameBytes, err := responseAnswerNameBytes(questionPacket, answerName)
	if err != nil {
		return nil, err
	}

	// Lay out the answer section before allocating: the owner of record i>0 is
	// a 2-byte pointer to the previous record's rdata name only while that
	// offset fits a pointer; otherwise the full name is repeated. rdata wire
	// lengths are fixed, so the layout is deterministic.
	ownerLens := make([]int, len(answerNameWires))
	pos := dnsHeaderSize + len(questionBytes)
	prevRData := 0
	for i, answerNameWire := range answerNameWires {
		if i == 0 || prevRData > 0x3FFF {
			ownerLens[i] = len(nameBytes)
		} else {
			ownerLens[i] = 2
		}
		pos += ownerLens[i] + 10
		prevRData = pos
		pos += len(answerNameWire)
	}
	answerLen := pos - (dnsHeaderSize + len(questionBytes))

	response := make([]byte, dnsHeaderSize+len(questionBytes)+answerLen+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(answerNameWires)))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	prevRData = 0
	for i, answerNameWire := range answerNameWires {
		if i == 0 || prevRData > 0x3FFF {
			offset += copy(response[offset:], nameBytes)
		} else {
			binary.BigEndian.PutUint16(response[offset:offset+2], uint16(0xC000|prevRData))
			offset += 2
		}
		binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_CNAME)
		binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
		binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
		binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(answerNameWire)))
		offset += 10
		prevRData = offset
		offset += copy(response[offset:], answerNameWire)
	}

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}

	return response, nil
}

func buildSingleTXTResponsePacket(questionPacket []byte, answerName string, answerPayload []byte) ([]byte, error) {
	if len(questionPacket) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(questionPacket)
	questionBytes, questionCount, questionEndOffset := extractQuestionSection(questionPacket, header)
	optStart, optLen := findOPTRecordRange(questionPacket, header, questionEndOffset)

	nameBytes, err := responseAnswerNameBytes(questionPacket, answerName)
	if err != nil {
		return nil, err
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+len(nameBytes)+10+len(answerPayload)+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	offset += copy(response[offset:], nameBytes)
	binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_TXT)
	binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
	binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(answerPayload)))
	offset += 10
	offset += copy(response[offset:], answerPayload)

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}

	return response, nil
}

func responseAnswerNameBytes(questionPacket []byte, answerName string) ([]byte, error) {
	rawName, parsedName, ok := extractFirstQuestionNameWire(questionPacket)
	if ok && sameDNSName(parsedName, answerName) {
		return rawName, nil
	}
	return encodeDNSNameStrict(answerName)
}

func extractFirstQuestionNameWire(packet []byte) ([]byte, string, bool) {
	if len(packet) < dnsHeaderSize {
		return nil, "", false
	}
	header := parseHeader(packet)
	if header.QDCount == 0 {
		return nil, "", false
	}

	name, nextOffset, err := parseName(packet, dnsHeaderSize)
	if err != nil || nextOffset <= dnsHeaderSize || nextOffset > len(packet) {
		return nil, "", false
	}

	return packet[dnsHeaderSize:nextOffset], name, true
}

func sameDNSName(a string, b string) bool {
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")
	return strings.EqualFold(a, b)
}

// decodeNSAnswerName decodes a name-rdata target (NS or CNAME) back into the
// payload unit bytes: label text (dots removed) is lowercase-base36.
func decodeNSAnswerName(name string) ([]byte, error) {
	return baseCodec.DecodeLowerBase36String(strings.ReplaceAll(name, ".", ""))
}

// extractAnswerUnits pulls tunnel payload units out of answer records. When
// any NS or CNAME answer is present, its rdata names are base36-decoded
// (fromNameType=true) and TXT answers are ignored (the server never mixes
// types in one response). Otherwise TXT answers are returned with today's
// semantics (raw or base64 text) and fromNameType=false.
func extractAnswerUnits(parsed Packet) ([][]byte, bool) {
	if len(parsed.Answers) == 0 {
		return nil, false
	}

	nameUnits := make([][]byte, 0, len(parsed.Answers))
	for _, answer := range parsed.Answers {
		if !isNameRDataRecordType(answer.Type) || answer.RDataName == "" {
			continue
		}
		decoded, err := decodeNSAnswerName(answer.RDataName)
		if err != nil || len(decoded) == 0 {
			continue
		}
		nameUnits = append(nameUnits, decoded)
	}
	if len(nameUnits) > 0 {
		return nameUnits, true
	}

	units := make([][]byte, 0, len(parsed.Answers))
	for _, answer := range parsed.Answers {
		if answer.Type != Enums.DNS_RECORD_TYPE_TXT {
			continue
		}
		raw := extractTXTBytes(answer.RData)
		if len(raw) == 0 {
			continue
		}
		units = append(units, raw)
	}
	return units, false
}

func ExtractVPNResponse(packet []byte, baseEncoded bool) (VpnProto.Packet, error) {
	parsed, err := ParsePacket(packet)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	rawAnswers, fromNameType := extractAnswerUnits(parsed)
	if len(rawAnswers) == 0 {
		return VpnProto.Packet{}, ErrTXTAnswerMissing
	}
	if fromNameType {
		// NS/CNAME units were already decoded from their name transport; the
		// base64 session flag applies to TXT answers only.
		baseEncoded = false
	}

	return assembleVPNResponse(rawAnswers, baseEncoded)
}

func DescribeResponseWithoutTunnelPayload(packet []byte) string {
	parsed, err := ParsePacket(packet)
	if err != nil {
		return fmt.Sprintf("unparseable dns response: %v", err)
	}

	qName := "-"
	if len(parsed.Questions) > 0 && parsed.Questions[0].Name != "" {
		qName = parsed.Questions[0].Name
	}

	answerKinds := summarizeRecordTypes(parsed.Answers)
	if answerKinds == "" {
		answerKinds = "none"
	}

	return fmt.Sprintf(
		"RCODE=%d QD=%d AN=%d NS=%d AR=%d QName=%s Answers=%s",
		parsed.Header.RCode,
		parsed.Header.QDCount,
		parsed.Header.ANCount,
		parsed.Header.NSCount,
		parsed.Header.ARCount,
		qName,
		answerKinds,
	)
}

func summarizeRecordTypes(records []ResourceRecord) string {
	if len(records) == 0 {
		return ""
	}

	counts := make(map[uint16]int, len(records))
	order := make([]uint16, 0, len(records))
	for _, rr := range records {
		if _, ok := counts[rr.Type]; !ok {
			order = append(order, rr.Type)
		}
		counts[rr.Type]++
	}

	parts := make([]string, 0, len(order))
	for _, rrType := range order {
		parts = append(parts, fmt.Sprintf("%s x%d", Enums.DNSRecordTypeName(rrType), counts[rrType]))
	}
	return strings.Join(parts, ", ")
}

func CalculateMaxEncodedQNameChars(domain string) int {
	domainLen := len(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domainLen <= 0 {
		return maxDNSNameLen
	}

	low := 0
	high := maxDNSNameLen
	best := 0
	for low <= high {
		mid := (low + high) / 2
		if encodedQNameLen(mid, domainLen) <= maxDNSNameLen {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return best
}

func EncodeDataToLabels(data string) string {
	if len(data) <= maxDNSLabelLen {
		return data
	}

	var b strings.Builder
	b.Grow(len(data) + len(data)/maxDNSLabelLen)
	for start := 0; start < len(data); start += maxDNSLabelLen {
		if start > 0 {
			b.WriteByte('.')
		}
		end := start + maxDNSLabelLen
		if end > len(data) {
			end = len(data)
		}
		b.WriteString(data[start:end])
	}
	return b.String()
}

func BuildTunnelQuestionName(domain string, encodedFrame string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return "", ErrInvalidName
	}
	if encodedFrame == "" {
		return domain, nil
	}

	name := EncodeDataToLabels(encodedFrame) + "." + domain
	if len(name) > maxDNSNameLen {
		return "", ErrInvalidName
	}
	return name, nil
}

func buildTXTAnswerChunks(rawFrame []byte, baseEncode bool) ([][]byte, error) {
	maxChunk := maxTXTAnswerPayload
	if baseEncode {
		maxChunk = maxTXTEncodedChunk
	}

	if len(rawFrame) == 0 {
		return [][]byte{appendLengthPrefixedTXT(nil)}, nil
	}

	if len(rawFrame) <= maxChunk {
		return [][]byte{buildTXTAnswerChunk(rawFrame, baseEncode)}, nil
	}

	header, err := VpnProto.Parse(rawFrame)
	if err != nil {
		return [][]byte{buildTXTAnswerChunk(rawFrame, baseEncode)}, nil
	}

	headerLen := header.HeaderLength
	chunk0PrefixLen := 2
	maxChunk0Data := max(maxChunk-chunk0PrefixLen-headerLen, 0)

	remaining := len(header.Payload) - maxChunk0Data
	maxChunkNData := maxChunk - 1
	totalChunks := 1
	if remaining > 0 {
		totalChunks += (remaining + maxChunkNData - 1) / maxChunkNData
	}
	if totalChunks > 255 {
		return nil, ErrTXTAnswerTooLarge
	}

	chunks := make([][]byte, 0, totalChunks)
	chunk0DataLen := min(maxChunk0Data, len(header.Payload))
	rawChunk0 := make([]byte, 2+headerLen+chunk0DataLen)
	rawChunk0[0] = 0x00
	rawChunk0[1] = byte(totalChunks)
	copy(rawChunk0[2:], rawFrame[:headerLen])
	copy(rawChunk0[2+headerLen:], header.Payload[:chunk0DataLen])

	if !baseEncode {
		chunks = append(chunks, appendLengthPrefixedTXT(rawChunk0))
		return appendRawTXTAnswerChunks(chunks, header.Payload, maxChunk0Data, maxChunkNData), nil
	}

	chunks = append(chunks, appendLengthPrefixedBase64TXT(rawChunk0))
	return appendBase64TXTAnswerChunks(chunks, header.Payload, maxChunk0Data, maxChunkNData), nil
}

func buildTXTAnswerChunk(data []byte, baseEncode bool) []byte {
	if !baseEncode {
		return appendLengthPrefixedTXT(data)
	}
	return appendLengthPrefixedBase64TXT(data)
}

func appendRawTXTAnswerChunks(chunks [][]byte, payload []byte, cursor int, maxChunkNData int) [][]byte {
	for chunkID := 1; cursor < len(payload); chunkID++ {
		end := min(cursor+maxChunkNData, len(payload))
		chunks = append(chunks, buildLengthPrefixedTXTChunk(byte(chunkID), payload[cursor:end]))
		cursor = end
	}
	return chunks
}

func appendBase64TXTAnswerChunks(chunks [][]byte, payload []byte, cursor int, maxChunkNData int) [][]byte {
	rawChunk := make([]byte, 1+maxChunkNData)
	for chunkID := 1; cursor < len(payload); chunkID++ {
		end := min(cursor+maxChunkNData, len(payload))
		rawChunk[0] = byte(chunkID)
		size := copy(rawChunk[1:], payload[cursor:end])
		chunks = append(chunks, appendLengthPrefixedBase64TXT(rawChunk[:1+size]))
		cursor = end
	}
	return chunks
}

func buildLengthPrefixedTXTChunk(prefix byte, data []byte) []byte {
	out := make([]byte, 2+len(data))
	out[0] = byte(1 + len(data))
	out[1] = prefix
	copy(out[2:], data)
	return out
}

func appendLengthPrefixedTXT(data []byte) []byte {
	if len(data) <= 255 {
		out := make([]byte, 1+len(data))
		out[0] = byte(len(data))
		copy(out[1:], data)
		return out
	}

	parts := 1 + (len(data)-1)/255
	out := make([]byte, len(data)+parts)
	writeOffset := 0
	for start := 0; start < len(data); start += 255 {
		end := min(start+255, len(data))
		out[writeOffset] = byte(end - start)
		writeOffset++
		writeOffset += copy(out[writeOffset:], data[start:end])
	}
	return out
}

func appendLengthPrefixedBase64TXT(data []byte) []byte {
	encodedLen := baseCodec.EncodedRawBase64Len(len(data))
	out := make([]byte, 1+encodedLen)
	out[0] = byte(encodedLen)
	baseCodec.EncodeRawBase64Into(out[1:], data)
	return out
}

// extractTXTBytes converts TXT rdata (one or more length-prefixed strings)
// into the concatenated string content.
func extractTXTBytes(rData []byte) []byte {
	if len(rData) == 0 {
		return nil
	}
	if int(rData[0])+1 == len(rData) {
		return rData[1:]
	}

	totalLen := 0
	for offset := 0; offset < len(rData); {
		size := int(rData[offset])
		offset++
		if size == 0 {
			continue
		}
		if offset+size > len(rData) {
			totalLen += len(rData) - offset
			break
		}
		totalLen += size
		offset += size
	}

	if totalLen == 0 {
		return nil
	}

	out := make([]byte, totalLen)
	writeOffset := 0
	for offset := 0; offset < len(rData); {
		size := int(rData[offset])
		offset++
		if size == 0 {
			continue
		}
		if offset+size > len(rData) {
			writeOffset += copy(out[writeOffset:], rData[offset:])
			break
		}
		writeOffset += copy(out[writeOffset:], rData[offset:offset+size])
		offset += size
	}
	return out
}

func assembleVPNResponse(rawAnswers [][]byte, baseEncoded bool) (VpnProto.Packet, error) {
	if len(rawAnswers) == 1 {
		raw := rawAnswers[0]
		if baseEncoded {
			decoded, err := baseCodec.DecodeRawBase64(raw)
			if err != nil {
				return VpnProto.Packet{}, err
			}
			raw = decoded
		}
		return VpnProto.ParseInflated(raw)
	}

	var chunks [256][]byte
	totalExpected := 0
	seenChunks := 0
	var header VpnProto.Packet
	headerSeen := false

	for _, raw := range rawAnswers {
		if baseEncoded {
			decoded, err := baseCodec.DecodeRawBase64(raw)
			if err != nil {
				return VpnProto.Packet{}, err
			}
			raw = decoded
		}
		if len(raw) == 0 {
			continue
		}

		if raw[0] == 0x00 {
			if len(raw) < 3 {
				return VpnProto.Packet{}, ErrTXTAnswerMalformed
			}
			totalExpected = int(raw[1])
			if totalExpected <= 0 || totalExpected > len(chunks) {
				return VpnProto.Packet{}, ErrTXTAnswerMalformed
			}
			parsed, err := VpnProto.ParseAtOffset(raw, 2)
			if err != nil {
				return VpnProto.Packet{}, err
			}
			header = parsed
			headerSeen = true
			if chunks[0] == nil {
				seenChunks++
			}
			chunks[0] = parsed.Payload
			continue
		}

		chunkID := int(raw[0])
		if chunkID >= len(chunks) {
			return VpnProto.Packet{}, ErrTXTAnswerMalformed
		}
		if chunks[chunkID] == nil {
			seenChunks++
		}
		chunks[chunkID] = raw[1:]
	}

	if !headerSeen || totalExpected <= 0 || seenChunks != totalExpected {
		return VpnProto.Packet{}, ErrTXTAnswerMalformed
	}
	for i := range totalExpected {
		if chunks[i] == nil {
			return VpnProto.Packet{}, ErrTXTAnswerMalformed
		}
	}
	for i := totalExpected; i < len(chunks); i++ {
		if chunks[i] != nil {
			return VpnProto.Packet{}, ErrTXTAnswerMalformed
		}
	}

	payloadLen := 0
	for i := range totalExpected {
		payloadLen += len(chunks[i])
	}

	payload := make([]byte, 0, payloadLen)
	for i := range totalExpected {
		payload = append(payload, chunks[i]...)
	}
	header.Payload = payload
	return VpnProto.InflatePayload(header)
}

func encodeDNSNameStrict(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}, nil
	}
	if len(name) > maxDNSNameLen {
		return nil, ErrInvalidName
	}

	encoded := make([]byte, len(name)+2)
	writeOffset := 0
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i < len(name) && name[i] != '.' {
			continue
		}
		labelLen := i - labelStart
		if labelLen == 0 || labelLen > maxDNSLabelLen {
			return nil, ErrInvalidName
		}
		encoded[writeOffset] = byte(labelLen)
		writeOffset++
		writeOffset += copy(encoded[writeOffset:], name[labelStart:i])
		labelStart = i + 1
	}
	encoded[writeOffset] = 0
	writeOffset++
	return encoded[:writeOffset], nil
}

func encodedQNameLen(encodedChars int, domainLen int) int {
	if encodedChars <= 0 {
		return domainLen
	}
	labelSplits := (encodedChars - 1) / maxDNSLabelLen
	return encodedChars + labelSplits + 1 + domainLen
}

var dnsIDCounter atomic.Uint32
var dnsIDInit sync.Once

func nextDNSRequestID() uint16 {
	dnsIDInit.Do(func() {
		var seed [4]byte
		if _, err := rand.Read(seed[:]); err == nil {
			dnsIDCounter.Store(uint32(binary.BigEndian.Uint32(seed[:])))
		}
	})
	return uint16(dnsIDCounter.Add(1))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
