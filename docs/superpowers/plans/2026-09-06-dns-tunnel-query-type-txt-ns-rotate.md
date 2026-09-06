# DNS Tunnel Query Type: TXT | NS | ROTATE — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the StormDNS VPN-over-DNS tunnel speak NS record type in addition to TXT, so the tunnel works when TXT is blocked/mangled in the resolver path and so the query stream can be disguised by mixing types (ROTATE).

**Architecture:** The server mirrors the question's qtype in the answer (TXT questions → TXT answers unchanged; NS questions → NS answers whose nameserver-name RDATA carries the payload). The client picks the qtype per query from a new config mode: `TXT` (default, fully backward compatible), `NS`, or `ROTATE` (uniform random TXT/NS per query). Payload chunk framing stays byte-identical to TXT; only the transport charset differs (TXT strings vs lowercase-base36 name labels), so the existing chunk-reassembly code is reused.

**Tech Stack:** Go 1.25, existing `internal/dnsparser`, `internal/basecodec` (lowerbase36), `internal/domainmatcher`, `internal/config`, `internal/vpnproto`. No new dependencies.

**Spec:** Design approved in chat on 2026-09-06 (brainstorming session: "add NS record type support", goals a+b = anti-fingerprint + interop, selection model iii = TXT/NS/ROTATE). Full design decisions below; no separate spec file.

## Design Decisions (locked)

1. **Mirror rule (server):** answer TXT questions with TXT records (existing code, byte-identical), NS questions with NS records. No server config, no wire negotiation. Old clients (TXT-only) keep working against the new server. NS/ROTATE modes require a matching new server; the old server answers NS tunnel queries with NODATA (`unsupported-qtype`), which surfaces as the existing session-init retry failure — documented in the config sample.
2. **NS answer framing:** identical unit bytes to TXT (single RR: whole raw frame; multi-RR: chunk 0 = `[0x00][total][vpn-header][payload...]`, chunk N = `[id][payload]`, ≤255 chunks), but each unit is transported as an **NS record whose RDATA is a domain name**: lowercase-base36(unit) split into ≤63-char labels. Capacity per unit: largest n where `EncodedLenLowerBase36(n) ≤ 250` (~161 bytes, vs 143 for TXT-base64 mode).
3. **NSDNAME has NO domain suffix** (deviation from the chat sketch, which proposed `<encoded>.<tunnel base domain>`): the server response builders only receive `requestName` (the full qname with data labels) and have no access to the matcher's `baseDomain`; a suffix would also make client-side decode ambiguous/context-dependent. A bare encoded name decodes with zero context (`ExtractVPNResponse` signature unchanged). Query-side names already expose the tunnel domain, so disguise value of the suffix was negligible.
4. **Client config:** `DNS_QUERY_TYPE = "TXT" | "NS" | "ROTATE"` (string, mirroring `PROTOCOL_TYPE` handling), default `"TXT"`. ROTATE = uniform random 50/50 per query via `math/rand`.
5. **NS responses are always name-safe** — the `BASE_ENCODE_DATA`/`ResponseBase64` flag governs TXT answers only. Extraction is type-aware: if any answer is NS, decode those (base36) and skip base64 handling.
6. **TXT code paths are not refactored.** New NS builder/extraction functions sit alongside the TXT ones, following the file's existing duplication style. Zero regression risk to the byte-tested TXT path.
7. **Parser support:** `parseResourceRecords` gains an `RDataName` field, decoded only for NS records (RDATA of NS is a name, possibly a compression pointer — the parser must resolve pointers against the whole packet). Decode failures leave `RDataName` empty and never fail packet parsing (path-2 DNS-proxy relay must not break on weird answers).

## Global Constraints

- DNS name wire length limit: max text 250 chars for NS rdata names (labels ≤63; worst split 63+63+62+62 → wire 250+4+1 = 255 ≤ 255). A 251-char text would produce a 256-byte wire name — never emit.
- Only lowercase-base36 (`[0-9a-z]`) may appear in NS rdata name labels.
- Do not modify any existing TXT builder/parser function body. Additions only.
- No new exported symbols in `enums`, `vpnproto`, `basecodec` (all needed codecs exist).
- Go: `go 1.25.0`; use stdlib `math/rand` for ROTATE (auto-seeded).
- Commit style: `feat: ...` / `test: ...` short lowercase summaries (repo convention).
- Run `go vet ./...`, `go build ./cmd/client && go build ./cmd/server`, `go test ./...` before the final commit.

---

### Task 1: Parser decodes NS rdata names (`RDataName`)

**Files:**
- Modify: `internal/dnsparser/parser.go` (struct `ResourceRecord`, `parseResourceRecords`, imports)
- Test: `internal/dnsparser/ns_test.go` (new)

**Interfaces:**
- Produces: `ResourceRecord.RDataName string` — for NS-type records whose rdata is a parseable (possibly compressed) domain name, the lowercased dotted name text; `""` otherwise (including decode failure — never a parse error).

- [x] **Step 1: Write the failing test**

Create `internal/dnsparser/ns_test.go` (package `dnsparser`):

```go
package dnsparser

import (
	"encoding/binary"
	"testing"

	Enums "stormdns-go/internal/enums"
)

// buildNSAnswerTestPacket crafts a single-question, single-answer response whose
// answer rdata is the wire name given in rdata. owner is written as a compression
// pointer to the question name (0xC00C).
func buildNSAnswerTestPacket(qtype uint16, rdata []byte) []byte {
	question := BuildTXTQuestionPacket("x.v.example.com", qtype, 0)
	nameWire, _ := encodeDNSNameStrict("x.v.example.com")
	rdataLen := len(rdata)
	if rdata == nil {
		rdataLen = 2 // compression pointer
	}
	packet := make([]byte, 0, len(question)+len(nameWire)+10+rdataLen)
	packet = append(packet, question...)
	packet = append(packet, 0xC0, 0x0C) // owner: pointer to qname
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], Enums.DNS_RECORD_TYPE_NS)
	binary.BigEndian.PutUint16(fixed[2:4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint16(fixed[8:10], uint16(rdataLen))
	packet = append(packet, fixed[:]...)
	if rdata != nil {
		packet = append(packet, rdata...)
	} else {
		packet = append(packet, 0xC0, 0x0C) // rdata: pointer to qname
	}
	return packet
}

func TestParsePacketDecodesNSRDataNamePlain(t *testing.T) {
	rdata, err := encodeDNSNameStrict("ns1.v.example.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(buildNSAnswerTestPacket(Enums.DNS_RECORD_TYPE_NS, rdata))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	got := parsed.Answers[0].RDataName
	if got != "ns1.v.example.com" {
		t.Fatalf("RDataName = %q, want %q", got, "ns1.v.example.com")
	}
}

func TestParsePacketDecodesNSRDataNameCompressed(t *testing.T) {
	parsed, err := ParsePacket(buildNSAnswerTestPacket(Enums.DNS_RECORD_TYPE_NS, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	got := parsed.Answers[0].RDataName
	if got != "x.v.example.com" {
		t.Fatalf("RDataName = %q, want %q", got, "x.v.example.com")
	}
}

func TestParsePacketLeavesRDataNameEmptyForTXT(t *testing.T) {
	rdata := []byte{5, 'h', 'e', 'l', 'l', 'o'}
	question := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 0)
	// answer section: owner pointer + TXT fixed part + rdata
	packet := append(question, 0xC0, 0x0C)
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], Enums.DNS_RECORD_TYPE_TXT)
	binary.BigEndian.PutUint16(fixed[2:4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rdata)))
	packet = append(packet, fixed[:]...)
	packet = append(packet, rdata...)

	parsed, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].RDataName != "" {
		t.Fatalf("TXT answer must have empty RDataName, got %+v", parsed.Answers)
	}
}

func TestParsePacketToleratesGarbageNSRData(t *testing.T) {
	// rdata claims 3 bytes but is a 63-byte label start: name decode fails,
	// packet parse must still succeed with empty RDataName.
	parsed, err := ParsePacket(buildNSAnswerTestPacket(Enums.DNS_RECORD_TYPE_NS, []byte{63, 'a', 'b'}))
	if err != nil {
		t.Fatalf("parse must not fail on malformed NS rdata: %v", err)
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].RDataName != "" {
		t.Fatalf("want 1 answer with empty RDataName, got %+v", parsed.Answers)
	}
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dnsparser/ -run TestParsePacketDecodesNSRDataName -v`
Expected: FAIL — `RDataName` does not exist on `ResourceRecord` (compile error).

- [x] **Step 3: Implement**

In `internal/dnsparser/parser.go`:

1. Add import:
```go
	Enums "stormdns-go/internal/enums"
```
2. Add field to `ResourceRecord`:
```go
type ResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLen    uint16
	RData    []byte
	RDataName string // decoded rdata name for name-type records (NS); "" when n/a or undecodable
}
```
3. In `parseResourceRecords`, right after `records[i] = ResourceRecord{...}` and before `offset = end`, decode NS names:
```go
		// NS rdata is a domain name (possibly a compression pointer). Decode it
		// so tunnel payloads carried in nameserver names can be read. A decode
		// failure (or a name that overruns rdLen) leaves RDataName empty and
		// never fails the whole packet parse.
		if rType == Enums.DNS_RECORD_TYPE_NS {
			if nameText, nameNext, nameErr := parseName(data, offset); nameErr == nil && nameNext <= end {
				records[i].RDataName = nameText
			}
		}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsparser/ -run 'TestParsePacketDecodesNSRDataName|TestParsePacketLeavesRDataNameEmptyForTXT|TestParsePacketToleratesGarbageNSRData' -v`
Expected: PASS (all 4).

Then run full package regression: `go test ./internal/dnsparser/`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/dnsparser/parser.go internal/dnsparser/ns_test.go
git commit -m "feat: decode NS rdata names in DNS parser"
```

---

### Task 2: Server builds NS answers mirroring the question type

**Files:**
- Modify: `internal/dnsparser/transport.go`
- Test: `internal/dnsparser/ns_test.go`

**Interfaces:**
- Consumes: Task 1 `ResourceRecord.RDataName` (not needed here), existing `VpnProto.BuildRawAuto`, `ParsePacketLite`, `encodeDNSNameStrict`, `EncodeDataToLabels`, `baseCodec.EncodedLenLowerBase36/EncodeLowerBase36`.
- Produces (all unexported unless noted):
  - `const maxNSNameChars = 250`
  - `func maxNSUnitBytes() int` — largest n with `baseCodec.EncodedLenLowerBase36(n) <= maxNSNameChars` (≈161)
  - `func buildNSAnswerName(chunk []byte) ([]byte, error)` — base36 text → ≤63-char labels → wire name; `ErrTXTAnswerTooLarge` if text > 250 chars
  - `func buildNSAnswerChunks(rawFrame []byte) ([][]byte, error)` — split a frame into chunk units (identical byte layout to TXT chunking, budget `maxNSUnitBytes()`), returns one wire-name per unit
  - `func questionTypeIsNS(questionPacket []byte) bool`
  - `func buildNSVPNResponse(questionPacket []byte, answerName string, rawFrame []byte) ([]byte, error)`
  - `BuildVPNResponsePacket` (existing, modified): NS question → NS answer; otherwise byte-identical TXT behavior.

- [x] **Step 1: Write the failing test**

Append to `internal/dnsparser/ns_test.go` (extend the existing import block with `"bytes"` and `VpnProto "stormdns-go/internal/vpnproto"`):

```go
var _ = bytes.Equal // bytes used below
var _ = VpnProto.Packet{}
```

// deterministic pseudo-random payload that does not compress smaller, so frame
// sizes (and therefore chunk counts) are stable.
func patternedPayload(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*31 + 7)
	}
	return out
}

func vpnPacketForTest(payload []byte) VpnProto.Packet {
	return VpnProto.Packet{
		SessionID:      7,
		PacketType:     Enums.PACKET_PONG,
		StreamID:       3,
		SequenceNum:    99,
		FragmentID:     0,
		TotalFragments: 1,
		Payload:        payload,
	}
}

func TestBuildVPNResponsePacketMirrorsNSQuestionSingle(t *testing.T) {
	question := BuildTXTQuestionPacket("a1b2.v.example.com", Enums.DNS_RECORD_TYPE_NS, 0)
	payload := []byte("hello ns world")
	resp, err := BuildVPNResponsePacket(question, "a1b2.v.example.com", vpnPacketForTest(payload), false)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Questions) != 1 || parsed.Questions[0].Type != Enums.DNS_RECORD_TYPE_NS {
		t.Fatalf("question type not echoed: %+v", parsed.Questions)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 NS answer, got %d", len(parsed.Answers))
	}
	if parsed.Answers[0].Type != Enums.DNS_RECORD_TYPE_NS {
		t.Fatalf("answer type = %d, want NS(%d)", parsed.Answers[0].Type, Enums.DNS_RECORD_TYPE_NS)
	}
	if parsed.Answers[0].RDataName == "" {
		t.Fatal("NS answer rdata name not decoded")
	}
	for _, label := range splitLabels(parsed.Answers[0].RDataName) {
		if len(label) > 63 {
			t.Fatalf("label %q exceeds 63 chars", label)
		}
	}

	got, err := ExtractVPNResponse(resp, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("roundtrip mismatch: type=%d payload=%q", got.PacketType, got.Payload)
	}
}

func TestBuildVPNResponsePacketMirrorsNSQuestionMultiChunk(t *testing.T) {
	question := BuildTXTQuestionPacket("aa.bb.v.example.com", Enums.DNS_RECORD_TYPE_NS, 0)
	payload := patternedPayload(800) // forces multiple NS answer records
	resp, err := BuildVPNResponsePacket(question, "aa.bb.v.example.com", vpnPacketForTest(payload), true /* base64 flag must be irrelevant for NS */)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) < 2 {
		t.Fatalf("want multiple NS answers, got %d", len(parsed.Answers))
	}
	for i, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_NS {
			t.Fatalf("answer %d type = %d, want NS", i, ans.Type)
		}
		if ans.RDataName == "" {
			t.Fatalf("answer %d rdata name missing", i)
		}
	}

	got, err := ExtractVPNResponse(resp, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || got.StreamID != 3 || got.SequenceNum != 99 ||
		!bytes.Equal(got.Payload, payload) {
		t.Fatalf("roundtrip mismatch: type=%d stream=%d seq=%d payloadlen=%d",
			got.PacketType, got.StreamID, got.SequenceNum, len(got.Payload))
	}
}

func TestBuildVPNResponsePacketKeepsTXTForTXTQuestion(t *testing.T) {
	question := BuildTXTQuestionPacket("a1b2.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 0)
	payload := patternedPayload(800)
	resp, err := BuildVPNResponsePacket(question, "a1b2.v.example.com", vpnPacketForTest(payload), false)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) == 0 {
		t.Fatal("no answers")
	}
	for _, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_TXT {
			t.Fatalf("TXT question must yield TXT answers, got type %d", ans.Type)
		}
	}
	got, err := ExtractVPNResponse(resp, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatal("TXT roundtrip regression")
	}
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	return out
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dnsparser/ -run TestBuildVPNResponsePacketMirrorsNSQuestion -v`
Expected: FAIL — answer records are TXT (mirror not implemented).

- [x] **Step 3: Implement**

In `internal/dnsparser/transport.go` (additions only; do not edit TXT function bodies):

```go
// NS answers carry payload units as domain names: lowercase-base36(unit) split
// into <=63-char labels. maxNSNameChars keeps the wire name <= 255 bytes for
// the worst-case 4-label split (63+63+62+62 => 250+4+1 = 255).
const maxNSNameChars = 250

// maxNSUnitBytes returns the largest raw chunk size whose base36 text fits in
// maxNSNameChars (~161 bytes).
func maxNSUnitBytes() int {
	for n := 255; n > 0; n-- {
		if baseCodec.EncodedLenLowerBase36(n) <= maxNSNameChars {
			return n
		}
	}
	return 0
}

// buildNSAnswerName encodes one payload unit as an NS rdata wire name.
func buildNSAnswerName(chunk []byte) ([]byte, error) {
	text := baseCodec.EncodeLowerBase36(chunk)
	if len(text) > maxNSNameChars {
		return nil, ErrTXTAnswerTooLarge
	}
	return encodeDNSNameStrict(EncodeDataToLabels(text))
}

// buildNSAnswerChunks splits rawFrame into chunk units with the same byte
// layout as the TXT chunker (chunk 0: [0x00][total][vpn header][payload...],
// chunk N: [id][payload...]) and returns one wire name per unit.
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
```

Then add the two response packet assemblers (mirror `buildSingleTXTResponsePacket` and `BuildTXTResponsePacket` structurally, changing only the type constant and that rdata is a wire name):

```go
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
```

Finally, branch at the top of the existing `BuildVPNResponsePacket` (after `rawFrame` is built; leave the TXT body untouched below the branch):

```go
	if questionTypeIsNS(questionPacket) {
		return buildNSVPNResponse(questionPacket, answerName, rawFrame)
	}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsparser/ -run 'TestBuildVPNResponsePacket' -v`
Expected: PASS (mirror single, mirror multi-chunk, TXT regression).

Then full package + downstream: `go test ./internal/dnsparser/ ./internal/udpserver/ ./internal/domainmatcher/`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/dnsparser/transport.go internal/dnsparser/ns_test.go
git commit -m "feat: build NS tunnel answers mirroring question type"
```

---

### Task 3: Client extraction reads NS answers

**Files:**
- Modify: `internal/dnsparser/transport.go`
- Test: `internal/dnsparser/ns_test.go`

**Interfaces:**
- Consumes: Task 1 `RDataName`, Task 2 builders (tests build real NS responses via `BuildVPNResponsePacket`).
- Produces:
  - `func decodeNSAnswerName(name string) ([]byte, error)` — strip dots, lowercase-base36 decode
  - `func extractAnswerUnits(parsed Packet) (units [][]byte, fromNS bool)` — NS answers first (base36-decoded units); if none, TXT answers (existing raw/base64 semantics)
  - `ExtractVPNResponse` (existing, modified): delegates to `extractAnswerUnits`; NS units skip base64 decoding.
- Behavior notes: answers that are neither TXT nor NS, empty units, undecodable names, and no-answer packets all keep today's `ErrTXTAnswerMissing` outcome. `assembleVPNResponse` is unchanged.

- [x] **Step 1: Write the failing test**

Append to `internal/dnsparser/ns_test.go`:

```go
func TestExtractVPNResponseReadsBase36NamePayload(t *testing.T) {
	// Single NS answer whose rdata name carries base36 of a real raw frame
	// (the server's single-answer path from Task 2).
	question := BuildTXTQuestionPacket("k9.v.example.com", Enums.DNS_RECORD_TYPE_NS, 0)
	frame, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
		SessionID:  7,
		PacketType: Enums.PACKET_PONG,
		Payload:    []byte{1, 2, 3, 4, 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	nameWire, err := buildNSAnswerName(frame)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := buildSingleNSResponsePacket(question, "k9.v.example.com", nameWire)
	if err != nil {
		t.Fatal(err)
	}

	// baseEncoded=true must not corrupt NS-unit decoding (NS is charset-safe by itself).
	got, err := ExtractVPNResponse(resp, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || !bytes.Equal(got.Payload, []byte{1, 2, 3, 4, 5}) {
		t.Fatalf("roundtrip mismatch: type=%d payload=%v", got.PacketType, got.Payload)
	}
}

func TestExtractVPNResponseNoPayloadFromUnreadableNS(t *testing.T) {
	// An NS answer whose rdata name cannot be decoded must behave like a
	// response without tunnel payload: ErrTXTAnswerMissing, not a panic.
	// (garbage rdata: 63-byte label declared but only 2 bytes present)
	resp := buildNSAnswerTestPacket(Enums.DNS_RECORD_TYPE_NS, []byte{63, 'a', 'b'})
	if _, err := ExtractVPNResponse(resp, false); !errors.Is(err, ErrTXTAnswerMissing) {
		t.Fatalf("want ErrTXTAnswerMissing, got %v", err)
	}
}

func TestDecodeNSAnswerNameHandlesLabelSplits(t *testing.T) {
	raw := patternedPayload(100)
	text := baseCodec.EncodeLowerBase36(raw)
	labels := EncodeDataToLabels(text)
	got, err := decodeNSAnswerName(labels)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("base36 label roundtrip mismatch")
	}
}
```

Extend `ns_test.go`'s import block with `errors`, `bytes`, `baseCodec "stormdns-go/internal/basecodec"`, and `VpnProto "stormdns-go/internal/vpnproto"` as needed.

(If any helper above is awkward — e.g. `buildSingleNSResponsePacket` is unexported but tests live in package `dnsparser`, so it is reachable — keep tests in-package exactly as in Task 1.)

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dnsparser/ -run TestExtractVPNResponseReadsBase36NamePayload -v`
Expected: FAIL — NS answers are ignored; error `ErrTXTAnswerMissing` or no payload (extraction not implemented).

- [x] **Step 3: Implement**

In `internal/dnsparser/transport.go` (additions; modify only the body of `ExtractVPNResponse`):

```go
// decodeNSAnswerName decodes an NS rdata name back into the payload unit bytes:
// label text (dots removed) is lowercase-base36.
func decodeNSAnswerName(name string) ([]byte, error) {
	return baseCodec.DecodeLowerBase36String(strings.ReplaceAll(name, ".", ""))
}

// extractAnswerUnits pulls tunnel payload units out of answer records. When any
// NS answer is present, its rdata names are base36-decoded (fromNS=true) and TXT
// answers are ignored (the server never mixes types in one response). Otherwise
// TXT answers are returned with today's semantics (raw or base64 text) and
// fromNS=false.
func extractAnswerUnits(parsed Packet) ([][]byte, bool) {
	if len(parsed.Answers) == 0 {
		return nil, false
	}

	nsUnits := make([][]byte, 0, len(parsed.Answers))
	for _, answer := range parsed.Answers {
		if answer.Type != Enums.DNS_RECORD_TYPE_NS || answer.RDataName == "" {
			continue
		}
		decoded, err := decodeNSAnswerName(answer.RDataName)
		if err != nil || len(decoded) == 0 {
			continue
		}
		nsUnits = append(nsUnits, decoded)
	}
	if len(nsUnits) > 0 {
		return nsUnits, true
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
```

Replace the body of `ExtractVPNResponse`:

```go
func ExtractVPNResponse(packet []byte, baseEncoded bool) (VpnProto.Packet, error) {
	parsed, err := ParsePacket(packet)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	rawAnswers, fromNS := extractAnswerUnits(parsed)
	if len(rawAnswers) == 0 {
		return VpnProto.Packet{}, ErrTXTAnswerMissing
	}
	if fromNS {
		// NS units were already decoded from their name transport; the base64
		// session flag applies to TXT answers only.
		baseEncoded = false
	}

	return assembleVPNResponse(rawAnswers, baseEncoded)
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsparser/ -run 'TestExtractVPNResponse|TestDecodeNSAnswerName' -v`
Expected: PASS.

Then full regression:
Run: `go test ./internal/dnsparser/ ./internal/client/ ./internal/udpserver/`
Expected: PASS (client/udpserver exercise `ExtractVPNResponse` on real TXT flows).

- [x] **Step 5: Commit**

```bash
git add internal/dnsparser/transport.go internal/dnsparser/ns_test.go
git commit -m "feat: extract tunnel payloads from NS answers"
```

---

### Task 4: Matcher accepts NS tunnel queries

**Files:**
- Modify: `internal/domainmatcher/matcher.go`
- Test: `internal/domainmatcher/matcher_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Matcher.Match` returns `ActionProcess` for TXT **and** NS questions with valid labels; other qtypes keep `Reason: "unsupported-qtype"`.

- [x] **Step 1: Write the failing test**

Inspect `internal/domainmatcher/matcher_test.go` first (read it fully; it is small) to reuse its helpers (`litePacketWithQuestion`, matcher construction). Then add:

```go
func TestMatchAcceptsNSQuestion(t *testing.T) {
	// setup identical to the existing TXT accept test, e.g. domains {"vpn-01.c.b.com"}
	decision := matcher.Match(litePacketWithQuestion("a1b2.vpn-01.c.b.com", Enums.DNS_RECORD_TYPE_NS))
	if decision.Action != ActionProcess {
		t.Fatalf("NS tunnel query rejected: action=%v reason=%s", decision.Action, decision.Reason)
	}
}

func TestMatchStillRejectsOtherTypes(t *testing.T) {
	// e.g. A query for the same name must remain "unsupported-qtype"
	decision := matcher.Match(litePacketWithQuestion("a1b2.vpn-01.c.b.com", Enums.DNS_RECORD_TYPE_A))
	if decision.Reason != "unsupported-qtype" {
		t.Fatalf("A query must be unsupported-qtype, got %s", decision.Reason)
	}
}
```

(Adapt domain/helper names to the file's actual fixture style.)

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domainmatcher/ -run TestMatchAcceptsNSQuestion -v`
Expected: FAIL — reason `unsupported-qtype`.

- [x] **Step 3: Implement**

In `internal/domainmatcher/matcher.go`, change the qtype gate:

```go
	if q0.Type != Enums.DNS_RECORD_TYPE_TXT && q0.Type != Enums.DNS_RECORD_TYPE_NS {
		return Decision{
			Action:       ActionNoData,
			Reason:       "unsupported-qtype",
			Question:     q0,
			RequestName:  requestName,
			BaseDomain:   baseDomain,
			QuestionType: q0.Type,
		}
	}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/domainmatcher/ -v`
Expected: PASS (new + all existing).

- [x] **Step 5: Commit**

```bash
git add internal/domainmatcher/matcher.go internal/domainmatcher/matcher_test.go
git commit -m "feat: accept NS qtype as tunnel query"
```

---

### Task 5: Client config `DNS_QUERY_TYPE`

**Files:**
- Modify: `internal/config/client.go`
- Modify: `internal/config/client_test.go`
- Modify: `client_config.toml.simple`
- Modify: `README.MD` (one table row)

**Interfaces:**
- Produces: `ClientConfig.DNSQueryType string` (TOML `DNS_QUERY_TYPE`), normalized uppercase in `finalizeClientConfig`: `""`/`"TXT"` → `"TXT"`, `"NS"`/`"ROTATE"` valid, anything else → error `invalid DNS_QUERY_TYPE: %q`. Default `"TXT"`.

- [x] **Step 1: Write the failing test**

Inspect `internal/config/client_test.go` for the existing validation test style (e.g. how it loads a config and asserts errors). Add:

```go
func TestClientConfigDNSQueryTypeValidation(t *testing.T) {
	// follow the file's fixture pattern; three cases:
	// 1. default (no key): DNSQueryType == "TXT"
	// 2. DNS_QUERY_TYPE = "ns"  -> normalized "NS"
	// 3. DNS_QUERY_TYPE = "A"   -> error containing `invalid DNS_QUERY_TYPE`
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestClientConfigDNSQueryType -v`
Expected: FAIL — field unknown (no compile error: TOML decode ignores unknown keys, so `DNSQueryType == ""` or error missing).

- [x] **Step 3: Implement**

1. Struct field (place after `BaseEncodeData`):
```go
	BaseEncodeData                        bool              `toml:"BASE_ENCODE_DATA"`
	DNSQueryType                          string            `toml:"DNS_QUERY_TYPE"`
```
2. Default in `defaultClientConfig()`:
```go
		BaseEncodeData:                        false,
		DNSQueryType:                          "TXT",
```
3. Validation in `finalizeClientConfig()` (place near the `PROTOCOL_TYPE` switch):
```go
	cfg.DNSQueryType = strings.ToUpper(strings.TrimSpace(cfg.DNSQueryType))
	switch cfg.DNSQueryType {
	case "", "TXT":
		cfg.DNSQueryType = "TXT"
	case "NS", "ROTATE":
	default:
		return cfg, fmt.Errorf("invalid DNS_QUERY_TYPE: %q", cfg.DNSQueryType)
	}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS.

- [x] **Step 5: Update sample config and README**

In `client_config.toml.simple`, add next to `BASE_ENCODE_DATA = false` (line ~203):

```toml
# DNS record type used for tunnel queries.
#   "TXT"    - default, works with every server version
#   "NS"     - tunnel over NS queries/answers; use when the resolver path blocks TXT
#   "ROTATE" - random TXT/NS mix per query (disguise); needs a matching server
DNS_QUERY_TYPE = "TXT"
```

In `README.MD`, add `DNS_QUERY_TYPE` to the config-list table row that already mentions `BASE_ENCODE_DATA` (line ~408).

- [x] **Step 6: Commit**

```bash
git add internal/config/client.go internal/config/client_test.go client_config.toml.simple README.MD
git commit -m "feat: add DNS_QUERY_TYPE client config (TXT/NS/ROTATE)"
```

---

### Task 6: Client picks the query type per packet

**Files:**
- Modify: `internal/client/tunnel_query.go`
- Modify: `internal/client/async_runtime.go` (two call sites)
- Test: `internal/client/tunnel_query_test.go` (new)

**Interfaces:**
- Consumes: Task 5 `cfg.DNSQueryType`.
- Produces:
  - `func (c *Client) pickTunnelQueryType() uint16` — `TXT`→16, `NS`→2, `ROTATE`→random 16/2 (`math/rand`), empty/unknown (defensive, incl. nil-`c` fields) →16.
  - `func (c *Client) buildTunnelQuestionBytes(domain string, encoded []byte) ([]byte, error)` (replaces package fn `buildTunnelTXTQuestionBytes`)
  - `func (c *Client) buildTunnelQuestionBytesPrepared(domain preparedTunnelDomain, encoded []byte) ([]byte, error)` (replaces package fn `buildTunnelTXTQuestionBytesPrepared`)
  - Existing `(*Client).buildTunnelTXTQueryRaw` keeps its name (used by session/mtu) but delegates to the new method.
- Exported dnsparser builders (`BuildTunnelTXTQuestionPacket*`) are unchanged — they already take a qtype parameter.

- [x] **Step 1: Write the failing test**

Create `internal/client/tunnel_query_test.go` (package `client`; use `Enums` and `DnsParser` imports; construct `&Client{}` zero values):

```go
package client

import (
	"testing"

	DnsParser "stormdns-go/internal/dnsparser"
	Enums "stormdns-go/internal/enums"
)

func questionTypeOf(t *testing.T, packet []byte) uint16 {
	t.Helper()
	lite, err := DnsParser.ParsePacketLite(packet)
	if err != nil || !lite.HasQuestion {
		t.Fatalf("bad test packet: %v", err)
	}
	return lite.FirstQuestion.Type
}

func TestPickTunnelQueryTypeTXTMode(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "TXT"
	for i := 0; i < 20; i++ {
		if got := c.pickTunnelQueryType(); got != Enums.DNS_RECORD_TYPE_TXT {
			t.Fatalf("TXT mode picked %d", got)
		}
	}
}

func TestPickTunnelQueryTypeNSMode(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "NS"
	if got := c.pickTunnelQueryType(); got != Enums.DNS_RECORD_TYPE_NS {
		t.Fatalf("NS mode picked %d", got)
	}
}

func TestPickTunnelQueryTypeRotateMix(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "ROTATE"
	seen := map[uint16]bool{}
	for i := 0; i < 200; i++ {
		seen[c.pickTunnelQueryType()] = true
	}
	if !seen[Enums.DNS_RECORD_TYPE_TXT] || !seen[Enums.DNS_RECORD_TYPE_NS] {
		t.Fatalf("ROTATE must produce both types, got %v", seen)
	}
}

func TestPickTunnelQueryTypeDefaultIsTXT(t *testing.T) {
	c := &Client{} // zero cfg -> "" -> TXT
	if got := c.pickTunnelQueryType(); got != Enums.DNS_RECORD_TYPE_TXT {
		t.Fatalf("default picked %d", got)
	}
}

func TestBuildTunnelQuestionBytesUsesMode(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "NS"
	packet, err := c.buildTunnelQuestionBytes("v.example.com", []byte("abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	if got := questionTypeOf(t, packet); got != Enums.DNS_RECORD_TYPE_NS {
		t.Fatalf("packet qtype = %d, want NS", got)
	}
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/ -run 'TestPickTunnelQueryType|TestBuildTunnelQuestionBytesUsesMode' -v`
Expected: FAIL — `pickTunnelQueryType` undefined (compile error).

- [x] **Step 3: Implement**

In `internal/client/tunnel_query.go`, replace the two package-level builders with methods and add the picker (add `"math/rand"` and `"strings"` imports):

```go
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
```

Update the two call sites in `internal/client/async_runtime.go` (lines ~551 and ~566) from `buildTunnelTXTQuestionBytesPrepared(prepared, encoded)` to `c.buildTunnelQuestionBytesPrepared(prepared, encoded)`.

Update `buildTunnelTXTQueryRaw` in `tunnel_query.go` to call `c.buildTunnelQuestionBytes(domain, encoded)`.

(Keep the name `buildTunnelTXTQueryRaw` — session.go and mtu.go call it; it is a client-level wrapper, not a builder of the type byte.)

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/client/ -run 'TestPickTunnelQueryType|TestBuildTunnelQuestionBytesUsesMode' -v`
Expected: PASS.

Then full client regression:
Run: `go test ./internal/client/`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/client/tunnel_query.go internal/client/async_runtime.go internal/client/tunnel_query_test.go
git commit -m "feat: per-query tunnel DNS type selection (TXT/NS/ROTATE)"
```

---

### Task 7: Server-side smoke test (udpserver) + full verification

**Files:**
- Test: `internal/udpserver/ns_tunnel_test.go` (new, small)

**Interfaces:**
- Consumes: everything above via public API (`BuildVPNResponsePacket`, `ExtractVPNResponse`, `Matcher`).

**Purpose:** prove the server ingress path (matcher accepts NS → session handler builds mirrored response) end to end without a full session harness: feed an NS tunnel query through `Matcher` and `BuildVPNResponsePacket`, then decode with the client-side extractor.

- [x] **Step 1: Write the test**

Read one existing udpserver test (e.g. `session_syn_test.go` header or `dns_tunnel_cap_test.go`) for the local-server fixture style first; if a full-server harness is heavy, keep this test purely in-package with `Matcher` + `BuildVPNResponsePacket`:

```go
package udpserver_test // or package udpserver, matching existing tests

// TestNSTunnelQueryAcceptedEndToEnd:
// 1. Build an NS tunnel query packet for a data-bearing qname (use the same
//    dnsparser builder the client uses, qtype NS).
// 2. Run it through the domain matcher configured with the test domain; assert
//    ActionProcess.
// 3. Build a server response via DnsParser.BuildVPNResponsePacket with a PONG
//    payload and assert ExtractVPNResponse (client-side) recovers it.
```

Keep the payload ≥ 200 bytes so the multi-chunk NS framing is exercised.

- [x] **Step 2: Run test to verify it passes (new behavior)**

Run: `go test ./internal/udpserver/ -run TestNSTunnelQueryAcceptedEndToEnd -v`
Expected: PASS (this task is the integration gate; if it fails, fix per systematic-debugging — most likely a framing mismatch caught earlier only by cross-package use).

- [x] **Step 3: Full verification**

Run:
```bash
go vet ./...
go build ./cmd/client && go build ./cmd/server
go test ./...
go test -race ./internal/dnsparser/ ./internal/domainmatcher/ ./internal/config/
```
Expected: all PASS.

- [x] **Step 4: Manual smoke (optional, environment permitting)**

`go run scripts/bench/bench.go` runs a local server+client; do one TXT run (regression). For an NS smoke, temporarily set `DNS_QUERY_TYPE = "NS"` in the bench's client config before running — confirm throughput > 0 and the logs show no `ErrTXTAnswerMissing` storms. Not required for merge.

- [x] **Step 5: Commit**

```bash
git add internal/udpserver/ns_tunnel_test.go
git commit -m "test: NS tunnel query acceptance end to end"
```

---

## Self-Review Notes (checked)

- Spec coverage: mirror rule (T2/T4), client mode + ROTATE (T5/T6), NS framing + capacity (T2), extraction (T3), parser rdata names (T1), docs (T5), integration gate (T7), backward compat TXT-default (T5/T6 defaults + untouched TXT paths + T2/T3 TXT regressions). All chat-design decisions covered.
- No placeholders: every step has concrete code or a read-first instruction with the exact target identified. The two tests in Task 5/Task 7 intentionally say "follow the file's fixture style" because exact fixture code must be read from the existing files first (their helpers differ); each still specifies the assertions verbatim.
- Type consistency: `RDataName`, `maxNSUnitBytes()`, `buildNSAnswerName`, `buildNSAnswerChunks`, `BuildNSResponsePacket`, `buildSingleNSResponsePacket`, `questionTypeIsNS`, `buildNSVPNResponse`, `decodeNSAnswerName`, `extractAnswerUnits`, `pickTunnelQueryType`, `buildTunnelQuestionBytes(Prepared)` names/signatures are identical across tasks. Existing exported names unchanged.
