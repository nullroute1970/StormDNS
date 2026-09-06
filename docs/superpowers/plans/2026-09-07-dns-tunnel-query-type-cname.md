# DNS Tunnel Query Type: CNAME — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the StormDNS VPN-over-DNS tunnel speak CNAME record type in addition to TXT and NS, so the tunnel works when TXT/NS are blocked, mangled, or fingerprinted in the resolver path and so the query stream can be disguised by mixing all three types (ROTATE).

**Architecture:** Same mirror rule as NS: the server answers CNAME questions with CNAME answers. Because RFC 1034/2181 allow a name only one CNAME RR, multi-unit CNAME answers are shaped as one legal alias **chain** — `qname → P1`, `P1 → P2`, …, `P(m−1) → Pm` — where each Pi is the lowercase-base36 wire name of chunk unit i (identical unit bytes and chunking to the NS transport, so client reassembly is reused). The client picks the qtype per query from config: `TXT` (default), `NS`, `CNAME`, or `ROTATE` (uniform random TXT/NS/CNAME).

**Tech Stack:** Go (repo `go.mod`), existing `internal/dnsparser`, `internal/basecodec` (lowerbase36), `internal/domainmatcher`, `internal/config`, `internal/vpnproto`. No new dependencies.

**Spec:** Design approved in chat on 2026-09-07 (brainstorming session: "add CNAME record type support"; scope = third tunnel transport type mirroring NS; ROTATE = uniform TXT/NS/CNAME; multi-unit framing = RFC-shaped CNAME chain). Full design decisions below; no separate spec file.

## Design Decisions (locked)

1. **Mirror rule (server):** TXT questions → TXT answers (existing, byte-identical), NS questions → NS answers (existing), CNAME questions → CNAME answers. No server config, no wire negotiation. Old clients (TXT/NS only) keep working against the new server. CNAME/ROTATE-with-CNAME modes require a matching new server; an old server answers CNAME tunnel queries with NODATA (`unsupported-qtype`), surfacing as the existing session-init retry failure — documented in the config sample and README.
2. **CNAME answer framing:** identical unit bytes to TXT/NS (single RR: whole raw frame; multi-RR: chunk 0 = `[0x00][total][vpn-header][payload...]`, chunk N = `[id][payload]`, ≤255 chunks), each unit transported as a domain name: lowercase-base36(unit) split into ≤63-char labels (`maxNSNameChars` = 250 text chars, ~161 raw bytes per unit — same budget as NS). The name-wire builders (`buildNSAnswerName`, `buildNSAnswerChunks`, `maxNSUnitBytes`) are reused verbatim.
3. **CNAME chain shape (multi-unit only):** RFC 1034 §3.6.2 forbids more than one CNAME RR per owner name, so records cannot all own the qname the way NS answers do. Instead RR 1 owns the qname and aliases it to P1 (unit 1); RR i+1 owns Pi (the previous rdata name) and aliases it to P(i+1). The owner of RR i+1 is written as a 2-byte compression pointer to the previous record's rdata when that offset fits (≤ 0x3FFF), otherwise the full name is repeated. The client reads CNAME rdata names in answer order — decode is unchanged from NS. The final target is a terminal name; unresolvable terminal targets are an accepted property of CNAME transport (single-RR CNAME answers already have it).
4. **Client config:** `DNS_QUERY_TYPE = "TXT" | "NS" | "CNAME" | "ROTATE"`, default `"TXT"`. ROTATE = uniform random 1/3 TXT/NS/CNAME per query via `math/rand`.
5. **CNAME/NS name transport is always name-safe** — the `BASE_ENCODE_DATA`/`ResponseBase64` flag governs TXT answers only. Extraction is type-aware: if any NS or CNAME answer is present, decode those rdata names (base36) and skip base64 handling.
6. **Existing TXT code paths are not refactored, and existing NS code is not modified** (comment-only touches allowed). New CNAME builders/extraction branches sit alongside the NS ones. The one shared addition is a tiny `isNameRDataRecordType` helper in the parser.
7. **Parser support:** `parseResourceRecords` decodes `RDataName` for CNAME records in addition to NS (RDATA is a name, possibly a compression pointer — resolve against the whole packet). Decode failures leave `RDataName` empty and never fail packet parsing (path-2 DNS-proxy relay must not break on weird answers).
8. **Matcher acceptance:** CNAME qtype joins TXT/NS in the `ActionProcess` gate (mirror of NS commit d0ffbcb). `policy.go` (`IsSupportedTunnelDNSQuery`) already accepts CNAME — no change.

## Global Constraints

- DNS name wire length limit: max text 250 chars for rdata names (labels ≤63; worst split 63+63+62+62 → wire 250+4+1 = 255 ≤ 255). Never emit a 251-char text.
- Only lowercase-base36 (`[0-9a-z]`) may appear in CNAME rdata name labels and chain owner names.
- Do not modify any existing TXT builder/parser function body. Additions only; NS function bodies untouched except comment lines.
- No new exported symbols in `enums`, `vpnproto`, `basecodec`.
- Use stdlib `math/rand` for ROTATE (auto-seeded).
- Commit style: `feat: ...` / `test: ...` / `docs: ...` short lowercase summaries (repo convention).
- Run `go vet ./...`, `go build ./cmd/client && go build ./cmd/server`, `go test ./...` before the final commit.

---

### Task 1: Parser decodes CNAME rdata names (`RDataName`)

**Files:**
- Modify: `internal/dnsparser/parser.go` (struct comment line ~60, `parseResourceRecords` NS-decode block ~lines 244-256, new helper near it)
- Test: `internal/dnsparser/cname_test.go` (new)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `func isNameRDataRecordType(recordType uint16) bool` — true for NS and CNAME (record types whose rdata is a wire-format name)
  - `ResourceRecord.RDataName` is now populated for NS **and** CNAME records: lowercased dotted name text; `""` when n/a or undecodable (never a parse error).

- [ ] **Step 1: Write the failing test**

Create `internal/dnsparser/cname_test.go` (package `dnsparser`):

```go
package dnsparser

import (
	"encoding/binary"
	"testing"

	Enums "stormdns-go/internal/enums"
)

// buildCNAMEAnswerTestPacket crafts a single-question, single-answer response
// whose answer type is CNAME and whose rdata is the wire name given in rdata.
// The owner is written as a compression pointer to the question name (0xC00C).
func buildCNAMEAnswerTestPacket(t *testing.T, rdata []byte) []byte {
	t.Helper()
	question := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_CNAME, 0)
	rdataLen := len(rdata)
	if rdata == nil {
		rdataLen = 2 // compression pointer
	}
	packet := make([]byte, 0, len(question)+2+10+rdataLen)
	packet = append(packet, question...)
	packet = append(packet, 0xC0, 0x0C) // owner: pointer to qname
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], Enums.DNS_RECORD_TYPE_CNAME)
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

func TestParsePacketDecodesCNAMERDataNamePlain(t *testing.T) {
	rdata, err := encodeDNSNameStrict("cdn1.v.example.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(buildCNAMEAnswerTestPacket(t, rdata))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	if got := parsed.Answers[0].RDataName; got != "cdn1.v.example.com" {
		t.Fatalf("RDataName = %q, want %q", got, "cdn1.v.example.com")
	}
}

func TestParsePacketDecodesCNAMERDataNameCompressed(t *testing.T) {
	parsed, err := ParsePacket(buildCNAMEAnswerTestPacket(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	if got := parsed.Answers[0].RDataName; got != "x.v.example.com" {
		t.Fatalf("RDataName = %q, want %q", got, "x.v.example.com")
	}
}

func TestParsePacketToleratesGarbageCNAMERData(t *testing.T) {
	// rdata claims 3 bytes but is a 63-byte label start: name decode fails,
	// packet parse must still succeed with empty RDataName.
	parsed, err := ParsePacket(buildCNAMEAnswerTestPacket(t, []byte{63, 'a', 'b'}))
	if err != nil {
		t.Fatalf("parse must not fail on malformed CNAME rdata: %v", err)
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].RDataName != "" {
		t.Fatalf("want 1 answer with empty RDataName, got %+v", parsed.Answers)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dnsparser/ -run TestParsePacketDecodesCNAME -v`
Expected: FAIL — `RDataName` stays `""` (CNAME decode not implemented).

- [ ] **Step 3: Implement**

In `internal/dnsparser/parser.go`:

1. Update the `ResourceRecord.RDataName` field comment (line ~60):
```go
	RDataName string // decoded rdata name for name-type records (NS/CNAME); "" when n/a or undecodable
```
2. Add the shared helper immediately above `parseResourceRecords`:
```go
// isNameRDataRecordType reports whether a record type carries a domain name
// as its rdata (a wire-format name, possibly a compression pointer).
func isNameRDataRecordType(recordType uint16) bool {
	return recordType == Enums.DNS_RECORD_TYPE_NS || recordType == Enums.DNS_RECORD_TYPE_CNAME
}
```
3. Replace the NS-only decode block inside `parseResourceRecords` (currently commented "NS rdata is a domain name..." with condition `if rType == Enums.DNS_RECORD_TYPE_NS {`):
```go
		// NS and CNAME rdata are domain names (possibly compression pointers).
		// Decode them so tunnel payloads carried in those names can be read. A
		// decode failure (or a name that overruns rdLen) leaves RDataName empty
		// and never fails the whole packet parse.
		if isNameRDataRecordType(rType) {
			if nameText, nameNext, nameErr := parseName(data, offset); nameErr == nil && nameNext <= end {
				records[i].RDataName = nameText
			}
		}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsparser/ -run 'TestParsePacketDecodesCNAME|TestParsePacketToleratesGarbageCNAME' -v`
Expected: PASS (all 3).

Then full package regression (NS/TXT tests must stay green):
Run: `go test ./internal/dnsparser/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dnsparser/parser.go internal/dnsparser/cname_test.go
git commit -m "feat: decode CNAME rdata names in DNS parser"
```

---

### Task 2: Server builds CNAME chain answers; client extraction reads them

**Files:**
- Modify: `internal/dnsparser/transport.go`
- Test: `internal/dnsparser/cname_test.go`

**Interfaces:**
- Consumes: Task 1 `isNameRDataRecordType`, existing `maxNSUnitBytes()`, `buildNSAnswerName(chunk []byte) ([]byte, error)`, `buildNSAnswerChunks(rawFrame []byte) ([][]byte, error)` (reused verbatim — they are type-agnostic base36-name helpers), `ParsePacketLite`, `responseAnswerNameBytes`, `buildResponseFlags`, `extractQuestionSection`, `findOPTRecordRange`, `VpnProto.BuildRawAuto`.
- Produces (all in `transport.go`, unexported unless noted):
  - `func questionTypeIsCNAME(questionPacket []byte) bool` — first question asks for CNAME
  - `func buildCNAMEVPNResponse(questionPacket []byte, answerName string, rawFrame []byte) ([]byte, error)` — single unit → one CNAME RR; else chain
  - `func buildSingleCNAMEResponsePacket(questionPacket []byte, answerName string, answerNameWire []byte) ([]byte, error)` — structural copy of `buildSingleNSResponsePacket` with type CNAME
  - `BuildCNAMEChainResponsePacket(questionPacket []byte, answerName string, answerNameWires [][]byte) ([]byte, error)` — multi-answer chain (shape in Design Decision 3)
  - `BuildVPNResponsePacket` (existing, modified): adds a CNAME branch after the NS branch; TXT body untouched
  - `extractAnswerUnits(parsed Packet) ([][]byte, bool)` (existing, modified): name-type answers (NS **or** CNAME) base36-decoded first; TXT fallback unchanged
  - `ExtractVPNResponse` (existing, modified): renamed local `fromNS` → `fromNameType`, comment update only
  - Comment-only touch: `decodeNSAnswerName`, `buildNSAnswerName`, `buildNSAnswerChunks` comments mention CNAME sharing.

- [ ] **Step 1: Write the failing tests**

Append to `internal/dnsparser/cname_test.go`. Extend imports to `"bytes"` and `"errors"`, plus `VpnProto "stormdns-go/internal/vpnproto"`. The helpers `patternedPayload`, `vpnPacketForTest`, `splitLabels` already exist in `ns_test.go` (same package) — reuse them.

```go
func TestBuildVPNResponsePacketMirrorsCNAMEQuestionSingle(t *testing.T) {
	question := BuildTXTQuestionPacket("a1b2.v.example.com", Enums.DNS_RECORD_TYPE_CNAME, 0)
	payload := []byte("hello cname world")
	resp, err := BuildVPNResponsePacket(question, "a1b2.v.example.com", vpnPacketForTest(payload), false)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Questions) != 1 || parsed.Questions[0].Type != Enums.DNS_RECORD_TYPE_CNAME {
		t.Fatalf("question type not echoed: %+v", parsed.Questions)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 CNAME answer, got %d", len(parsed.Answers))
	}
	if parsed.Answers[0].Type != Enums.DNS_RECORD_TYPE_CNAME {
		t.Fatalf("answer type = %d, want CNAME(%d)", parsed.Answers[0].Type, Enums.DNS_RECORD_TYPE_CNAME)
	}
	if parsed.Answers[0].RDataName == "" {
		t.Fatal("CNAME answer rdata name not decoded")
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

func TestBuildVPNResponsePacketMirrorsCNAMEQuestionChain(t *testing.T) {
	question := BuildTXTQuestionPacket("aa.bb.v.example.com", Enums.DNS_RECORD_TYPE_CNAME, 0)
	payload := patternedPayload(800) // forces multiple CNAME answer records
	resp, err := BuildVPNResponsePacket(question, "aa.bb.v.example.com", vpnPacketForTest(payload), true /* base64 flag must be irrelevant for CNAME */)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) < 2 {
		t.Fatalf("want multiple CNAME answers, got %d", len(parsed.Answers))
	}
	for i, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_CNAME {
			t.Fatalf("answer %d type = %d, want CNAME", i, ans.Type)
		}
		if ans.RDataName == "" {
			t.Fatalf("answer %d rdata name missing", i)
		}
		if i > 0 && ans.Name != parsed.Answers[i-1].RDataName {
			t.Fatalf("chain broken at link %d: owner %q != previous target %q", i, ans.Name, parsed.Answers[i-1].RDataName)
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

func TestExtractVPNResponseReadsCNAMENamePayload(t *testing.T) {
	// Single CNAME answer whose rdata target name carries base36 of a real raw
	// frame (the server's single-answer path).
	question := BuildTXTQuestionPacket("k9.v.example.com", Enums.DNS_RECORD_TYPE_CNAME, 0)
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
	resp, err := buildSingleCNAMEResponsePacket(question, "k9.v.example.com", nameWire)
	if err != nil {
		t.Fatal(err)
	}

	// baseEncoded=true must not corrupt CNAME-unit decoding (name transport is
	// charset-safe by itself).
	got, err := ExtractVPNResponse(resp, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || !bytes.Equal(got.Payload, []byte{1, 2, 3, 4, 5}) {
		t.Fatalf("roundtrip mismatch: type=%d payload=%v", got.PacketType, got.Payload)
	}
}

func TestExtractVPNResponseNoPayloadFromUnreadableCNAME(t *testing.T) {
	// A CNAME answer whose rdata name cannot be decoded must behave like a
	// response without tunnel payload: ErrTXTAnswerMissing, not a panic.
	resp := buildCNAMEAnswerTestPacket(t, []byte{63, 'a', 'b'})
	if _, err := ExtractVPNResponse(resp, false); !errors.Is(err, ErrTXTAnswerMissing) {
		t.Fatalf("want ErrTXTAnswerMissing, got %v", err)
	}
}

func TestExtractVPNResponseIgnoresRecordsAppendedByRecursor(t *testing.T) {
	// Recursors may append address records after a CNAME chain; units must come
	// only from the CNAME rdata names, in order.
	payload := patternedPayload(400)
	question := BuildTXTQuestionPacket("aa.bb.v.example.com", Enums.DNS_RECORD_TYPE_CNAME, 0)
	resp, err := BuildVPNResponsePacket(question, "aa.bb.v.example.com", vpnPacketForTest(payload), false)
	if err != nil {
		t.Fatal(err)
	}

	// Append one A record after the chain and bump ANCount.
	owner, err := encodeDNSNameStrict("extra.example.net")
	if err != nil {
		t.Fatal(err)
	}
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], Enums.DNS_RECORD_TYPE_A)
	binary.BigEndian.PutUint16(fixed[2:4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint16(fixed[8:10], 4)
	resp = append(resp, owner...)
	resp = append(resp, fixed[:]...)
	resp = append(resp, 1, 2, 3, 4)
	anCount := binary.BigEndian.Uint16(resp[6:8])
	binary.BigEndian.PutUint16(resp[6:8], anCount+1)

	got, err := ExtractVPNResponse(resp, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("roundtrip mismatch: type=%d payloadlen=%d", got.PacketType, len(got.Payload))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/dnsparser/ -run 'TestBuildVPNResponsePacketMirrorsCNAME|TestExtractVPNResponseReadsCNAME|TestExtractVPNResponseNoPayloadFromUnreadableCNAME|TestExtractVPNResponseIgnoresRecordsAppendedByRecursor' -v`
Expected: FAIL — answers are TXT/NS or missing (mirror not implemented); CNAME extraction errors.

- [ ] **Step 3: Implement**

In `internal/dnsparser/transport.go`:

1. Dispatch — after the NS branch at the top of `BuildVPNResponsePacket`, add a CNAME branch (TXT body below stays untouched):
```go
	if questionTypeIsNS(questionPacket) {
		return buildNSVPNResponse(questionPacket, answerName, rawFrame)
	}
	if questionTypeIsCNAME(questionPacket) {
		return buildCNAMEVPNResponse(questionPacket, answerName, rawFrame)
	}
```

2. Add next to `questionTypeIsNS`:
```go
// questionTypeIsCNAME reports whether the packet's first question asks for CNAME.
func questionTypeIsCNAME(questionPacket []byte) bool {
	lite, err := ParsePacketLite(questionPacket)
	return err == nil && lite.HasQuestion && lite.FirstQuestion.Type == Enums.DNS_RECORD_TYPE_CNAME
}
```

3. Add next to `buildNSVPNResponse`:
```go
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
```

4. Add after `buildSingleNSResponsePacket` (structural copy, only the type constant and the rdata meaning differ — rdata is the wire name being aliased to):
```go
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
```

5. Add after `BuildNSResponsePacket`:
```go
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
```

6. Update comments on the reused NS helpers (comment-only):
   - `maxNSUnitBytes` comment → "...whose base36 text fits in maxNSNameChars (~161 bytes). Shared by the NS and CNAME name transports."
   - `buildNSAnswerName` comment → "encodes one payload unit as a name-rdata wire name (NS or CNAME target): lowercase-base36 text split into <=63-char labels."
   - `buildNSAnswerChunks` comment → "...and returns one rdata wire name per unit (shared by the NS and CNAME name transports)."
   - `decodeNSAnswerName` comment → "decodes a name-rdata target (NS or CNAME) back into the payload unit bytes: label text (dots removed) is lowercase-base36."

7. Extraction — replace the body of `extractAnswerUnits` (NS-only first pass becomes NS+CNAME):
```go
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
```

8. In `ExtractVPNResponse`, rename the local `fromNS` to `fromNameType` and update its comment (behavior unchanged):
```go
	rawAnswers, fromNameType := extractAnswerUnits(parsed)
	if len(rawAnswers) == 0 {
		return VpnProto.Packet{}, ErrTXTAnswerMissing
	}
	if fromNameType {
		// NS/CNAME units were already decoded from their name transport; the
		// base64 session flag applies to TXT answers only.
		baseEncoded = false
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsparser/ -run 'TestBuildVPNResponsePacketMirrorsCNAME|TestExtractVPNResponseReadsCNAME|TestExtractVPNResponseNoPayloadFromUnreadableCNAME|TestExtractVPNResponseIgnoresRecordsAppendedByRecursor' -v`
Expected: PASS.

Then full regression:
Run: `go test ./internal/dnsparser/ ./internal/client/ ./internal/udpserver/`
Expected: PASS (existing NS/TXT tests unchanged behavior).

- [ ] **Step 5: Commit**

```bash
git add internal/dnsparser/transport.go internal/dnsparser/cname_test.go
git commit -m "feat: CNAME chain tunnel answers (server mirror + name extraction)"
```

---

### Task 3: Matcher accepts CNAME tunnel queries

**Files:**
- Modify: `internal/domainmatcher/matcher.go` (qtype gate ~line 89)
- Test: `internal/domainmatcher/matcher_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Matcher.Match` returns `ActionProcess` for TXT, NS, **and** CNAME questions with valid labels; other qtypes keep `Reason: "unsupported-qtype"`.

- [ ] **Step 1: Write the failing test**

Append to `internal/domainmatcher/matcher_test.go` (mirrors `TestMatcherReturnsProcessForNSQuestion`, which sits at the end of the file):

```go
func TestMatcherReturnsProcessForCNAMEQuestion(t *testing.T) {
	matcher := New([]string{"a.com", "c.b.com", "cc.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("vpn-01.c.b.com", Enums.DNS_RECORD_TYPE_CNAME))
	if decision.Action != ActionProcess {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionProcess)
	}
	if decision.QuestionType != Enums.DNS_RECORD_TYPE_CNAME {
		t.Fatalf("unexpected question type: got=%d want=%d", decision.QuestionType, Enums.DNS_RECORD_TYPE_CNAME)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domainmatcher/ -run TestMatcherReturnsProcessForCNAMEQuestion -v`
Expected: FAIL — action `ActionNoData`, reason `unsupported-qtype`.

- [ ] **Step 3: Implement**

In `internal/domainmatcher/matcher.go`, extend the qtype gate:
```go
	if q0.Type != Enums.DNS_RECORD_TYPE_TXT && q0.Type != Enums.DNS_RECORD_TYPE_NS &&
		q0.Type != Enums.DNS_RECORD_TYPE_CNAME {
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/domainmatcher/ -v`
Expected: PASS (new + all existing).

- [ ] **Step 5: Commit**

```bash
git add internal/domainmatcher/matcher.go internal/domainmatcher/matcher_test.go
git commit -m "feat: accept CNAME qtype as tunnel query"
```

---

### Task 4: Client config `DNS_QUERY_TYPE` accepts CNAME + docs

**Files:**
- Modify: `internal/config/client.go` (validation switch ~line 359)
- Modify: `internal/config/client_test.go`
- Modify: `client_config.toml.simple` (DNS_QUERY_TYPE comment block ~lines 205-209)
- Modify: `README.MD` (DNS Delegation Details paragraph ~line 190, table ~lines 193-199, note ~line 201, FAQ ~line 681)

**Interfaces:**
- Produces: `DNS_QUERY_TYPE` accepts `"TXT"` (default), `"NS"`, `"CNAME"`, `"ROTATE"`; anything else → error `invalid DNS_QUERY_TYPE: %q`.

- [ ] **Step 1: Write the failing test**

Append to `internal/config/client_test.go` (uses the existing `writeClientConfigForTest` helper):

```go
func TestClientConfigDNSQueryTypeNormalizesCNAME(t *testing.T) {
	cfg := writeClientConfigForTest(t, `
DNS_QUERY_TYPE = "cname"
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
DOMAINS = ["v.domain.com"]
`)
	if cfg.DNSQueryType != "CNAME" {
		t.Fatalf("DNSQueryType = %q, want %q", cfg.DNSQueryType, "CNAME")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestClientConfigDNSQueryTypeNormalizesCNAME -v`
Expected: FAIL — `invalid DNS_QUERY_TYPE: "CNAME"`.

- [ ] **Step 3: Implement**

1. In `internal/config/client.go`, extend the validation switch:
```go
	case "NS", "CNAME", "ROTATE":
```

2. In `client_config.toml.simple`, replace the comment block above `DNS_QUERY_TYPE = "TXT"`:
```toml
# DNS record type used for tunnel queries.
#   "TXT"    - default, works with every server version
#   "NS"     - tunnel over NS queries/answers; use when the resolver path blocks TXT
#   "CNAME"  - tunnel over CNAME query/answer chains; the most web-like query shape
#   "ROTATE" - random TXT/NS/CNAME mix per query (disguise); requires a matching server
```

3. In `README.MD`, replace the delegation paragraph and table:
```markdown
**These same two records serve every tunnel query type — TXT, NS, CNAME, or a ROTATE mix. No extra DNS records are needed.** Delegation is type-agnostic: queries of any type for `v.example.com` or for names beneath it (payload-carrying tunnel names are always subdomains of the tunnel domain) are referred to `ns.example.com` and reach your server. The server answers each query with the same record type it was asked for (TXT questions get TXT answers, NS questions get NS answers, CNAME questions get CNAME answer chains, all with TTL 0), so resolvers never cache tunnel traffic.

`DNS_QUERY_TYPE` in the client config selects the record type used for tunnel queries:

| Value | Meaning |
| --- | --- |
| `"TXT"` (default) | Works with every server version; the classic tunnel shape |
| `"NS"` | Tunnel over NS queries/answers — use when a resolver or middlebox in your path drops or mangles TXT queries/answers |
| `"CNAME"` | Tunnel over CNAME queries and CNAME answer chains — the most ordinary, web-like query shape; use when NS queries/answers look suspicious in your path |
| `"ROTATE"` | Random TXT/NS/CNAME mix per query, so the stream does not look like a single-type DNS tunnel |

`"NS"`, `"CNAME"`, and `"ROTATE"` require a server running the same feature version. An older server answers NS and CNAME tunnel queries with an empty response, which surfaces as repeated session-init retries — switch back to `"TXT"` if your server has not been updated.
```

4. In `README.MD`, update the FAQ troubleshooting paragraph:
```markdown
If tunnel queries never get answers while normal lookups work, some resolver or middlebox in your path may block or mangle TXT queries/answers. Switch the client to NS or CNAME queries (see `DNS_QUERY_TYPE` under [DNS Delegation Details](#dns-delegation-details)); the same delegation records work unchanged. These modes need a server that mirrors the question type, so update the server first.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/client.go internal/config/client_test.go client_config.toml.simple README.MD
git commit -m "feat: accept CNAME in DNS_QUERY_TYPE client config"
```

---

### Task 5: Client picks the query type per packet (CNAME mode + 3-way ROTATE)

**Files:**
- Modify: `internal/client/tunnel_query.go` (`pickTunnelQueryType`)
- Modify: `internal/client/tunnel_query_test.go`

**Interfaces:**
- Consumes: Task 4 `cfg.DNSQueryType`.
- Produces: `func (c *Client) pickTunnelQueryType() uint16` — `TXT`→16, `NS`→2, `CNAME`→5, `ROTATE`→uniform random 16/2/5 (`math/rand`), empty/unknown (defensive, incl. nil-`c` fields) →16. All other callers unchanged (`buildTunnelQuestionBytes(Prepared)` already route through the picker).

- [ ] **Step 1: Write the failing tests**

In `internal/client/tunnel_query_test.go`:
1. Update `TestPickTunnelQueryTypeRotateMix` to require all three types (rename body; keep the function name and map-based shape):
```go
func TestPickTunnelQueryTypeRotateMix(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "ROTATE"
	seen := map[uint16]bool{}
	for i := 0; i < 300; i++ {
		seen[c.pickTunnelQueryType()] = true
	}
	for _, want := range []uint16{
		Enums.DNS_RECORD_TYPE_TXT,
		Enums.DNS_RECORD_TYPE_NS,
		Enums.DNS_RECORD_TYPE_CNAME,
	} {
		if !seen[want] {
			t.Fatalf("ROTATE must produce type %d, got %v", want, seen)
		}
	}
}
```
2. Add CNAME-mode tests after `TestPickTunnelQueryTypeNSMode`:
```go
func TestPickTunnelQueryTypeCNAMEMode(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "CNAME"
	if got := c.pickTunnelQueryType(); got != Enums.DNS_RECORD_TYPE_CNAME {
		t.Fatalf("CNAME mode picked %d", got)
	}
}

func TestBuildTunnelQuestionBytesUsesCNAMEMode(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "CNAME"
	packet, err := c.buildTunnelQuestionBytes("v.example.com", []byte("abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	if got := questionTypeOf(t, packet); got != Enums.DNS_RECORD_TYPE_CNAME {
		t.Fatalf("packet qtype = %d, want CNAME", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/client/ -run 'TestPickTunnelQueryType|TestBuildTunnelQuestionBytesUses' -v`
Expected: FAIL — `TestPickTunnelQueryTypeCNAMEMode` picks TXT; `TestPickTunnelQueryTypeRotateMix` never sees CNAME; `TestBuildTunnelQuestionBytesUsesCNAMEMode` gets qtype TXT.

- [ ] **Step 3: Implement**

In `internal/client/tunnel_query.go`, replace `pickTunnelQueryType` (comment + body):
```go
// pickTunnelQueryType returns the DNS record type for the next tunnel query
// based on the configured mode: TXT (default), NS, CNAME, or ROTATE (uniform
// random).
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
	case "CNAME":
		return Enums.DNS_RECORD_TYPE_CNAME
	case "ROTATE":
		switch rand.Intn(3) {
		case 0:
			return Enums.DNS_RECORD_TYPE_TXT
		case 1:
			return Enums.DNS_RECORD_TYPE_NS
		default:
			return Enums.DNS_RECORD_TYPE_CNAME
		}
	default:
		return Enums.DNS_RECORD_TYPE_TXT
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/client/ -run 'TestPickTunnelQueryType|TestBuildTunnelQuestionBytesUses' -v`
Expected: PASS.

Then full client regression:
Run: `go test ./internal/client/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/client/tunnel_query.go internal/client/tunnel_query_test.go
git commit -m "feat: per-query tunnel DNS type selection (TXT/NS/CNAME/ROTATE)"
```

---

### Task 6: Server-side smoke test (udpserver) + full verification

**Files:**
- Test: `internal/udpserver/cname_tunnel_test.go` (new, mirrors `ns_tunnel_test.go`)

**Interfaces:**
- Consumes: everything above via public API (`BuildVPNResponsePacket`, `ExtractVPNResponse`, `Matcher`, `Server.handleMTUDownRequest`). Reuses `patternBytes` and the `Server` fixture style already defined in `ns_tunnel_test.go` (same package `udpserver`).

**Purpose:** prove the server ingress path (matcher accepts CNAME → MTU handler builds a chained CNAME response → client-side extractor recovers the payload) end to end.

- [ ] **Step 1: Write the test**

Create `internal/udpserver/cname_tunnel_test.go`:

```go
// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package udpserver

import (
	"encoding/binary"
	"sync"
	"testing"

	DnsParser "stormdns-go/internal/dnsparser"
	domainMatcher "stormdns-go/internal/domainmatcher"
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

func TestCNAMETunnelQueryAcceptedEndToEnd(t *testing.T) {
	// 1. A CNAME-type tunnel query for a data-bearing name passes the matcher.
	matcher := domainMatcher.New([]string{"v.example.com"}, 3)
	query, err := DnsParser.BuildTunnelTXTQuestionPacket("abc.v.example.com", []byte("q3f2abc"), Enums.DNS_RECORD_TYPE_CNAME, 0)
	if err != nil {
		t.Fatal(err)
	}
	lite, err := DnsParser.ParseDNSRequestLite(query)
	if err != nil {
		t.Fatal(err)
	}
	decision := matcher.Match(lite)
	if decision.Action != domainMatcher.ActionProcess {
		t.Fatalf("CNAME tunnel query rejected: action=%v reason=%s", decision.Action, decision.Reason)
	}

	// 2. The real server response handler mirrors the question type into a
	//    chained CNAME answer whose links own the previous rdata name.
	s := &Server{
		mtuProbePayloadPool: sync.Pool{
			New: func() any {
				return make([]byte, mtuProbeMaxDownSize)
			},
		},
	}

	downloadSize := 300 // forces multi-record CNAME chain framing
	payload := make([]byte, mtuProbeDownMinSize+downloadSize)
	payload[0] = mtuProbeModeRaw
	copy(payload[1:1+mtuProbeCodeLength], []byte{9, 8, 7, 6})
	binary.BigEndian.PutUint16(payload[mtuProbeUpMinSize:mtuProbeDownMinSize], uint16(downloadSize))
	copy(payload[mtuProbeDownMinSize:], patternBytes(downloadSize))

	response := s.handleMTUDownRequest(query, lite, decision, VpnProto.Packet{
		SessionID:   9,
		PacketType:  Enums.PACKET_MTU_DOWN_REQ,
		StreamID:    1,
		SequenceNum: 2,
		Payload:     payload,
	})
	if response == nil {
		t.Fatal("expected response packet")
	}

	parsed, err := DnsParser.ParsePacket(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) < 2 {
		t.Fatalf("expected multiple CNAME answers, got %d", len(parsed.Answers))
	}
	for i, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_CNAME {
			t.Fatalf("answer %d type = %d, want CNAME", i, ans.Type)
		}
		if i > 0 && ans.Name != parsed.Answers[i-1].RDataName {
			t.Fatalf("chain broken at link %d: owner %q != previous target %q", i, ans.Name, parsed.Answers[i-1].RDataName)
		}
	}

	// 3. The client-side extractor recovers the payload from the chain.
	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_DOWN_RES)
	}
	if len(packet.Payload) != downloadSize {
		t.Fatalf("unexpected payload len: got=%d want=%d", len(packet.Payload), downloadSize)
	}
	if got := packet.Payload[:mtuProbeCodeLength]; string(got) != string([]byte{9, 8, 7, 6}) {
		t.Fatalf("unexpected probe code: got=%v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it passes (new behavior)**

Run: `go test ./internal/udpserver/ -run TestCNAMETunnelQueryAcceptedEndToEnd -v`
Expected: PASS (this task is the integration gate; if it fails, debug per systematic-debugging — most likely a framing mismatch caught only by cross-package use).

- [ ] **Step 3: Full verification**

Run:
```bash
go vet ./...
go build ./cmd/client && go build ./cmd/server
go test ./...
go test -race ./internal/dnsparser/ ./internal/domainmatcher/ ./internal/config/ ./internal/client/ ./internal/udpserver/
```
Expected: all PASS.

- [ ] **Step 4: Manual smoke (optional, environment permitting)**

`go run scripts/bench/bench.go` runs a local server+client; do one TXT run (regression). For a CNAME smoke, temporarily set `DNS_QUERY_TYPE = "CNAME"` in the bench's client config before running — confirm throughput > 0 and the logs show no `ErrTXTAnswerMissing` storms. Not required for merge.

- [ ] **Step 5: Commit**

```bash
git add internal/udpserver/cname_tunnel_test.go
git commit -m "test: CNAME tunnel query acceptance end to end"
```

---

## Self-Review Notes (checked)

- Spec coverage: mirror rule (T2/T3), client mode + 3-way ROTATE (T4/T5), CNAME chain framing + capacity (T2), extraction (T2), parser rdata names (T1), docs (T4), integration gate (T6), backward compat TXT/NS-default (T4/T5 defaults + untouched TXT/NS paths + package regressions in T1/T2). All chat-design decisions covered.
- No placeholders: every step has concrete code, exact insertion points, and runnable verification with expected outcomes.
- Type consistency: `isNameRDataRecordType`, `questionTypeIsCNAME`, `buildCNAMEVPNResponse`, `buildSingleCNAMEResponsePacket`, `BuildCNAMEChainResponsePacket`, `fromNameType` names/signatures are identical across tasks. Existing exported names unchanged. Test helpers `patternedPayload`, `vpnPacketForTest`, `splitLabels` (dnsparser), `patternBytes` (udpserver), `writeClientConfigForTest` (config), `litePacketWithQuestion` (domainmatcher), `questionTypeOf` (client) all exist in their packages today — reused, never redefined.
