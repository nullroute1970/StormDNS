package client

import (
	"encoding/binary"
	"testing"
)

func TestEncodedCharsForPayloadUsesWorstCaseUploadPacketType(t *testing.T) {
	c := createTestClient(t)

	got := c.encodedCharsForPayload(120)
	want := c.encodedCharsForPacketPayload(maxUploadProbePacketType, 120)
	if got != want {
		t.Fatalf("expected worst-case encoded char count, got=%d want=%d", got, want)
	}
}

func TestEncodedCharsForPayloadMatchesMaxUploadProbeCapacityModel(t *testing.T) {
	c := createTestClient(t)

	payloadLen := 120
	if !c.canBuildUploadPayload("example.com", payloadLen) {
		t.Fatalf("expected payload length %d to fit generated upload MTU question", payloadLen)
	}

	got := c.encodedCharsForPayload(payloadLen)
	if got <= 0 {
		t.Fatal("expected encoded char count to be positive")
	}
}

func TestBuildMTUProbePayloadWritesModeAndProbeCodeWithoutFillingTail(t *testing.T) {
	c := createTestClient(t)

	payload, code, useBase64, err := c.buildMTUProbePayload(16)
	if err != nil {
		t.Fatalf("buildMTUProbePayload returned error: %v", err)
	}
	if useBase64 {
		t.Fatal("expected raw response mode for test client")
	}
	if len(payload) != 16 {
		t.Fatalf("unexpected payload length: got=%d want=%d", len(payload), 16)
	}
	if payload[0] != mtuProbeRawResponse {
		t.Fatalf("unexpected mode byte: got=%d want=%d", payload[0], mtuProbeRawResponse)
	}
	if got := binary.BigEndian.Uint32(payload[1 : 1+mtuProbeCodeLength]); got != code {
		t.Fatalf("unexpected probe code in payload: got=%d want=%d", got, code)
	}
	for i, value := range payload[1+mtuProbeCodeLength:] {
		if value != 0 {
			t.Fatalf("expected zero-filled tail at offset %d, got=%d", i+(1+mtuProbeCodeLength), value)
		}
	}
}
