// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"errors"
	"net"
	"time"

	"stormdns-go/internal/arq"
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

var errLateStreamResult = errors.New("late stream result for closed or terminal local stream")

func (c *Client) HandleTCPConnect(_ context.Context, conn net.Conn) {
	streamID, ok := c.get_new_stream_id()
	if !ok {
		if conn != nil {
			_ = conn.Close()
		}
		return
	}

	c.log.Infof("🔌 <green>New TCP CONNECT, Stream ID: <cyan>%d</cyan></green>", streamID)

	s := c.new_stream(streamID, conn, nil)
	if s == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return
	}

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok || arqObj == nil {
		c.removeStream(streamID)
		return
	}

	arqObj.SendControlPacketWithTTL(
		Enums.PACKET_STREAM_SYN,
		0,
		0,
		0,
		nil,
		Enums.DefaultPacketPriority(Enums.PACKET_STREAM_SYN),
		true,
		nil,
		120*time.Second,
	)
}

func (c *Client) streamResultAllowed(s *Stream_client) bool {
	if s == nil || s.NetConn == nil {
		return false
	}

	switch s.StatusValue() {
	case streamStatusCancelled, streamStatusDraining, streamStatusClosing, streamStatusTimeWait, streamStatusClosed:
		return false
	}

	return s.TerminalSince().IsZero()
}

func (c *Client) handleStreamConnected(packet VpnProto.Packet, s *Stream_client, arqObj *arq.ARQ) error {
	if s == nil || arqObj == nil {
		return nil
	}

	switch s.StatusValue() {
	case streamStatusActive:
		return nil
	case streamStatusDraining, streamStatusClosing, streamStatusTimeWait, streamStatusClosed:
		return nil
	}

	if s.StatusValue() == streamStatusCancelled || !c.streamResultAllowed(s) {
		arqObj.Close("late STREAM_CONNECTED result", arq.CloseOptions{SendRST: true})
		return nil
	}

	arqObj.SetIOReady(true)
	s.SetStatus(streamStatusActive)
	c.noteStreamProgress(packet.StreamID)
	return nil
}

func (c *Client) handleStreamConnectFail(_ VpnProto.Packet, s *Stream_client, arqObj *arq.ARQ) error {
	if s == nil || arqObj == nil {
		return nil
	}

	switch s.StatusValue() {
	case streamStatusDraining, streamStatusClosing, streamStatusTimeWait, streamStatusClosed:
		return nil
	}

	if s.StatusValue() == streamStatusCancelled || !c.streamResultAllowed(s) {
		arqObj.Close("late STREAM_CONNECT_FAIL result", arq.CloseOptions{SendRST: true})
		return nil
	}

	s.MarkTerminal(time.Now())
	s.SetStatus(streamStatusTimeWait)
	arqObj.Close("STREAM connect failure received", arq.CloseOptions{Force: true})
	return nil
}
