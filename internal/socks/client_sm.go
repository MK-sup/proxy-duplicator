// Package socks implements the minimal SOCKS5 surface dupc and dupd need:
// method negotiation + request parsing on the client side, and a synthesized
// client handshake toward the upstream go-socks5-proxy on the server side.
package socks

import (
	"bufio"
	"fmt"
	"io"

	"proxy-duplicator/internal/protocol"
)

// SOCKS5 constants (RFC1928).
const (
	Version     = 0x05
	CmdConnect  = 0x01
	CmdBind     = 0x02
	CmdUDPAssoc = 0x03

	AuthNone     = 0x00
	AuthUserPass = 0x02 // RFC 1929
	AuthNoAccept = 0xFF

	RepSuccess     = 0x00
	RepGeneralFail = 0x01
	RepNotAllowed  = 0x02
	RepNetworkFail = 0x03
	RepHostUnreach = 0x04
	RepCmdNotSup   = 0x07
	RepAddrType    = 0x08
)

// Negotiate reads the client's method selection and replies no-auth.
func Negotiate(br *bufio.Reader, w io.Writer) error {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}
	if hdr[0] != Version {
		return fmt.Errorf("bad socks version 0x%02x", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return fmt.Errorf("read method list: %w", err)
	}
	hasNone := false
	for _, m := range methods {
		if m == AuthNone {
			hasNone = true
			break
		}
	}
	if !hasNone {
		_, _ = w.Write([]byte{Version, AuthNoAccept})
		return fmt.Errorf("client offers no no-auth method")
	}
	if _, err := w.Write([]byte{Version, AuthNone}); err != nil {
		return fmt.Errorf("write method reply: %w", err)
	}
	return nil
}

// Request is a parsed SOCKS5 command request.
type Request struct {
	Cmd  byte
	Addr protocol.Addr
}

// ReadRequest reads VER CMD RSV ATYP DST.ADDR DST.PORT.
func ReadRequest(br *bufio.Reader) (Request, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return Request{}, fmt.Errorf("read request: %w", err)
	}
	if hdr[0] != Version {
		return Request{}, fmt.Errorf("bad socks version 0x%02x", hdr[0])
	}
	addr, err := protocol.ReadAddr(br)
	if err != nil {
		return Request{}, fmt.Errorf("read request addr: %w", err)
	}
	return Request{Cmd: hdr[1], Addr: addr}, nil
}

// WriteReply writes a fixed-form success/general reply (BND 0.0.0.0:0).
func WriteReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{
		Version, rep, 0x00, 0x01,
		0, 0, 0, 0,
		0, 0,
	})
	return err
}

// FailureReply builds a failure reply payload (for OPEN_ACK on dial errors).
func FailureReply(rep byte) []byte {
	return []byte{Version, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}

// ReplyRep extracts the status byte from a raw SOCKS5 reply payload.
func ReplyRep(payload []byte) (byte, error) {
	if len(payload) < 2 {
		return 0, fmt.Errorf("reply too short (%d bytes)", len(payload))
	}
	if payload[0] != Version {
		return 0, fmt.Errorf("bad reply version 0x%02x", payload[0])
	}
	return payload[1], nil
}
