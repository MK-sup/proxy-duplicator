package socks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"proxy-duplicator/internal/protocol"
)

// DialUpstream connects to the local go-socks5-proxy, performs method
// negotiation and a CONNECT to target, and returns:
//
//   - conn: the established upstream connection (nil if the proxy replied
//     with rep != 0 — reply still carries the verbatim bytes to forward),
//   - reply: the raw SOCKS5 reply payload to echo to the client as OPEN_ACK,
//   - err: transport/protocol failure where no usable reply exists.
//
// Overall handshake is bounded by timeout.
func DialUpstream(ctx context.Context, upstream string, target protocol.Addr, timeout time.Duration) (net.Conn, []byte, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", upstream)
	if err != nil {
		return nil, nil, fmt.Errorf("dial upstream %s: %w", upstream, err)
	}
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, nil, err
	}

	br := bufio.NewReader(conn)
	// Method negotiation: offer no-auth only.
	if _, err := conn.Write([]byte{Version, 0x01, AuthNone}); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write methods: %w", err)
	}
	var mhdr [2]byte
	if _, err := io.ReadFull(br, mhdr[:]); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read method reply: %w", err)
	}
	if mhdr[0] != Version || mhdr[1] != AuthNone {
		conn.Close()
		return nil, nil, fmt.Errorf("upstream refused auth (0x%02x 0x%02x)", mhdr[0], mhdr[1])
	}

	// CONNECT request built from the parsed target.
	req := []byte{Version, CmdConnect, 0x00}
	req = target.AppendTo(req)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write connect: %w", err)
	}

	reply, rep, err := readReply(br)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read connect reply: %w", err)
	}
	if rep != RepSuccess {
		conn.Close()
		return nil, reply, nil // caller sends the failure ack and destroys
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, reply, nil
}

// readReply reads one full SOCKS5 reply and returns its raw bytes + status.
func readReply(br *bufio.Reader) ([]byte, byte, error) {
	var hdr [4]byte // VER REP RSV ATYP
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, 0, err
	}
	if hdr[0] != Version {
		return nil, 0, fmt.Errorf("bad reply version 0x%02x", hdr[0])
	}
	raw := append([]byte(nil), hdr[:]...)
	switch hdr[3] {
	case protocol.ATYPIPv4:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, 0, err
		}
		raw = append(raw, buf...)
	case protocol.ATYPIPv6:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, 0, err
		}
		raw = append(raw, buf...)
	case protocol.ATYPDomain:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return nil, 0, err
		}
		buf := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, 0, err
		}
		raw = append(raw, l[0])
		raw = append(raw, buf...)
	default:
		return nil, 0, fmt.Errorf("bad reply ATYP 0x%02x", hdr[3])
	}
	return raw, hdr[1], nil
}
