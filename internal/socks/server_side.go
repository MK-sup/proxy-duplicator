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
// negotiation (and RFC 1929 username/password subnegotiation when user
// != "") and a CONNECT to target, and returns:
//
//   - conn: the established upstream connection (nil if the proxy replied
//     with rep != 0 — reply still carries the verbatim bytes to forward),
//   - reply: the raw SOCKS5 reply payload to echo to the client as OPEN_ACK,
//   - err: transport/protocol failure where no usable reply exists.
//
// Overall handshake is bounded by timeout.
func DialUpstream(ctx context.Context, upstream string, target protocol.Addr, timeout time.Duration, user, pass string) (net.Conn, []byte, error) {
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
	// Method negotiation: offer no-auth always; also offer username/password
	// (RFC 1929) when credentials are configured.
	methods := []byte{AuthNone}
	if user != "" {
		methods = append(methods, AuthUserPass)
	}
	req := append([]byte{Version, byte(len(methods))}, methods...)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write methods: %w", err)
	}
	var mhdr [2]byte
	if _, err := io.ReadFull(br, mhdr[:]); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read method reply: %w", err)
	}
	if mhdr[0] != Version {
		conn.Close()
		return nil, nil, fmt.Errorf("bad method reply version 0x%02x", mhdr[0])
	}
	switch mhdr[1] {
	case AuthNone:
		// nothing more
	case AuthUserPass:
		if user == "" {
			conn.Close()
			return nil, nil, fmt.Errorf("upstream requires username/password (set socks5_user/socks5_password)")
		}
		if err := userPassAuth(conn, br, user, pass); err != nil {
			conn.Close()
			return nil, nil, err
		}
	case AuthNoAccept:
		conn.Close()
		if user != "" {
			return nil, nil, fmt.Errorf("upstream accepted no auth method (0x%02x 0xff) — check socks5_user/socks5_password", mhdr[0])
		}
		return nil, nil, fmt.Errorf("upstream refused auth (0x%02x 0xff) — upstream may require username/password (set socks5_user/socks5_password)", mhdr[0])
	default:
		conn.Close()
		return nil, nil, fmt.Errorf("upstream chose unsupported auth method 0x%02x", mhdr[1])
	}

	// CONNECT request built from the parsed target.
	req = []byte{Version, CmdConnect, 0x00}
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

// userPassAuth performs RFC 1929 username/password subnegotiation.
func userPassAuth(conn net.Conn, br *bufio.Reader, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return fmt.Errorf("upstream credentials too long (max 255 bytes)")
	}
	msg := []byte{0x01, byte(len(user))}
	msg = append(msg, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("write userpass auth: %w", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(br, resp[:]); err != nil {
		return fmt.Errorf("read userpass auth reply: %w", err)
	}
	if resp[0] != 0x01 {
		return fmt.Errorf("bad userpass auth version 0x%02x", resp[0])
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("upstream auth rejected (status 0x%02x) — check socks5_user/socks5_password", resp[1])
	}
	return nil
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
