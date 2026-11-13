package e2e

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"proxy-duplicator/internal/protocol"
)

// startUDPEcho returns a loopback UDP echo server and its address.
func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

// socksUDPAssociate performs the SOCKS5 UDP ASSOCIATE handshake over TCP and
// returns the relay address plus the control conn (caller must Close it).
func socksUDPAssociate(t *testing.T, socksAddr string) (*net.UDPAddr, net.Conn) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	br := bufio.NewReader(conn)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	var m [2]byte
	if _, err := io.ReadFull(br, m[:]); err != nil || m != [2]byte{0x05, 0x00} {
		conn.Close()
		t.Fatalf("method reply %v err=%v", m, err)
	}
	// UDP ASSOCIATE with 0.0.0.0:0 (src discovered from datagrams).
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	var rh [4]byte
	if _, err := io.ReadFull(br, rh[:]); err != nil {
		conn.Close()
		t.Fatalf("assoc reply hdr: %v", err)
	}
	if rh[0] != 0x05 || rh[1] != 0x00 {
		conn.Close()
		t.Fatalf("assoc refused: %v", rh)
	}
	var host string
	var n int
	switch rh[3] {
	case 0x01:
		var b [6]byte // ip4 + port
		if _, err := io.ReadFull(br, b[:]); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		host = net.IP(b[0:4]).String()
		n = int(binary.BigEndian.Uint16(b[4:6]))
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		hb := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(br, hb); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		host = string(hb[:len(hb)-2])
		n = int(binary.BigEndian.Uint16(hb[len(hb)-2:]))
	default:
		conn.Close()
		t.Fatalf("bad relay atyp %d", rh[3])
	}
	return &net.UDPAddr{IP: net.ParseIP(host), Port: n}, conn
}

// buildUDPRequest wraps payload for target into an RFC1928 datagram.
func buildUDPRequest(target *net.UDPAddr, payload []byte) []byte {
	a := protocol.Addr{Host: target.IP.String(), Port: uint16(target.Port), ATYP: protocol.ATYPIPv4}
	b := []byte{0, 0, 0}
	b = a.AppendTo(b)
	return append(b, payload...)
}

// parseUDPReply strips the RFC1928 header from a relayed reply.
func parseUDPReply(b []byte) (protocol.Addr, []byte, error) {
	return protocol.ParseUDPDatagram(b)
}

// TestUDPAssociateEcho runs the full UDP path: Nekoray-style ASSOCIATE →
// client relay → duplicated tunnels → server UDP socket → echo → back.
func TestUDPAssociateEcho(t *testing.T) {
	echo := startUDPEcho(t)
	e := startEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}), "")

	// Wait for the SOCKS listener + tunnels.
	deadline := time.Now().Add(15 * time.Second)
	var relay *net.UDPAddr
	var control net.Conn
	for time.Now().Before(deadline) {
		relay, control = socksUDPAssociateSafe(e.socksAddr)
		if relay != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if relay == nil {
		t.Fatal("UDP ASSOCIATE never succeeded")
	}
	defer control.Close()

	pc, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(10 * time.Second))

	sizes := []int{1, 100, 1400, 8192}
	for _, size := range sizes {
		payload := patternBody(size)
		if _, err := pc.Write(buildUDPRequest(echo, payload)); err != nil {
			t.Fatalf("send size=%d: %v", size, err)
		}
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := pc.Read(buf)
		if err != nil {
			t.Fatalf("reply size=%d: %v", size, err)
		}
		_, data, err := parseUDPReply(buf[:n])
		if err != nil {
			t.Fatalf("parse reply size=%d: %v", size, err)
		}
		if err := bytesEqual(data, payload); err != nil {
			t.Fatalf("echo mismatch size=%d: %v", size, err)
		}
	}

	// Several datagrams in a row (ordering across duplicated tunnels).
	for i := 0; i < 20; i++ {
		payload := []byte(fmt.Sprintf("burst-%02d", i))
		if _, err := pc.Write(buildUDPRequest(echo, payload)); err != nil {
			t.Fatalf("burst send %d: %v", i, err)
		}
		buf := make([]byte, 4096)
		_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := pc.Read(buf)
		if err != nil {
			t.Fatalf("burst reply %d: %v", i, err)
		}
		_, data, err := parseUDPReply(buf[:n])
		if err != nil || !bytes.Equal(data, payload) {
			t.Fatalf("burst %d: data=%q err=%v", i, data, err)
		}
	}

	// Closing the control conn must end the association: subsequent datagrams
	// are dropped (no reply).
	_ = control.Close()
	time.Sleep(300 * time.Millisecond)
	payload := []byte("after-close")
	_, _ = pc.Write(buildUDPRequest(echo, payload))
	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	if n, err := pc.Read(buf); err == nil {
		t.Fatalf("got reply after association close (%d bytes)", n)
	}
}

// socksUDPAssociateSafe never fails the test (used while tunnels establish).
func socksUDPAssociateSafe(socksAddr string) (*net.UDPAddr, net.Conn) {
	conn, err := net.DialTimeout("tcp", socksAddr, time.Second)
	if err != nil {
		return nil, nil
	}
	fail := func() (*net.UDPAddr, net.Conn) {
		conn.Close()
		return nil, nil
	}
	br := bufio.NewReader(conn)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail()
	}
	var m [2]byte
	if _, err := io.ReadFull(br, m[:]); err != nil || m != [2]byte{0x05, 0x00} {
		return fail()
	}
	if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail()
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var rh [4]byte
	if _, err := io.ReadFull(br, rh[:]); err != nil || rh[0] != 0x05 || rh[1] != 0x00 {
		return fail()
	}
	_ = conn.SetDeadline(time.Time{})
	if rh[3] != 0x01 {
		return fail()
	}
	var b [6]byte
	if _, err := io.ReadFull(br, b[:]); err != nil {
		return fail()
	}
	return &net.UDPAddr{IP: net.IP(b[0:4]), Port: int(binary.BigEndian.Uint16(b[4:6]))}, conn
}
