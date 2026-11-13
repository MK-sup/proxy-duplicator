package socks

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"proxy-duplicator/internal/protocol"
)

func TestNegotiateAndReadRequest(t *testing.T) {
	// Client bytes: methods [05 02 00 02], then CONNECT to 192.0.2.1:80.
	client := []byte{
		0x05, 0x02, 0x00, 0x02, // methods: no-auth, gssapi
		0x05, 0x01, 0x00, 0x01, // VER, CONNECT, RSV, IPv4
		192, 0, 2, 1, 0, 80,
	}
	br := bufio.NewReader(bytes.NewReader(client))
	var out bytes.Buffer
	if err := Negotiate(br, &out); err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	if !bytes.Equal(out.Bytes(), []byte{0x05, 0x00}) {
		t.Errorf("method reply = %v", out.Bytes())
	}
	req, err := ReadRequest(br)
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if req.Cmd != CmdConnect {
		t.Errorf("Cmd = 0x%02x", req.Cmd)
	}
	if req.Addr.String() != "192.0.2.1:80" {
		t.Errorf("Addr = %v", req.Addr)
	}
}

func TestNegotiateRequiresNoAuth(t *testing.T) {
	client := []byte{0x05, 0x01, 0x02} // only gssapi
	br := bufio.NewReader(bytes.NewReader(client))
	var out bytes.Buffer
	if err := Negotiate(br, &out); err == nil {
		t.Fatal("expected refusal")
	}
	if !bytes.Equal(out.Bytes(), []byte{0x05, 0xFF}) {
		t.Errorf("reply = %v, want 05 FF", out.Bytes())
	}
}

func TestReadRequestDomain(t *testing.T) {
	raw := []byte{0x05, 0x01, 0x00, 0x03, 0x0b}
	raw = append(raw, "example.com"...)
	raw = append(raw, 0x01, 0xbb) // 443
	req, err := ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if req.Addr.String() != "example.com:443" {
		t.Errorf("Addr = %v", req.Addr)
	}
}

func TestReplyRep(t *testing.T) {
	rep, err := ReplyRep(FailureReply(RepHostUnreach))
	if err != nil || rep != RepHostUnreach {
		t.Fatalf("rep=%d err=%v", rep, err)
	}
	if _, err := ReplyRep([]byte{0x05}); err == nil {
		t.Fatal("short reply must fail")
	}
}

// --- fixture upstream (minimal go-socks5-proxy stand-in) ---

type fixtureUpstream struct {
	ln     net.Listener
	mu     sync.Mutex
	targets []string
	reply  byte
	echo   bool // pipe accepted conns to the target
}

func startFixture(t *testing.T, reply byte, echo bool) *fixtureUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixtureUpstream{ln: ln, reply: reply, echo: echo}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fixtureUpstream) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fixtureUpstream) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	// method negotiation
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00})
	// request
	req, err := ReadRequest(br)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.targets = append(f.targets, req.Addr.String())
	f.mu.Unlock()

	if f.reply != RepSuccess {
		conn.Write(FailureReply(f.reply))
		return
	}
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if !f.echo {
		// hold open until client closes
		io.Copy(io.Discard, conn)
		return
	}
	up, err := net.Dial("tcp", req.Addr.String())
	if err != nil {
		conn.Close()
		return
	}
	go func() { io.Copy(up, br); up.Close() }()
	io.Copy(conn, up)
	conn.Close()
}

func (f *fixtureUpstream) Targets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.targets...)
}

func TestDialUpstreamSuccess(t *testing.T) {
	f := startFixture(t, RepSuccess, false)
	conn, reply, err := DialUpstream(context.Background(), f.ln.Addr().String(),
		protocol.Addr{Host: "198.51.100.9", Port: 8443, ATYP: protocol.ATYPIPv4}, 5*time.Second, "", "")
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	defer conn.Close()
	if conn == nil {
		t.Fatal("conn is nil on success")
	}
	rep, err := ReplyRep(reply)
	if err != nil || rep != RepSuccess {
		t.Fatalf("reply rep=%d err=%v", rep, err)
	}
	if got := f.Targets(); len(got) != 1 || got[0] != "198.51.100.9:8443" {
		t.Errorf("targets = %v", got)
	}
}

func TestDialUpstreamRefused(t *testing.T) {
	f := startFixture(t, RepHostUnreach, false)
	conn, reply, err := DialUpstream(context.Background(), f.ln.Addr().String(),
		protocol.Addr{Host: "example.com", Port: 80, ATYP: protocol.ATYPDomain}, 5*time.Second, "", "")
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	if conn != nil {
		t.Error("conn must be nil on refusal")
	}
	rep, err := ReplyRep(reply)
	if err != nil || rep != RepHostUnreach {
		t.Fatalf("reply rep=%d err=%v (raw=%v)", rep, err, reply)
	}
}

func TestDialUpstreamBadTarget(t *testing.T) {
	f := startFixture(t, RepSuccess, false)
	_, _, err := DialUpstream(context.Background(), "127.0.0.1:1" /* closed port */,
		protocol.Addr{Host: "example.com", Port: 80}, 500*time.Millisecond, "", "")
	if err == nil {
		t.Fatal("expected dial error")
	}
	_ = f
}

// --- RFC 1929 auth fixture (go-socks5-proxy -user/-password stand-in) ---

type authFixture struct {
	ln       net.Listener
	user, pass string
}

// startAuthFixture accepts only method 0x02 and validates credentials.
// If requireMethod00 is false it also accepts no-auth (for offer tests).
func startAuthFixture(t *testing.T, user, pass string) *authFixture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &authFixture{ln: ln, user: user, pass: pass}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *authFixture) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	// Require user/pass method to be offered and select it.
	hasUP := false
	for _, m := range methods {
		if m == AuthUserPass {
			hasUP = true
		}
	}
	if !hasUP {
		conn.Write([]byte{Version, AuthNoAccept})
		return
	}
	conn.Write([]byte{Version, AuthUserPass})
	// RFC 1929 subnegotiation
	var uh [2]byte
	if _, err := io.ReadFull(br, uh[:]); err != nil || uh[0] != 0x01 {
		return
	}
	u := make([]byte, uh[1])
	if _, err := io.ReadFull(br, u); err != nil {
		return
	}
	var plen [1]byte
	if _, err := io.ReadFull(br, plen[:]); err != nil {
		return
	}
	p := make([]byte, plen[0])
	if _, err := io.ReadFull(br, p); err != nil {
		return
	}
	if string(u) != f.user || string(p) != f.pass {
		conn.Write([]byte{0x01, 0x01}) // status: not allowed
		return
	}
	conn.Write([]byte{0x01, 0x00}) // success
	// CONNECT
	req, err := ReadRequest(br)
	if err != nil {
		return
	}
	_ = req
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	io.Copy(io.Discard, conn)
}

func TestDialUpstreamUserPassSuccess(t *testing.T) {
	f := startAuthFixture(t, "alice", "s3cret")
	conn, reply, err := DialUpstream(context.Background(), f.ln.Addr().String(),
		protocol.Addr{Host: "198.51.100.9", Port: 443, ATYP: protocol.ATYPIPv4},
		5*time.Second, "alice", "s3cret")
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	defer conn.Close()
	rep, err := ReplyRep(reply)
	if err != nil || rep != RepSuccess {
		t.Fatalf("reply rep=%d err=%v", rep, err)
	}
}

func TestDialUpstreamUserPassWrongPassword(t *testing.T) {
	f := startAuthFixture(t, "alice", "s3cret")
	_, _, err := DialUpstream(context.Background(), f.ln.Addr().String(),
		protocol.Addr{Host: "198.51.100.9", Port: 443, ATYP: protocol.ATYPIPv4},
		5*time.Second, "alice", "wrong")
	if err == nil {
		t.Fatal("expected auth rejection")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("socks5_user/socks5_password")) {
		t.Errorf("error should hint at config keys: %v", err)
	}
}

func TestDialUpstreamNoCredsAgainstAuthProxy(t *testing.T) {
	f := startAuthFixture(t, "alice", "s3cret")
	_, _, err := DialUpstream(context.Background(), f.ln.Addr().String(),
		protocol.Addr{Host: "198.51.100.9", Port: 443, ATYP: protocol.ATYPIPv4},
		5*time.Second, "", "")
	if err == nil {
		t.Fatal("expected 0xff refusal")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("socks5_user/socks5_password")) {
		t.Errorf("error should hint at config keys: %v", err)
	}
}

func TestDialUpstreamCredsAgainstNoAuthProxy(t *testing.T) {
	// no-auth fixture ignores credentials and still works when we offer both.
	f := startFixture(t, RepSuccess, false)
	conn, reply, err := DialUpstream(context.Background(), f.ln.Addr().String(),
		protocol.Addr{Host: "198.51.100.9", Port: 443, ATYP: protocol.ATYPIPv4},
		5*time.Second, "alice", "s3cret")
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	defer conn.Close()
	rep, err := ReplyRep(reply)
	if err != nil || rep != RepSuccess {
		t.Fatalf("reply rep=%d err=%v", rep, err)
	}
}
