package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"proxy-duplicator/internal/client"
	"proxy-duplicator/internal/config"
	"proxy-duplicator/internal/server"
	"proxy-duplicator/internal/socks"
)

// freePort returns a loopback port that was free a moment ago.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", addr)
}

func testLogger() *slog.Logger {
	if os.Getenv("DUP_E2E_VERBOSE") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- fixture go-socks5-proxy stand-in ---

type fixtureUpstream struct {
	ln net.Listener
}

// startFixture is a minimal SOCKS5 server that CONNECTs to the requested
// target (stands in for serjs/go-socks5-proxy in tests).
func startFixture(t *testing.T) *fixtureUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixtureUpstream{ln: ln}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fixtureUpstream) Addr() string { return f.ln.Addr().String() }

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
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req, err := socks.ReadRequest(br)
	if err != nil {
		return
	}
	up, err := net.DialTimeout("tcp", req.Addr.String(), 5*time.Second)
	if err != nil {
		conn.Write(socks.FailureReply(socks.RepHostUnreach))
		return
	}
	defer up.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() {
		io.Copy(up, br)
		up.Close()
	}()
	io.Copy(conn, up)
}

// --- controllable TCP proxy (one per client-side route) ---

type tcpProxy struct {
	t       *testing.T
	backend string
	port    string

	mu     sync.Mutex
	ln     net.Listener
	conns  []net.Conn
	killed bool
}

func newTCPProxy(t *testing.T, backend string) *tcpProxy {
	t.Helper()
	full := freePort(t)
	_, port, err := net.SplitHostPort(full)
	if err != nil {
		t.Fatal(err)
	}
	p := &tcpProxy{t: t, backend: backend, port: port}
	p.reviveLockedStart()
	return p
}

func (p *tcpProxy) Addr() string { return "127.0.0.1:" + p.port }

// Revive re-opens the proxy on its previous port.
func (p *tcpProxy) Revive() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.killed = false
	p.reviveLockedStart()
}

func (p *tcpProxy) reviveLockedStart() {
	ln, err := net.Listen("tcp", "127.0.0.1:"+p.port)
	if err != nil {
		p.t.Errorf("proxy listen %s: %v", p.port, err)
		return
	}
	p.ln = ln
	go p.acceptLoop(ln)
}

func (p *tcpProxy) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		if p.killed {
			p.mu.Unlock()
			conn.Close()
			return
		}
		p.conns = append(p.conns, conn)
		p.mu.Unlock()
		go p.pipe(conn)
	}
}

func (p *tcpProxy) pipe(c net.Conn) {
	bc, err := net.DialTimeout("tcp", p.backend, time.Second)
	if err != nil {
		c.Close()
		return
	}
	p.mu.Lock()
	if p.killed {
		p.mu.Unlock()
		c.Close()
		bc.Close()
		return
	}
	p.conns = append(p.conns, bc)
	p.mu.Unlock()

	go func() { io.Copy(bc, c); bc.Close() }()
	io.Copy(c, bc)
	c.Close()
}

// Kill closes the listener and every tracked conn (tunnel outage).
func (p *tcpProxy) Kill() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.killed = true
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

// --- environment ---

type env struct {
	target     *httptest.Server
	fixture    *fixtureUpstream
	serverAddr string
	proxies    []*tcpProxy
	socksAddr  string

	ctx        context.Context
	cancel     context.CancelFunc
	serverDone chan struct{}
	clientDone chan struct{}
}

// startEnvBase boots fixture + dupd (no client yet); ctx is live.
func startEnvBase(t *testing.T, handler http.Handler) *env {
	t.Helper()

	e := &env{
		target:     httptest.NewServer(handler),
		fixture:    startFixture(t),
		serverAddr: freePort(t),
		serverDone: make(chan struct{}),
	}
	t.Cleanup(e.target.Close)

	serverCfg := writeConfig(t, fmt.Sprintf(`
mode: server
listen: "%s"
socks5_upstream: "%s"
ping_interval: 1s
ping_timeout: 5s
relay_close_grace: 5s
log: {level: error}
`, e.serverAddr, e.fixture.Addr()))
	scfg, err := config.Load(serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := scfg.Validate(config.ModeServer); err != nil {
		t.Fatal(err)
	}
	e.ctx, e.cancel = context.WithCancel(context.Background())

	go func() {
		defer close(e.serverDone)
		if err := server.Run(e.ctx, scfg, testLogger()); err != nil {
			t.Errorf("server: %v", err)
		}
	}()
	waitTCP(t, e.serverAddr, 5*time.Second)
	return e
}

// startClient boots dupc with the given client config body (must contain a
// socks5_listen — pass the env's socksAddr via fmt) and registers cleanup.
func (e *env) startClient(t *testing.T, clientYaml string) {
	t.Helper()
	e.socksAddr = freePort(t)
	clientYaml = clientYaml + fmt.Sprintf("\nsocks5_listen: %q\n", e.socksAddr)
	ccfgPath := writeConfig(t, clientYaml)
	ccfg, err := config.Load(ccfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ccfg.Validate(config.ModeClient); err != nil {
		t.Fatal(err)
	}
	e.clientDone = make(chan struct{})
	go func() {
		defer close(e.clientDone)
		if err := client.Run(e.ctx, ccfg, testLogger()); err != nil {
			t.Errorf("client: %v", err)
		}
	}()
	t.Cleanup(e.shutdown)
}

// startEnv boots fixture + dupd + 2 controllable proxies + dupc (plain).
// extraClientYaml is appended to the client config (may be "").
func startEnv(t *testing.T, handler http.Handler, extraClientYaml string) *env {
	t.Helper()
	return startEnvN(t, handler, 2, extraClientYaml)
}

// startEnvN is startEnv with n tunnels (n controllable proxies).
func startEnvN(t *testing.T, handler http.Handler, n int, extraClientYaml string) *env {
	t.Helper()
	e := startEnvBase(t, handler)

	addrs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		p := newTCPProxy(t, e.serverAddr)
		e.proxies = append(e.proxies, p)
		addrs = append(addrs, fmt.Sprintf("%q", p.Addr()))
	}

	e.startClient(t, fmt.Sprintf(`
mode: client
tunnels: %d
transport: plain
plain:
  addresses: [%s]
ping_interval: 1s
ping_timeout: 5s
reconnect: {initial: 200ms, max: 1s}
both_dead_close_after: 1s
relay_close_grace: 5s
queue: {frames: 512}
log: {level: error}
`, n, strings.Join(addrs, ", "))+extraClientYaml)
	return e
}

func (e *env) shutdown() {
	if e.cancel != nil {
		e.cancel()
	}
	wait := func(ch chan struct{}) {
		if ch == nil {
			return
		}
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			// hang protection: don't fail the test in cleanup
		}
	}
	wait(e.clientDone)
	wait(e.serverDone)
}

// socks5Dial is a minimal SOCKS5 CONNECT dialer (client-side test tool).
func socks5Dial(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	var m [2]byte
	if _, err := io.ReadFull(br, m[:]); err != nil {
		return fail(err)
	}
	if m[0] != 0x05 || m[1] != 0x00 {
		return fail(fmt.Errorf("method reply %v", m))
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fail(err)
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x02)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fail(fmt.Errorf("host too long"))
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	req = append(req, pb[:]...)
	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}

	var rh [4]byte
	if _, err := io.ReadFull(br, rh[:]); err != nil {
		return fail(err)
	}
	if rh[0] != 0x05 {
		return fail(fmt.Errorf("bad reply version %d", rh[0]))
	}
	var addrLen int
	switch rh[3] {
	case 0x01:
		addrLen = 4 + 2
	case 0x02:
		addrLen = 16 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return fail(err)
		}
		addrLen = int(l[0]) + 2
	default:
		return fail(fmt.Errorf("bad reply atyp %d", rh[3]))
	}
	if _, err := io.ReadFull(br, make([]byte, addrLen)); err != nil {
		return fail(err)
	}
	if rh[1] != 0x00 {
		return fail(fmt.Errorf("socks reply rep=0x%02x", rh[1]))
	}
	return &socksConn{Conn: conn, br: br}, nil
}

type socksConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *socksConn) Read(p []byte) (int, error) { return c.br.Read(p) }

// httpGet issues a GET through the dupc SOCKS5 listener.
func httpGet(t *testing.T, socksAddr, url string, timeout time.Duration) ([]byte, error) {
	t.Helper()
	body, _, err := httpDo(t, socksAddr, http.MethodGet, url, nil, timeout)
	return body, err
}

// httpPost issues a POST through the dupc SOCKS5 listener.
func httpPost(t *testing.T, socksAddr, url string, payload []byte, timeout time.Duration) ([]byte, error) {
	t.Helper()
	body, _, err := httpDo(t, socksAddr, http.MethodPost, url, payload, timeout)
	return body, err
}

func httpDo(t *testing.T, socksAddr, method, url string, payload []byte, timeout time.Duration) ([]byte, int, error) {
	t.Helper()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socks5Dial(ctx, socksAddr, addr)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, resp.StatusCode, fmt.Errorf("read body (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		return out, resp.StatusCode, fmt.Errorf("status %d", resp.StatusCode)
	}
	return out, resp.StatusCode, nil
}

// patternBody builds deterministic payload of size n.
func patternBody(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + i/251)
	}
	return b
}

func bytesEqual(a, b []byte) error {
	if len(a) != len(b) {
		return fmt.Errorf("len %d != %d", len(a), len(b))
	}
	if !bytes.Equal(a, b) {
		for i := range a {
			if a[i] != b[i] {
				return fmt.Errorf("first diff at %d: %d != %d", i, a[i], b[i])
			}
		}
	}
	return nil
}
