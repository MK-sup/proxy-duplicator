package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHDialConfig describes one SSH tunnel: dial sshd, then open a direct-tcpip
// channel to the server-side dupd listener.
type SSHDialConfig struct {
	Address           string
	User              string
	Password          string
	KeyFile           string
	KeyPassphrase     string
	HostKey           string // pinned host key (authorized_keys line); "" = accept any (MITM risk)
	ConnectTimeout    time.Duration
	KeepaliveInterval time.Duration
	ForwardHost       string // server-side, usually 127.0.0.1
	ForwardPort       uint32 // server-side dupd listen port
	Log               *slog.Logger
}

// directTCPPayload is the SSH direct-tcpip channel open payload (field order
// matters: addr, port, originator addr, originator port).
type directTCPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// sshStream closes the channel, the SSH client, and the underlying TCP conn;
// it also stops the keepalive loop.
type sshStream struct {
	ssh.Channel
	client    *ssh.Client
	tcp       net.Conn
	stopKA    chan struct{}
	closeOnce sync.Once
}

func (s *sshStream) Close() error {
	s.closeOnce.Do(func() { close(s.stopKA) })
	_ = s.Channel.Close()
	_ = s.client.Close()
	_ = s.tcp.Close()
	return nil
}

// DialSSH establishes one SSH tunnel with its direct-tcpip channel.
func DialSSH(ctx context.Context, cfg SSHDialConfig, name string) (*Stream, error) {
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.ForwardHost == "" {
		cfg.ForwardHost = "127.0.0.1"
	}
	if cfg.ForwardPort == 0 {
		cfg.ForwardPort = 9000
	}

	d := net.Dialer{Timeout: cfg.ConnectTimeout, KeepAlive: 30 * time.Second}
	tcp, err := d.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("ssh tcp dial %s: %w", cfg.Address, err)
	}
	if tc, ok := tcp.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	hostKeyCB, err := hostKeyCallback(cfg.HostKey)
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}
	auths, err := authMethods(cfg)
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}

	cc, chans, reqs, err := ssh.NewClientConn(tcp, cfg.Address, &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auths,
		HostKeyCallback: hostKeyCB,
		Timeout:         cfg.ConnectTimeout,
	})
	if err != nil {
		_ = tcp.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", cfg.Address, err)
	}
	client := ssh.NewClient(cc, chans, reqs)

	stopKA := make(chan struct{})
	go keepaliveLoop(client, cfg.KeepaliveInterval, stopKA, cfg.Log, func() {
		_ = client.Close()
		_ = tcp.Close()
	})

	ch, chReqs, err := client.OpenChannel("direct-tcpip", ssh.Marshal(&directTCPPayload{
		DestAddr:   cfg.ForwardHost,
		DestPort:   cfg.ForwardPort,
		OriginAddr: "127.0.0.1",
		OriginPort: 0,
	}))
	if err != nil {
		close(stopKA)
		_ = client.Close()
		_ = tcp.Close()
		return nil, fmt.Errorf("open direct-tcpip %s:%d: %w", cfg.ForwardHost, cfg.ForwardPort, err)
	}
	go ssh.DiscardRequests(chReqs)

	return NewStream(&sshStream{Channel: ch, client: client, tcp: tcp, stopKA: stopKA}, name), nil
}

func hostKeyCallback(pinned string) (ssh.HostKeyCallback, error) {
	if pinned == "" {
		// No pin configured: accept any host key. The MITM trade-off is
		// documented in the README — set ssh.host_key to close it.
		return ssh.InsecureIgnoreHostKey(), nil
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pinned))
	if err != nil {
		return nil, fmt.Errorf("parse ssh.host_key: %w", err)
	}
	return ssh.FixedHostKey(pk), nil
}

func authMethods(cfg SSHDialConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if cfg.KeyFile != "" {
		var raw []byte
		raw, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read ssh key %s: %w", cfg.KeyFile, err)
		}
		var signer ssh.Signer
		if cfg.KeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(raw, []byte(cfg.KeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(raw)
		}
		if err != nil {
			return nil, fmt.Errorf("parse ssh key %s: %w", cfg.KeyFile, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		methods = append(methods, ssh.Password(cfg.Password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no ssh auth configured (password or key_file)")
	}
	return methods, nil
}

// keepaliveFails is how many consecutive transport errors (err != nil) it
// takes to tear the connection down. A REQUEST_FAILURE (!ok) is NOT fatal —
// some servers/middleboxes refuse the request while the link is healthy;
// app-level PING/PONG is the primary liveness check.
const keepaliveFails = 4

// keepaliveTracker counts consecutive hard failures (transport errors only).
type keepaliveTracker struct {
	fails     int
	threshold int
}

// record classifies one probe: err != nil is a hard fail (counts toward
// teardown); a refused request (!ok without err) resets nothing and never
// counts. Returns true when the connection should be torn down.
func (k *keepaliveTracker) record(err error) bool {
	if err != nil {
		k.fails++
		return k.fails >= k.threshold
	}
	k.fails = 0
	return false
}

// keepaliveLoop issues keepalive@openssh.com requests; only real transport
// errors count toward teardown (the channel read then errors and the
// replicator evicts the link). Exits on stop. interval <= 0 disables it.
func keepaliveLoop(client *ssh.Client, interval time.Duration, stop <-chan struct{}, log *slog.Logger, onDead func()) {
	if interval <= 0 {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	k := &keepaliveTracker{threshold: keepaliveFails}
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if k.record(err) {
				log.Warn("ssh keepalive failed — tearing down connection",
					"fails", k.fails, "threshold", k.threshold, "err", err)
				onDead()
				return
			}
			if err != nil {
				log.Warn("ssh keepalive error", "err", err, "fails", k.fails, "threshold", k.threshold)
				continue
			}
			if !ok {
				log.Debug("ssh keepalive refused by peer (ignored)")
			}
		}
	}
}
