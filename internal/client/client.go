package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"proxy-duplicator/internal/config"
	"proxy-duplicator/internal/protocol"
	"proxy-duplicator/internal/relay"
	"proxy-duplicator/internal/session"
	"proxy-duplicator/internal/socks"
	"proxy-duplicator/internal/transport"
)

// Client is dupc: local SOCKS5 for Nekoray, N duplicated tunnels to dupd.
type Client struct {
	cfg *config.Config
	log *slog.Logger

	rep *transport.Replicator
	tab *session.Table
	udp *udpHub

	ln net.Listener

	gcStop chan struct{}
	wg     sync.WaitGroup
}

// Run starts the client and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	c := &Client{
		cfg:    cfg,
		log:    log,
		gcStop: make(chan struct{}),
	}

	c.tab = session.NewTable(session.Options{
		MaxSessions:      cfg.Limits.MaxSessions,
		ReorderMaxFrames: cfg.Limits.ReorderMaxFrames,
		ReorderMaxBytes:  cfg.Limits.ReorderMaxBytes,
		GapSkipTimeout:   cfg.Limits.GapSkipTimeout.D(),
		TCPIdle:          cfg.Limits.SessionIdleTCP.D(),
		UDPIdle:          cfg.Limits.UDPIdle.D(),
		Log:              log,
		OnSkip: func(id, from, to uint32) {
			log.Warn("seq gap skipped (frame lost on all tunnels)", "session", id, "from", from, "to", to)
		},
	})

	c.rep = transport.NewReplicator(ctx, cfg.Tunnels, transport.Options{
		QueueFrames:   cfg.Queue.Frames,
		MaxPayload:    cfg.Limits.MaxFramePayload,
		PingInterval:  cfg.PingInterval.D(),
		PingTimeout:   cfg.PingTimeout.D(),
		Log:           log,
		OnLinkChange:  nil, // tunnel managers poll state
	})
	c.udp = newUDPHub(c)

	ln, err := net.Listen("tcp", cfg.SOCKS5Listen)
	if err != nil {
		return fmt.Errorf("listen socks5 %s: %w", cfg.SOCKS5Listen, err)
	}
	c.ln = ln
	log.Info("socks5 listening", "addr", ln.Addr().String(), "tunnels", cfg.Tunnels, "transport", cfg.Transport)

	// Tunnel managers: one dial/reconnect loop per slot.
	for i := 0; i < cfg.Tunnels; i++ {
		c.wg.Add(1)
		go c.tunnelLoop(ctx, i)
	}
	// Session GC + both-dead watchdog.
	c.wg.Add(1)
	go c.janitor(ctx)

	c.wg.Add(1)
	go c.acceptLoop(ctx)

	<-ctx.Done()
	log.Info("shutting down")
	_ = ln.Close()
	c.udp.closeSocket()
	c.tab.CloseAll("client shutdown")
	c.rep.CloseAll()
	c.wg.Wait()
	return nil
}

// tunnelLoop keeps slot i alive: dial forever with backoff, hand the stream to
// the replicator, and redial when the link drops.
func (c *Client) tunnelLoop(ctx context.Context, slot int) {
	defer c.wg.Done()
	endpoints := c.endpointFor(slot)
	backoff := c.cfg.Reconnect.Initial.D()
	maxBackoff := c.cfg.Reconnect.Max.D()

	for ctx.Err() == nil {
		stream, err := c.dialTunnel(ctx, slot, endpoints)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Warn("tunnel dial failed", "slot", slot, "endpoint", endpoints, "err", err, "retry_in", backoff)
			if !sleep(ctx, backoff) {
				return
			}
			backoff = minDur(backoff*2, maxBackoff)
			continue
		}
		backoff = c.cfg.Reconnect.Initial.D()

		gen := c.rep.SetLink(slot, stream)
		go c.rep.ReadLoop(slot, stream, gen, c.onFrame)

		// Wait until this generation drops (poll + context).
		for ctx.Err() == nil {
			if !sleep(ctx, 300*time.Millisecond) {
				_ = stream.Close()
				return
			}
			if c.rep.State(slot) != transport.LinkUp {
				break
			}
		}
	}
}

func (c *Client) endpointFor(slot int) []string {
	var eps []string
	switch c.cfg.Transport {
	case config.TransportSSH:
		eps = c.cfg.SSH.Endpoints()
	default:
		eps = c.cfg.Plain.Endpoints()
	}
	if len(eps) == 0 {
		return nil
	}
	return []string{eps[slot%len(eps)]}
}

func (c *Client) dialTunnel(ctx context.Context, slot int, endpoints []string) (*transport.Stream, error) {
	name := fmt.Sprintf("%s#%d", c.cfg.Transport, slot)
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no endpoint for slot %d", slot)
	}
	addr := endpoints[0]
	switch c.cfg.Transport {
	case config.TransportSSH:
		return transport.DialSSH(ctx, transport.SSHDialConfig{
			Address:           addr,
			User:              c.cfg.SSH.User,
			Password:          c.cfg.SSH.Password,
			KeyFile:           expandHome(c.cfg.SSH.KeyFile),
			KeyPassphrase:     c.cfg.SSH.KeyPassphrase,
			HostKey:           c.cfg.SSH.HostKey,
			ConnectTimeout:    c.cfg.SSH.ConnectTimeout.D(),
			KeepaliveInterval: c.cfg.SSH.KeepaliveInterval.D(),
			ForwardHost:       "127.0.0.1",
			ForwardPort:       uint32(c.cfg.SSH.ForwardPort),
		}, name)
	default:
		return transport.DialPlain(ctx, addr, name, c.cfg.SSH.ConnectTimeout.D())
	}
}

func expandHome(p string) string {
	if len(p) > 0 && p[0] == '~' {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}

// onFrame routes sequenced frames from either tunnel into the session.
func (c *Client) onFrame(_ int, f *protocol.Frame) {
	if f.SessionID == 0 || !f.Type.Sequenced() {
		return // global/control frames are consumed by the replicator
	}
	switch f.Type {
	case protocol.TypeOpen, protocol.TypeUDPData:
		c.log.Debug("unexpected client-bound frame", "type", f.Type, "session", f.SessionID)
		return
	}
	s := c.tab.Get(f.SessionID)
	if s == nil {
		c.log.Debug("frame for unknown session", "type", f.Type, "session", f.SessionID, "seq", f.Seq)
		return
	}
	s.HandleInbound(f)
}

func (c *Client) acceptLoop(ctx context.Context) {
	defer c.wg.Done()
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				c.log.Debug("socks accept", "err", err)
			}
			return
		}
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.handleSocks(conn)
		}()
	}
}

func (c *Client) handleSocks(conn net.Conn) {
	br := bufio.NewReader(conn)
	if err := socks.Negotiate(br, conn); err != nil {
		c.log.Debug("socks negotiate failed", "remote", conn.RemoteAddr(), "err", err)
		_ = conn.Close()
		return
	}
	req, err := socks.ReadRequest(br)
	if err != nil {
		c.log.Debug("socks request failed", "err", err)
		_ = conn.Close()
		return
	}
	switch req.Cmd {
	case socks.CmdConnect:
		c.handleConnect(conn, br, req.Addr)
	case socks.CmdUDPAssoc:
		if err := c.handleUDPAssociate(conn); err != nil {
			c.log.Debug("udp associate failed", "err", err)
			_ = conn.Close()
		}
	default:
		_ = socks.WriteReply(conn, socks.RepCmdNotSup)
		_ = conn.Close()
	}
}

// handleConnect allocates a session, sends OPEN, waits for OPEN_ACK, then
// relays raw bytes until either side closes.
func (c *Client) handleConnect(conn net.Conn, br *bufio.Reader, target protocol.Addr) {
	p := relay.NewTCP(conn, c.rep.Send, c.cfg.RelayCloseGrace.D(), c.log)

	sess, err := c.tab.Alloc(session.KindTCP, target.String(), p, session.Hooks{
		OnClose:   p.Stop,
		OnInbound: p.Enqueue,
	})
	if err != nil {
		c.log.Warn("session alloc failed", "target", target, "err", err)
		_ = socks.WriteReply(conn, socks.RepGeneralFail)
		_ = conn.Close()
		return
	}
	p.Bind(sess, func(reason string) { c.tab.Destroy(sess.ID, reason) })

	// Bytes the handshake reader buffered past the request (early pipelining).
	if n := br.Buffered(); n > 0 {
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err == nil {
			p.SetLeftover(buf)
		}
	}

	open, err := protocol.NewFrame(protocol.TypeOpen, sess.ID, sess.NextSeq(), target.AppendTo(nil))
	if err != nil {
		c.tab.Destroy(sess.ID, "open frame: "+err.Error())
		_ = socks.WriteReply(conn, socks.RepGeneralFail)
		_ = conn.Close()
		return
	}
	if err := c.rep.Send(open); err != nil {
		c.tab.Destroy(sess.ID, "open send: "+err.Error())
		_ = socks.WriteReply(conn, socks.RepGeneralFail)
		_ = conn.Close()
		return
	}

	p.Start()
	if _, err := p.WaitAck(10 * time.Second); err != nil {
		c.log.Debug("connect failed", "target", target, "session", sess.ID, "err", err)
		_ = p.WriteLocal(socks.FailureReply(socks.RepHostUnreach))
		c.tab.Destroy(sess.ID, "connect: "+err.Error())
		return
	}
	c.log.Debug("session established", "session", sess.ID, "target", target)
}

// janitor runs session GC and the both-dead watchdog.
func (c *Client) janitor(ctx context.Context) {
	defer c.wg.Done()
	gcTick := time.NewTicker(30 * time.Second)
	deadTick := time.NewTicker(500 * time.Millisecond)
	defer gcTick.Stop()
	defer deadTick.Stop()

	var deadSince time.Time
	destroyed := false

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-gcTick.C:
			if n := c.tab.GC(now); n > 0 {
				c.log.Debug("idle sessions swept", "count", n)
			}
			st := c.rep.Stats()
			c.log.Debug("replication stats",
				"sent", st.Sent, "requeued", st.Requeued, "blocked", st.Blocked,
				"skipped", st.Skipped, "up", c.rep.UpCount(), "sessions", c.tab.Len())
		case <-deadTick.C:
			up := c.rep.UpCount()
			now := time.Now()
			switch {
			case up == 0:
				if deadSince.IsZero() {
					deadSince = now
					c.log.Warn("all tunnels down")
				} else if !destroyed && now.Sub(deadSince) > c.cfg.BothDeadCloseAfter.D() {
					c.log.Warn("all tunnels down too long — closing local sessions",
						"after", c.cfg.BothDeadCloseAfter.D())
					c.tab.CloseAll("all tunnels down")
					destroyed = true
				}
			default:
				if destroyed {
					c.log.Info("tunnel recovered", "up", up)
				}
				deadSince = time.Time{}
				destroyed = false
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
