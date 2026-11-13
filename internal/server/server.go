// Package server implements the dupd side: accepts N tunnel links, dedups
// duplicated frames, and forwards sessions to the local go-socks5-proxy (TCP)
// or straight out of the server (UDP).
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"proxy-duplicator/internal/config"
	"proxy-duplicator/internal/protocol"
	"proxy-duplicator/internal/relay"
	"proxy-duplicator/internal/session"
	"proxy-duplicator/internal/socks"
	"proxy-duplicator/internal/transport"
)

const (
	// maxTunnels is how many concurrent tunnel links dupd accepts (client
	// config `tunnels` must be <= this).
	maxTunnels = 8
	// pendingTTTL bounds frames that arrive for a session whose OPEN is still
	// in flight (OPEN skipped by a full queue on the client side).
	pendingTTL       = 10 * time.Second
	pendingPerSession = 64
)

type pendingFrame struct {
	f  *protocol.Frame
	at time.Time
}

// Server is dupd.
type Server struct {
	cfg *config.Config
	log *slog.Logger

	rep *transport.Replicator
	tab *session.Table
	ln  net.Listener

	mu      sync.Mutex
	pending map[uint32][]pendingFrame

	wg sync.WaitGroup
}

// Run starts the server and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	s := &Server{
		cfg:     cfg,
		log:     log,
		pending: make(map[uint32][]pendingFrame),
	}

	s.tab = session.NewTable(session.Options{
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

	s.rep = transport.NewReplicator(ctx, maxTunnels, transport.Options{
		QueueFrames:  cfg.Queue.Frames,
		MaxPayload:   cfg.Limits.MaxFramePayload,
		PingInterval: cfg.PingInterval.D(),
		PingTimeout:  cfg.PingTimeout.D(),
		Log:          log,
	})

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen tunnels %s: %w", cfg.Listen, err)
	}
	s.ln = ln
	log.Info("tunnel listener ready", "addr", ln.Addr().String(),
		"socks5_upstream", cfg.SOCKS5Upstream, "max_tunnels", maxTunnels)

	s.wg.Add(1)
	go s.acceptLoop(ctx)
	s.wg.Add(1)
	go s.janitor(ctx)

	<-ctx.Done()
	log.Info("shutting down")
	_ = ln.Close()
	s.tab.CloseAll("server shutdown")
	s.rep.CloseAll()
	s.wg.Wait()
	return nil
}

// acceptLoop assigns each incoming tunnel conn to a free replicator slot.
func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				s.log.Debug("tunnel accept", "err", err)
			}
			return
		}
		slot := s.freeSlot()
		if slot < 0 {
			s.log.Warn("no free tunnel slot — rejecting conn", "remote", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}
		stream := transport.NewStream(conn, fmt.Sprintf("peer#%d", slot))
		gen := s.rep.SetLink(slot, stream)
		go s.rep.ReadLoop(slot, stream, gen, s.onFrame)
	}
}

// freeSlot picks a down slot (single accept goroutine: no races).
func (s *Server) freeSlot() int {
	for i := 0; i < s.rep.Len(); i++ {
		if s.rep.State(i) == transport.LinkDown {
			return i
		}
	}
	return -1
}

// onFrame routes sequenced frames from either tunnel.
func (s *Server) onFrame(_ int, f *protocol.Frame) {
	if f.SessionID == 0 || !f.Type.Sequenced() {
		return
	}
	switch f.Type {
	case protocol.TypeOpen:
		s.handleOpen(f)
		return
	case protocol.TypeOpenAck, protocol.TypeUDPReply:
		s.log.Debug("unexpected server-bound frame", "type", f.Type, "session", f.SessionID)
		return
	case protocol.TypeUDPData:
		s.handleUDPData(f)
		return
	}

	sess := s.tab.Get(f.SessionID)
	if sess == nil {
		s.bufferPending(f)
		return
	}
	sess.HandleInbound(f)
}

// handleOpen creates the session from the client's OPEN (seq 0) and dials the
// upstream go-socks5-proxy in a goroutine (never on the tunnel reader).
func (s *Server) handleOpen(f *protocol.Frame) {
	if f.Seq != 0 {
		s.log.Debug("OPEN with nonzero seq dropped", "session", f.SessionID, "seq", f.Seq)
		return
	}
	target, n, err := protocol.ParseAddr(f.Payload)
	if err != nil || n != len(f.Payload) {
		s.log.Warn("bad OPEN payload", "session", f.SessionID, "err", err)
		return
	}

	p := relay.NewTCP(nil, s.rep.Send, s.cfg.RelayCloseGrace.D(), s.log)
	sess, created, err := s.tab.Create(f.SessionID, session.KindTCP, target.String(), p, session.Hooks{
		OnClose:   p.Stop,
		OnInbound: p.Enqueue,
	})
	if err != nil {
		s.log.Debug("OPEN rejected", "session", f.SessionID, "err", err)
		return
	}
	if !created {
		return // duplicate OPEN (requeued copy): first one is in charge
	}
	p.Bind(sess, func(reason string) { s.tab.Destroy(sess.ID, reason) })
	// The OPEN itself consumed seq 0: push it through the reorder so the
	// session's expected seq advances past it (relay ignores TypeOpen).
	sess.HandleInbound(f)
	s.flushPending(sess)

	s.log.Debug("OPEN", "session", sess.ID, "target", target)
	go s.connectUpstream(sess, p, target)
}

// connectUpstream completes the SOCKS5 handshake with go-socks5-proxy, echoes
// the raw reply as OPEN_ACK (seq 0), then starts the relay on success.
func (s *Server) connectUpstream(sess *session.Session, p *relay.TCP, target protocol.Addr) {
	conn, reply, err := socks.DialUpstream(context.Background(), s.cfg.SOCKS5Upstream, target, s.cfg.SOCKS5DialTimeout.D())
	if err != nil {
		s.log.Warn("upstream dial failed", "session", sess.ID, "target", target, "err", err)
		s.tab.Destroy(sess.ID, "upstream dial: "+err.Error())
		return
	}

	ack, err := protocol.NewFrame(protocol.TypeOpenAck, sess.ID, sess.NextSeq(), reply)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		s.tab.Destroy(sess.ID, "ack frame: "+err.Error())
		return
	}
	if err := s.rep.Send(ack); err != nil {
		if conn != nil {
			conn.Close()
		}
		s.tab.Destroy(sess.ID, "ack send: "+err.Error())
		return
	}
	if conn == nil {
		// Proxy replied with failure — ack already carried the status.
		s.tab.Destroy(sess.ID, "upstream refused")
		return
	}
	p.BindLocal(conn)
	p.Start()
}

// bufferPending parks frames that arrived for a session whose OPEN has not
// been processed yet (queue-skip on the OPEN frame), and sweeps stale ones.
func (s *Server) bufferPending(f *protocol.Frame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.pending[f.SessionID]
	if len(q) >= pendingPerSession {
		s.log.Debug("pending overflow — dropping frame",
			"session", f.SessionID, "type", f.Type, "seq", f.Seq)
		return
	}
	s.pending[f.SessionID] = append(q, pendingFrame{f: f, at: time.Now()})
}

func (s *Server) flushPending(sess *session.Session) {
	s.mu.Lock()
	q := s.pending[sess.ID]
	delete(s.pending, sess.ID)
	s.mu.Unlock()
	for _, pf := range q {
		sess.HandleInbound(pf.f)
	}
}

func (s *Server) sweepPending(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, q := range s.pending {
		kept := q[:0]
		for _, pf := range q {
			if now.Sub(pf.at) <= pendingTTL {
				kept = append(kept, pf)
			}
		}
		if len(kept) == 0 {
			delete(s.pending, id)
		} else {
			s.pending[id] = kept
		}
	}
}

// janitor runs session GC and the pending-frame sweep.
func (s *Server) janitor(ctx context.Context) {
	defer s.wg.Done()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if n := s.tab.GC(now); n > 0 {
				s.log.Debug("idle sessions swept", "count", n)
			}
			s.sweepPending(now)
		}
	}
}
