package server

import (
	"fmt"
	"net"
	"sync"
	"time"

	"proxy-duplicator/internal/protocol"
	"proxy-duplicator/internal/session"
)

// udpState is the server-side owner of one UDP session: a dedicated ephemeral
// UDP socket plus a short-lived DNS cache.
type udpState struct {
	srv  *Server
	sess *session.Session

	mu    sync.Mutex
	conn  *net.UDPConn
	cache map[string]udpTarget
}

type udpTarget struct {
	ip  net.IP
	exp time.Time
}

// handleUDPData creates the session on the first datagram (seq 0) or feeds an
// existing one through dedup/reorder.
func (s *Server) handleUDPData(f *protocol.Frame) {
	sess := s.tab.Get(f.SessionID)
	if sess != nil {
		sess.HandleInbound(f)
		return
	}
	target, _, err := protocol.ParseUDPDatagram(f.Payload)
	if err != nil {
		s.log.Debug("udp data without session dropped", "session", f.SessionID, "err", err)
		return
	}
	// Open the socket BEFORE publishing the session: a concurrent tunnel
	// reader that hits the Get path must never see a nil conn (its copy is
	// the one that gets delivered — ours may be dropped as a duplicate).
	st := &udpState{srv: s, cache: make(map[string]udpTarget)}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		s.log.Warn("udp socket failed", "session", f.SessionID, "err", err)
		return
	}
	st.mu.Lock()
	st.conn = conn
	st.mu.Unlock()

	sess, created, err := s.tab.Create(f.SessionID, session.KindUDP, target.String(), st, session.Hooks{
		OnClose:   st.close,
		OnInbound: st.onDatagram,
	})
	if err != nil || !created {
		_ = conn.Close() // another reader won the race (or id rejected)
		return
	}
	st.sess = sess
	go st.readLoop(conn)
	s.log.Debug("udp session", "session", sess.ID, "first_target", target)
	sess.HandleInbound(f) // advances seq 0
}

// onDatagram is the in-order inbound path: strip the RFC1928 header, resolve
// the target, and send the payload from the server's socket.
func (st *udpState) onDatagram(f *protocol.Frame) {
	st.srv.log.Debug("udp inbound", "session", f.SessionID, "type", f.Type, "seq", f.Seq, "bytes", len(f.Payload))
	if f.Type != protocol.TypeUDPData {
		return
	}
	target, data, err := protocol.ParseUDPDatagram(f.Payload)
	if err != nil {
		st.srv.log.Debug("bad UDP_DATA", "session", f.SessionID, "err", err)
		return
	}
	raddr, err := st.resolve(target)
	if err != nil {
		st.srv.log.Debug("udp resolve failed", "session", f.SessionID, "target", target, "err", err)
		return
	}
	st.mu.Lock()
	conn := st.conn
	st.mu.Unlock()
	if conn == nil {
		return
	}
	if _, err := conn.WriteToUDP(data, raddr); err != nil {
		st.srv.log.Debug("udp send failed", "session", f.SessionID, "target", target, "err", err)
	} else {
		st.srv.log.Debug("udp sent", "session", f.SessionID, "target", target, "bytes", len(data))
	}
}

// resolve maps the datagram target to a UDP address (literals are direct;
// domains go through DNS with a 60s per-session cache).
func (st *udpState) resolve(target protocol.Addr) (*net.UDPAddr, error) {
	if ip := net.ParseIP(target.Host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: int(target.Port)}, nil
	}
	now := time.Now()
	st.mu.Lock()
	if t, ok := st.cache[target.Host]; ok && now.Before(t.exp) {
		st.mu.Unlock()
		return &net.UDPAddr{IP: t.ip, Port: int(target.Port)}, nil
	}
	st.mu.Unlock()

	ips, err := net.LookupIP(target.Host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = fmt.Errorf("no A/AAAA records")
		}
		return nil, err
	}
	ip := ips[0]
	st.mu.Lock()
	st.cache[target.Host] = udpTarget{ip: ip, exp: now.Add(60 * time.Second)}
	st.mu.Unlock()
	return &net.UDPAddr{IP: ip, Port: int(target.Port)}, nil
}

// readLoop turns replies from targets into UDP_REPLY frames.
func (st *udpState) readLoop(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed (session destroyed / shutdown)
		}
		st.sess.Touch()
		// Payload: compact source addr (the replying target) + data.
		src := protocol.Addr{Host: from.IP.String(), Port: uint16(from.Port)}
		payload := src.AppendTo(nil)
		room := st.srv.cfg.Limits.MaxFramePayload - len(payload)
		if n > room {
			st.srv.log.Debug("udp reply too large — dropped", "session", st.sess.ID, "size", n)
			continue
		}
		payload = append(payload, buf[:n]...)
		f, err := protocol.NewFrame(protocol.TypeUDPReply, st.sess.ID, st.sess.NextSeq(), payload)
		if err != nil {
			continue
		}
		if err := st.srv.rep.Send(f); err != nil {
			return // shutting down
		}
		st.srv.log.Debug("udp reply shipped", "session", st.sess.ID, "bytes", n, "from", from)
	}
}

// close is Hooks.OnClose: tear the socket down (idempotent).
func (st *udpState) close(reason string) {
	st.mu.Lock()
	conn := st.conn
	st.conn = nil
	st.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}
