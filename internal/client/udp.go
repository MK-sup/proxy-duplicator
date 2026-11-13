package client

import (
	"fmt"
	"io"
	"net"
	"sync"

	"proxy-duplicator/internal/protocol"
	"proxy-duplicator/internal/session"
	"proxy-duplicator/internal/socks"
)

// udpEntry is the client-side owner state of one UDP ASSOCIATE session.
type udpEntry struct {
	hub   *udpHub
	sess  *session.Session
	conn  net.Conn   // SOCKS5 control conn (lifecycle anchor)
	src   *net.UDPAddr // Nekoray's datagram source (set on first datagram)
	bound bool
}

// udpHub owns the local UDP relay socket and the src->session bindings.
//
// Binding rules: the first datagram from an unbound source binds it to the
// newest ASSOCIATE session still without a source; later datagrams from that
// source reuse the binding (one seq space per source). Bindings die with
// their control conn or the session (idle GC / both-dead).
type udpHub struct {
	c *Client

	mu      sync.Mutex
	pc      *net.UDPConn
	pending []*udpEntry // ASSOCIATE sessions awaiting their first datagram
	bySrc   map[string]*udpEntry
}

func newUDPHub(c *Client) *udpHub {
	return &udpHub{c: c, bySrc: make(map[string]*udpEntry)}
}

// relaySocket lazily binds the local UDP relay (cfg.udp_relay).
func (h *udpHub) relaySocket() (*net.UDPConn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pc != nil {
		return h.pc, nil
	}
	addr, err := net.ResolveUDPAddr("udp", h.c.cfg.UDPRelay)
	if err != nil {
		return nil, fmt.Errorf("resolve udp_relay %q: %w", h.c.cfg.UDPRelay, err)
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind udp_relay %s: %w", h.c.cfg.UDPRelay, err)
	}
	h.pc = pc
	go h.readLoop(pc)
	h.c.log.Info("udp relay listening", "addr", pc.LocalAddr())
	return pc, nil
}

func (h *udpHub) addPending(e *udpEntry) {
	h.mu.Lock()
	h.pending = append(h.pending, e)
	h.mu.Unlock()
}

// bind resolves the source addr of an inbound datagram to a session entry.
func (h *udpHub) bind(src *net.UDPAddr) *udpEntry {
	key := src.String()
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok := h.bySrc[key]; ok && !e.sess.Closed() {
		return e
	}
	// Newest ASSOCIATE session without a source yet.
	for i := len(h.pending) - 1; i >= 0; i-- {
		e := h.pending[i]
		if e.sess.Closed() {
			continue
		}
		e.src = src
		e.bound = true
		h.pending = append(h.pending[:i], h.pending[i+1:]...)
		h.bySrc[key] = e
		return e
	}
	return nil
}

func (h *udpHub) release(e *udpEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, p := range h.pending {
		if p == e {
			h.pending = append(h.pending[:i], h.pending[i+1:]...)
			break
		}
	}
	if e.bound && e.src != nil {
		key := e.src.String()
		if cur, ok := h.bySrc[key]; ok && cur == e {
			delete(h.bySrc, key)
		}
	}
}

// closeSocket closes the relay socket at shutdown (readLoop exits).
func (h *udpHub) closeSocket() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pc != nil {
		_ = h.pc.Close()
		h.pc = nil
	}
}

// readLoop demuxes Nekoray's datagrams into sessions and ships them as
// UDP_DATA frames over every tunnel.
func (h *udpHub) readLoop(pc *net.UDPConn) {
	buf := make([]byte, 65535+64)
	maxPayload := h.c.cfg.Limits.MaxFramePayload
	for {
		n, src, err := pc.ReadFromUDP(buf)
		if err != nil {
			return // relay socket closed at shutdown
		}
		e := h.bind(src)
		if e == nil {
			h.c.log.Debug("udp datagram without ASSOCIATE — dropped", "src", src)
			continue
		}
		if n > maxPayload-32 {
			h.c.log.Debug("udp datagram too large — dropped", "src", src, "size", n)
			continue
		}
		dgram := make([]byte, n)
		copy(dgram, buf[:n])
		if _, _, err := protocol.ParseUDPDatagram(dgram); err != nil {
			h.c.log.Debug("bad udp datagram — dropped", "src", src, "err", err)
			continue
		}
		if e.sess.Closed() {
			continue
		}
		f, err := protocol.NewFrame(protocol.TypeUDPData, e.sess.ID, e.sess.NextSeq(), dgram)
		if err != nil {
			continue
		}
		if err := h.c.rep.Send(f); err != nil {
			return // shutting down
		}
	}
}

// handleUDPAssociate implements SOCKS5 UDP ASSOCIATE: reply with the local
// relay address and keep the control conn open as the session anchor.
func (c *Client) handleUDPAssociate(conn net.Conn) error {
	pc, err := c.udp.relaySocket()
	if err != nil {
		_ = socks.WriteReply(conn, socks.RepGeneralFail)
		return err
	}
	e := &udpEntry{hub: c.udp, conn: conn}
	sess, err := c.tab.Alloc(session.KindUDP, "udp-assoc:"+conn.RemoteAddr().String(), e, session.Hooks{
		OnClose:   func(string) { c.udpRelease(e) },
		OnInbound: func(f *protocol.Frame) { c.udpDeliver(e, f) },
	})
	if err != nil {
		_ = socks.WriteReply(conn, socks.RepGeneralFail)
		return err
	}
	e.sess = sess
	c.udp.addPending(e)

	// Reply: BND.ADDR/BND.PORT = relay socket.
	relayAddr := pc.LocalAddr().(*net.UDPAddr)
	ip4 := relayAddr.IP.To4()
	if ip4 == nil {
		ip4 = net.IPv4(127, 0, 0, 1).To4()
	}
	reply := []byte{socks.Version, socks.RepSuccess, 0x00, 0x01}
	reply = append(reply, ip4...)
	reply = append(reply, byte(relayAddr.Port>>8), byte(relayAddr.Port))
	if _, err := conn.Write(reply); err != nil {
		c.tab.Destroy(sess.ID, "assoc reply write: "+err.Error())
		return err
	}
	c.log.Debug("udp associate", "session", sess.ID, "relay", relayAddr.String())

	// The association lives until the control conn closes.
	go func() {
		_, _ = io.Copy(io.Discard, conn) // blocks until peer closes
		c.tab.Destroy(sess.ID, "assoc control conn closed")
	}()
	return nil
}

// udpRelease removes hub state for a dying session.
func (c *Client) udpRelease(e *udpEntry) {
	if e.hub != nil {
		e.hub.release(e)
	}
	if e.conn != nil {
		_ = e.conn.Close()
	}
}

// udpDeliver wraps an inbound UDP_REPLY into RFC1928 form and sends it back
// to Nekoray's datagram source.
func (c *Client) udpDeliver(e *udpEntry, f *protocol.Frame) {
	if f.Type != protocol.TypeUDPReply {
		return
	}
	addr, n, err := protocol.ParseAddr(f.Payload)
	if err != nil {
		c.log.Debug("bad UDP_REPLY addr", "session", f.SessionID, "err", err)
		return
	}
	e.hub.mu.Lock()
	pc, src := e.hub.pc, e.src
	e.hub.mu.Unlock()
	if pc == nil || src == nil {
		return // relay closed or no bound source yet
	}
	wire := []byte{0x00, 0x00, 0x00} // RSV, RSV, FRAG
	wire = addr.AppendTo(wire)
	wire = append(wire, f.Payload[n:]...)

	if _, err := pc.WriteToUDP(wire, src); err != nil {
		c.log.Debug("udp reply write failed", "session", f.SessionID, "err", err)
	} else {
		c.log.Debug("udp reply delivered", "session", f.SessionID, "bytes", len(wire), "to", src)
	}
}
