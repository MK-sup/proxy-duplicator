// Package relay pumps bytes between a local connection and a multiplexed
// session through the Replicator, with SOCKS5 half-close semantics.
package relay

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"proxy-duplicator/internal/protocol"
	"proxy-duplicator/internal/session"
)

// TCP relays one SOCKS5 CONNECT session.
//
// Inbound frames arrive via Enqueue (Hooks.OnInbound, strict seq order) and
// are written to the local conn by a single down goroutine; the up goroutine
// reads the local conn into DATA frames. CLOSE frames implement half-close:
// reason 0 = peer write EOF (CloseWrite on our side), reason 1 = abort.
type TCP struct {
	sess    *session.Session
	local   net.Conn
	leftover []byte // bytes already buffered by the SOCKS reader (client side)
	send    func(*protocol.Frame) error
	destroy func(reason string) // table.Destroy (may be nil in tests)
	grace   time.Duration
	log     *slog.Logger

	down chan *protocol.Frame
	done chan struct{}
	once sync.Once

	wrMu         sync.Mutex // serializes local-conn writes (downWriter vs reject paths)

	upEOF, peerEOF atomic.Bool
	ackCh          chan ackResult // client side: OPEN_ACK outcome
	finMu          sync.Mutex     // guards graceTimer
	graceTimer     *time.Timer
	stopOnce       sync.Once
}

type ackResult struct {
	rep byte
	err error
}

// NewTCP builds a relay bound to local (not started). Set Sess and Destroy
// after session allocation, then call Start.
func NewTCP(local net.Conn, send func(*protocol.Frame) error, grace time.Duration, log *slog.Logger) *TCP {
	if grace <= 0 {
		grace = 30 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	return &TCP{
		local:  local,
		send:   send,
		grace:  grace,
		log:    log,
		down:   make(chan *protocol.Frame, 256),
		done:   make(chan struct{}),
		ackCh:  make(chan ackResult, 1),
	}
}

// Bind attaches the allocated session and the destroy function.
func (p *TCP) Bind(sess *session.Session, destroy func(string)) {
	p.sess = sess
	p.destroy = destroy
}

// SetLeftover queues bytes the SOCKS handshake reader buffered beyond the
// request; they are sent as the first DATA frames. Must be set before Start.
func (p *TCP) SetLeftover(b []byte) { p.leftover = b }

// BindLocal attaches the local conn on the server side, where the upstream
// connection only exists after the go-socks5-proxy handshake. Must be set
// before Start.
func (p *TCP) BindLocal(c net.Conn) { p.local = c }

// WriteLocal writes bytes to the local conn under the write lock (used by the
// SOCKS failure-reply path; the down writer uses the same lock so replies
// never interleave at the byte level).
func (p *TCP) WriteLocal(b []byte) error {
	p.wrMu.Lock()
	defer p.wrMu.Unlock()
	return writeAll(p.local, b)
}

// Enqueue hands one in-order inbound frame to the down writer
// (Hooks.OnInbound). Blocks while the down queue is full — real
// backpressure — but releases immediately if the relay is stopped.
func (p *TCP) Enqueue(f *protocol.Frame) {
	select {
	case p.down <- f:
	case <-p.done:
	}
}

// Start spawns the up/down goroutines. OPEN_ACK is written to the local conn
// when it arrives through the down queue (client side only; the server never
// receives one).
func (p *TCP) Start() {
	go p.up()
	go p.downWriter()
}

// WaitAck blocks until the OPEN_ACK is processed or timeout elapses.
// Returns the SOCKS5 reply status byte.
func (p *TCP) WaitAck(timeout time.Duration) (byte, error) {
	select {
	case r := <-p.ackCh:
		return r.rep, r.err
	case <-time.After(timeout):
		return 0, fmt.Errorf("OPEN_ACK timeout after %s", timeout)
	case <-p.done:
		return 0, fmt.Errorf("relay closed before OPEN_ACK")
	}
}

// Stop releases resources (idempotent). Called from Hooks.OnClose.
func (p *TCP) Stop(reason string) {
	p.stopOnce.Do(func() {
		close(p.done)
		p.finMu.Lock()
		if p.graceTimer != nil {
			p.graceTimer.Stop()
		}
		p.finMu.Unlock()
		if p.local != nil {
			_ = p.local.Close()
		}
	})
}

func (p *TCP) destroySelf(reason string) {
	if p.destroy != nil {
		p.destroy(reason) // table.Destroy → Stop via Hooks.OnClose
	} else {
		p.Stop(reason)
	}
}

// up reads the local conn into DATA frames.
func (p *TCP) up() {
	// Drain whatever the SOCKS handshake reader buffered past the request.
	if len(p.leftover) > 0 {
		if !p.sendBytes(p.leftover) {
			return
		}
		p.leftover = nil
	}
	buf := make([]byte, protocol.ReadChunk)
	for {
		select {
		case <-p.done:
			return
		default:
		}
		n, err := p.local.Read(buf)
		if n > 0 {
			if !p.sendBytes(buf[:n]) {
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				p.upEOF.Store(true)
				p.sendClose(protocol.CloseHalf)
				p.maybeFinish("local EOF")
				return
			}
			p.sendClose(protocol.CloseAbort)
			p.destroySelf("local read: " + err.Error())
			return
		}
	}
}

// sendBytes ships a chunk as one DATA frame; false means the relay is dead.
func (p *TCP) sendBytes(b []byte) bool {
	seq := p.sess.NextSeq()
	f, err := protocol.NewFrame(protocol.TypeData, p.sess.ID, seq, b)
	if err != nil {
		p.destroySelf("frame: " + err.Error())
		return false
	}
	if err := p.send(f); err != nil {
		p.destroySelf("send: " + err.Error())
		return false
	}
	return true
}

// downWriter writes in-order inbound frames to the local conn.
func (p *TCP) downWriter() {
	for {
		select {
		case <-p.done:
			return
		case f := <-p.down:
			switch f.Type {
			case protocol.TypeData:
				if err := p.WriteLocal(f.Payload); err != nil {
					p.sendClose(protocol.CloseAbort)
					p.destroySelf("local write: " + err.Error())
					return
				}
			case protocol.TypeOpenAck:
				if err := p.WriteLocal(f.Payload); err != nil {
					p.destroySelf("local write (ack): " + err.Error())
					return
				}
				rep := byte(0x01)
				if len(f.Payload) >= 2 {
					rep = f.Payload[1]
				}
				select {
				case p.ackCh <- ackResult{rep: rep}:
				default:
				}
				if rep != 0x00 {
					p.destroySelf(fmt.Sprintf("upstream refused (rep=0x%02x)", rep))
					return
				}
			case protocol.TypeClose:
				if f.Reason() == protocol.CloseHalf {
					p.peerEOF.Store(true)
					closeWrite(p.local)
					p.maybeFinish("peer half-close")
					// Keep running: local -> upstream direction may continue.
				} else {
					p.destroySelf("peer abort")
					return
				}
			}
		}
	}
}

// maybeFinish tears the session down once both directions hit EOF; the first
// half-close arms a grace timer for the other direction.
func (p *TCP) maybeFinish(why string) {
	p.finMu.Lock()
	defer p.finMu.Unlock()
	if p.upEOF.Load() && p.peerEOF.Load() {
		p.destroySelf("both directions closed (" + why + ")")
		return
	}
	if p.graceTimer == nil {
		p.graceTimer = time.AfterFunc(p.grace, func() {
			p.destroySelf("half-close grace expired")
		})
	}
}

func (p *TCP) sendClose(reason byte) {
	if p.sess == nil {
		return
	}
	seq := p.sess.NextSeq()
	f := protocol.NewClose(p.sess.ID, seq, reason)
	_ = p.send(f)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	_ = c.Close()
}
