package transport

import (
	"context"
	"encoding/binary"
	"log/slog"
	"sync"
	"time"

	"proxy-duplicator/internal/protocol"
)

// LinkState is the health state of one tunnel.
type LinkState int

const (
	LinkDown LinkState = iota
	LinkUp
)

func (s LinkState) String() string {
	if s == LinkUp {
		return "up"
	}
	return "down"
}

// Options configures a Replicator.
type Options struct {
	// QueueFrames is the per-tunnel bounded send queue size.
	QueueFrames int
	// MaxPayload caps decoded frames.
	MaxPayload int
	// PingInterval / PingTimeout drive app-level stall detection per tunnel.
	PingInterval time.Duration
	PingTimeout  time.Duration
	// Log may be nil.
	Log *slog.Logger
	// OnLinkChange is fired (outside locks) whenever a tunnel transitions
	// up/down; the owner uses it to reconnect / count dead tunnels.
	OnLinkChange func(slot int, up bool, reason string)
}

// Stats is a snapshot of replication counters.
type Stats struct {
	Sent     uint64   // frames accepted by Send
	Requeued uint64   // frames re-submitted after a link eviction
	Blocked  uint64   // Send calls that entered the all-queues-full wait
	Skipped  []uint64 // per-slot: frames sent elsewhere while this queue was full
}

type slot struct {
	q        chan *protocol.Frame
	state    LinkState
	gen      uint64 // generation: bumped on SetLink and on eviction
	stream   *Stream
	done     chan struct{} // closed on eviction; writer exits
	lastPong time.Time
	pingFail int
}

// Replicator fans every frame out to all live tunnels. The receiver keeps the
// first copy of each (session, seq) and drops duplicates (dedup/reorder lives
// in internal/session).
//
// Send policy: non-blocking fan-out to every Up tunnel; success if >= 1 tunnel
// accepts (full queues of individual tunnels are skipped — the frame is
// redundant there). If ALL live queues are full, block the source (real
// backpressure, no frame loss). When a tunnel dies, its queued and in-flight
// frames are re-submitted through the survivors, so a frame is only ever lost
// if every tunnel is lost at once. While no tunnel is Up, Send blocks — the
// evicting goroutine holds the salvaged frames (bounded by one queue) until a
// tunnel recovers.
type Replicator struct {
	ctx    context.Context
	opts   Options
	logger *slog.Logger

	mu       sync.Mutex
	slots    []*slot
	sent     uint64
	requeued uint64
	blocked  uint64
	skipped  []uint64
	notifyCh chan struct{} // wakeups for Send waiters
}

// NewReplicator builds N tunnel slots and starts the health monitor.
func NewReplicator(ctx context.Context, n int, opts Options) *Replicator {
	if opts.QueueFrames <= 0 {
		opts.QueueFrames = 512
	}
	if opts.MaxPayload <= 0 {
		opts.MaxPayload = protocol.DefaultMaxPayload
	}
	if opts.PingInterval <= 0 {
		opts.PingInterval = 5 * time.Second
	}
	if opts.PingTimeout <= 0 {
		opts.PingTimeout = 15 * time.Second
	}
	r := &Replicator{
		ctx:      ctx,
		opts:     opts,
		logger:   opts.Log,
		slots:    make([]*slot, n),
		skipped:  make([]uint64, n),
		notifyCh: make(chan struct{}, 1),
	}
	for i := range r.slots {
		r.slots[i] = &slot{q: make(chan *protocol.Frame, opts.QueueFrames)}
	}
	go r.healthLoop()
	return r
}

func (r *Replicator) log() *slog.Logger {
	if r.logger != nil {
		return r.logger
	}
	return slog.Default()
}

// Len returns the tunnel count.
func (r *Replicator) Len() int { return len(r.slots) }

// UpCount returns the number of live tunnels.
func (r *Replicator) UpCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, s := range r.slots {
		if s.state == LinkUp {
			n++
		}
	}
	return n
}

// State returns the state of slot i.
func (r *Replicator) State(i int) LinkState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.slots[i].state
}

// Stats returns a counter snapshot.
func (r *Replicator) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	sk := make([]uint64, len(r.skipped))
	copy(sk, r.skipped)
	return Stats{Sent: r.sent, Requeued: r.requeued, Blocked: r.blocked, Skipped: sk}
}

// SetLink attaches a freshly established stream to slot i and starts its
// writer goroutine. It returns the link generation to pass to ReadLoop.
// Any previous stream for the slot is evicted first.
func (r *Replicator) SetLink(i int, stream *Stream) uint64 {
	r.mu.Lock()
	s := r.slots[i]
	var old *Stream
	if s.state == LinkUp && s.stream != nil {
		old = s.stream
		r.evictLocked(s, s.gen)
	}
	s.state = LinkUp
	s.gen++
	gen := s.gen
	s.stream = stream
	s.done = make(chan struct{})
	s.lastPong = time.Now()
	s.pingFail = 0
	done, q := s.done, s.q
	r.mu.Unlock()

	if old != nil {
		_ = old.Close()
		r.log().Warn("link replaced", "slot", i)
	}
	go r.runWriter(i, gen, stream, q, done)
	r.log().Info("link up", "slot", i, "link", stream.Name(), "gen", gen)
	r.fireLinkChange(i, true, "established")
	r.signal()
	return gen
}

// evictLocked marks the slot down and invalidates its generation.
// Caller holds r.mu.
func (r *Replicator) evictLocked(s *slot, gen uint64) {
	s.state = LinkDown
	s.gen++ // invalidate stale writer/reader/health calls for the old gen
	if s.done != nil {
		close(s.done)
		s.done = nil
	}
	s.stream = nil
}

// evict tears slot i down (if gen is current) and re-submits everything the
// tunnel still held — its queue plus the caller's in-flight frame — through
// the surviving tunnels. See Replicator docs for the no-tunnel case.
func (r *Replicator) evict(i int, gen uint64, inflight *protocol.Frame, reason string) {
	s := r.slots[i]

	r.mu.Lock()
	if s.gen != gen || s.state == LinkDown {
		// Stale generation (already evicted/replaced): only the in-flight
		// frame is ours to salvage.
		r.mu.Unlock()
		if inflight != nil {
			r.resend(inflight)
		}
		return
	}
	var requeue []*protocol.Frame
	if inflight != nil {
		requeue = append(requeue, inflight)
	}
drain:
	for {
		select {
		case f := <-s.q:
			requeue = append(requeue, f)
		default:
			break drain
		}
	}
	stream := s.stream
	r.evictLocked(s, gen)
	r.mu.Unlock()

	if stream != nil {
		_ = stream.Close()
	}
	r.log().Warn("link down", "slot", i, "reason", reason, "requeued", len(requeue))
	r.fireLinkChange(i, false, reason)
	r.signal()
	for _, f := range requeue {
		r.resend(f)
	}
}

// resend re-fans a salvaged frame out; blocks while no tunnel is Up.
func (r *Replicator) resend(f *protocol.Frame) {
	if err := r.Send(f); err == nil {
		r.mu.Lock()
		r.requeued++
		r.mu.Unlock()
	}
}

func (r *Replicator) fireLinkChange(i int, up bool, reason string) {
	if r.opts.OnLinkChange != nil {
		r.opts.OnLinkChange(i, up, reason)
	}
}

// runWriter owns writes for one tunnel generation.
func (r *Replicator) runWriter(i int, gen uint64, stream *Stream, q chan *protocol.Frame, done <-chan struct{}) {
	for {
		select {
		case f := <-q:
			if err := stream.WriteFrame(f); err != nil {
				r.evict(i, gen, f, "write: "+err.Error())
				return
			}
		case <-done:
			return
		case <-r.ctx.Done():
			_ = stream.Close()
			return
		}
	}
}

// CloseAll evicts every live link without requeue (shutdown path: Send is
// about to fail via context anyway) and closes their streams.
func (r *Replicator) CloseAll() {
	r.mu.Lock()
	type victim struct {
		s   *slot
		gen uint64
		st  *Stream
	}
	var vs []victim
	for _, s := range r.slots {
		if s.state == LinkUp && s.stream != nil {
			vs = append(vs, victim{s, s.gen, s.stream})
			r.evictLocked(s, s.gen)
		}
	}
	r.mu.Unlock()
	for _, v := range vs {
		_ = v.st.Close()
		r.log().Info("link closed (shutdown)", "gen", v.gen)
	}
	r.signal()
}

// ReadLoop reads frames from one tunnel generation until failure. PING/PONG
// are handled internally; everything else goes to onData (slot, frame).
// Must run in its own goroutine.
func (r *Replicator) ReadLoop(i int, stream *Stream, gen uint64, onData func(int, *protocol.Frame)) {
	for {
		r.mu.Lock()
		cur := r.slots[i].gen
		r.mu.Unlock()
		if cur != gen {
			return // link was evicted/replaced; stream is closed
		}
		f, err := stream.ReadFrame(r.opts.MaxPayload)
		if err != nil {
			r.evict(i, gen, nil, "read: "+err.Error())
			return
		}
		switch f.Type {
		case protocol.TypePing:
			pong, _ := protocol.NewFrame(protocol.TypePong, 0, 0, f.Payload)
			r.EnqueueTo(i, pong)
		case protocol.TypePong:
			r.markPong(i, gen)
		default:
			onData(i, f)
		}
	}
}

func (r *Replicator) markPong(i int, gen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.slots[i]
	if s.gen != gen || s.state != LinkUp {
		return
	}
	s.lastPong = time.Now()
	s.pingFail = 0
}

// EnqueueTo tries a non-blocking write of f into slot i's queue (used for
// per-tunnel PING/PONG control frames). Returns false if the slot is down or
// its queue is full.
func (r *Replicator) EnqueueTo(i int, f *protocol.Frame) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.slots[i]
	if s.state != LinkUp {
		return false
	}
	select {
	case s.q <- f:
		return true
	default:
		return false
	}
}

// Send fans f out to every live tunnel (see Replicator docs for the policy).
func (r *Replicator) Send(f *protocol.Frame) error {
	countedBlocked := false
	for {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		r.mu.Lock()
		accepts, liveUp := 0, false
		var full []int
		for i, s := range r.slots {
			if s.state != LinkUp {
				continue
			}
			liveUp = true
			select {
			case s.q <- f:
				accepts++
			default:
				full = append(full, i)
			}
		}
		if accepts > 0 {
			r.sent++
			for _, i := range full {
				r.skipped[i]++ // frame went elsewhere; this queue was full
			}
		} else if liveUp && !countedBlocked {
			r.blocked++
			countedBlocked = true
		}
		r.mu.Unlock()

		if accepts > 0 {
			return nil
		}
		// Either no tunnel is Up or every live queue is full: wait briefly
		// and retry (link changes wake us earlier via notifyCh).
		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-r.notifyCh:
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// signal wakes Send waiters after link state changes.
func (r *Replicator) signal() {
	select {
	case r.notifyCh <- struct{}{}:
	default:
	}
}

// healthLoop sends PINGs through each live tunnel's own queue and evicts
// tunnels that stop answering (or whose queues overflow with control frames).
func (r *Replicator) healthLoop() {
	ticker := time.NewTicker(r.opts.PingInterval)
	defer ticker.Stop()
	var pingSeq uint64
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			type victim struct {
				i   int
				gen uint64
				why string
			}
			var victims []victim

			r.mu.Lock()
			for i, s := range r.slots {
				if s.state != LinkUp {
					continue
				}
				if now.Sub(s.lastPong) > r.opts.PingTimeout {
					victims = append(victims, victim{i, s.gen, "ping timeout"})
					continue
				}
				var ts [8]byte
				pingSeq++
				binary.BigEndian.PutUint64(ts[:], pingSeq)
				ping, _ := protocol.NewFrame(protocol.TypePing, 0, 0, ts[:])
				select {
				case s.q <- ping:
					s.pingFail = 0
				default:
					s.pingFail++
					if s.pingFail >= 2 {
						victims = append(victims, victim{i, s.gen, "ping enqueue failed (queue wedged)"})
					}
				}
			}
			r.mu.Unlock()

			for _, v := range victims {
				r.evict(v.i, v.gen, nil, v.why)
			}
			r.signal()
		}
	}
}
