package session

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"proxy-duplicator/internal/protocol"
)

// Kind distinguishes TCP pipe sessions from UDP sessions (different idle GC).
type Kind uint8

const (
	KindTCP Kind = iota
	KindUDP
)

func (k Kind) String() string {
	if k == KindUDP {
		return "udp"
	}
	return "tcp"
}

// Hooks receive session lifecycle events. OnInbound is called from inside the
// reorder push (strict seq order); it may block — it runs on a tunnel reader
// goroutine, so implementations should hand off to their own queues. OnClose
// fires exactly once (GC, peer CLOSE, abort, idle timeout).
type Hooks struct {
	OnClose   func(reason string)
	OnInbound func(f *protocol.Frame)
}

// Session is one multiplexed flow (a SOCKS5 CONNECT pipe or a UDP binding).
// Owner carries side-specific state (local conn, upstream conn, socket, ...).
type Session struct {
	ID     uint32
	Kind   Kind
	Target string
	Owner  any

	table    *Table
	hooks    Hooks
	in       *Reorder
	pushMu   sync.Mutex // serializes inbound delivery from both tunnel readers
	nextSeq  atomic.Uint32
	activeAt atomic.Int64 // unix nano of last activity in either direction
	closed   atomic.Bool

	closeOnce sync.Once
}

// NextSeq allocates the next outgoing sequence number for this side
// (first call returns 0 — reserved for OPEN / OPEN_ACK).
func (s *Session) NextSeq() uint32 { return s.nextSeq.Add(1) - 1 }

// Touch marks activity (used by GC).
func (s *Session) Touch() { s.activeAt.Store(time.Now().UnixNano()) }

// LastActivity returns the last touch time.
func (s *Session) LastActivity() time.Time { return time.Unix(0, s.activeAt.Load()) }

// Closed reports whether Close already ran.
func (s *Session) Closed() bool { return s.closed.Load() }

// Close invokes the owner callback exactly once (local resource teardown).
func (s *Session) Close(reason string) {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.hooks.OnClose != nil {
			s.hooks.OnClose(reason)
		}
	})
}

// Inbound returns the dedup/reorder buffer for frames arriving for this
// session on this side.
func (s *Session) Inbound() *Reorder { return s.in }

// HandleInbound dedups/reorders one incoming sequenced frame and delivers it
// in order to Hooks.OnInbound. Safe to call concurrently from multiple tunnel
// readers (serialized per session).
func (s *Session) HandleInbound(f *protocol.Frame) {
	s.Touch()
	s.pushMu.Lock()
	defer s.pushMu.Unlock()
	s.in.Push(f, time.Now(), func(fr *protocol.Frame) {
		if s.hooks.OnInbound != nil {
			s.hooks.OnInbound(fr)
		}
	})
}

// Options configures a Table.
type Options struct {
	MaxSessions      int
	ReorderMaxFrames int
	ReorderMaxBytes  int
	GapSkipTimeout   time.Duration
	TCPIdle          time.Duration
	UDPIdle          time.Duration
	Log              *slog.Logger
	// OnSkip is invoked when reorder jumps a seq hole (lost on all tunnels).
	OnSkip func(sessionID uint32, from, to uint32)
}

// Table owns all sessions of one side plus tombstones that swallow late
// frames of already-freed sessions.
type Table struct {
	opts Options
	log  *slog.Logger

	mu         sync.RWMutex
	sessions   map[uint32]*Session
	tombstones map[uint32]time.Time // freed id -> expiry
	nextID     uint32
}

// NewTable creates an empty session table.
func NewTable(opts Options) *Table {
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = 8192
	}
	if opts.TCPIdle <= 0 {
		opts.TCPIdle = 120 * time.Second
	}
	if opts.UDPIdle <= 0 {
		opts.UDPIdle = 60 * time.Second
	}
	return &Table{
		opts:       opts,
		log:        opts.Log,
		sessions:   make(map[uint32]*Session),
		tombstones: make(map[uint32]time.Time),
	}
}

func (t *Table) logger() *slog.Logger {
	if t.log != nil {
		return t.log
	}
	return slog.Default()
}

// Create registers a session with an explicit id (server side: id comes from
// the OPEN / first UDP_DATA frame). Duplicate OPEN with the same target
// returns the existing session with created=false; a different target or a
// tombstoned id is an error.
func (t *Table) Create(id uint32, kind Kind, target string, owner any, hooks Hooks) (*Session, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.sessions[id]; ok {
		if kind == KindUDP || s.Target == target {
			return s, false, nil // idempotent duplicate OPEN / first datagram
		}
		return nil, false, fmt.Errorf("session %d already exists (target %q, new %q)", id, s.Target, target)
	}
	if _, ok := t.tombstones[id]; ok {
		return nil, false, fmt.Errorf("session %d is tombstoned (late frame?)", id)
	}
	if len(t.sessions) >= t.opts.MaxSessions {
		return nil, false, fmt.Errorf("max sessions %d reached", t.opts.MaxSessions)
	}
	s := t.newSession(id, kind, target, owner, hooks)
	t.sessions[id] = s
	return s, true, nil
}

// Alloc creates a session with a fresh id (client side).
func (t *Table) Alloc(kind Kind, target string, owner any, hooks Hooks) (*Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.sessions) >= t.opts.MaxSessions {
		return nil, fmt.Errorf("max sessions %d reached", t.opts.MaxSessions)
	}
	for i := 0; i <= t.opts.MaxSessions+1; i++ {
		id := t.nextID
		t.nextID++
		if t.nextID == 0 {
			t.nextID = 1 // id 0 is reserved (tunnel-global PING/PONG)
		}
		if _, used := t.sessions[id]; used || id == 0 {
			continue
		}
		if _, tomb := t.tombstones[id]; tomb {
			continue // never hand out a tombstoned id
		}
		s := t.newSession(id, kind, target, owner, hooks)
		t.sessions[id] = s
		return s, nil
	}
	return nil, fmt.Errorf("no free session id (max %d)", t.opts.MaxSessions)
}

func (t *Table) newSession(id uint32, kind Kind, target string, owner any, hooks Hooks) *Session {
	now := time.Now()
	s := &Session{
		ID:     id,
		Kind:   kind,
		Target: target,
		Owner:  owner,
		table:  t,
		hooks:  hooks,
	}
	s.activeAt.Store(now.UnixNano())
	var skipCB func(uint32, uint32)
	if t.opts.OnSkip != nil {
		sid := id
		skipCB = func(from, to uint32) { t.opts.OnSkip(sid, from, to) }
	}
	s.in = NewReorder(now, t.opts.ReorderMaxFrames, t.opts.ReorderMaxBytes, t.opts.GapSkipTimeout, skipCB)
	return s
}

// Get looks up a session and refreshes its activity timestamp. Returns
// nil for unknown or tombstoned ids (late frames are silently dropped by
// callers).
func (t *Table) Get(id uint32) *Session {
	t.mu.RLock()
	s, ok := t.sessions[id]
	t.mu.RUnlock()
	if !ok {
		return nil
	}
	s.Touch()
	return s
}

// Len returns the live session count.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// Destroy closes a session (owner callback fires once), removes it from the
// table, and tombstones the id so late frames are swallowed.
func (t *Table) Destroy(id uint32, reason string) {
	t.mu.Lock()
	s, ok := t.sessions[id]
	if ok {
		delete(t.sessions, id)
		t.tombstones[id] = time.Now().Add(t.idle(s.Kind))
	}
	t.mu.Unlock()
	if ok {
		t.logger().Debug("session destroyed", "id", id, "kind", s.Kind, "reason", reason)
		s.Close(reason)
	}
}

func (t *Table) idle(k Kind) time.Duration {
	if k == KindUDP {
		return t.opts.UDPIdle
	}
	return t.opts.TCPIdle
}

// CloseAll destroys every session with the given reason (shutdown path).
func (t *Table) CloseAll(reason string) {
	t.mu.Lock()
	all := make([]*Session, 0, len(t.sessions))
	for id, s := range t.sessions {
		all = append(all, s)
		delete(t.sessions, id)
		t.tombstones[id] = time.Now().Add(t.idle(s.Kind))
	}
	t.mu.Unlock()
	for _, s := range all {
		s.Close(reason)
	}
}

// GC sweeps idle sessions (destroy + tombstone) and expired tombstones.
// Returns the number of sessions destroyed. Intended to be called periodically
// from a ticker goroutine.
func (t *Table) GC(now time.Time) int {
	type victim struct {
		s   *Session
		why string
	}
	var kill []victim

	t.mu.Lock()
	for id, s := range t.sessions {
		if now.Sub(s.LastActivity()) > t.idle(s.Kind) {
			kill = append(kill, victim{s, "idle timeout"})
			delete(t.sessions, id)
			t.tombstones[id] = now.Add(t.idle(s.Kind))
		}
	}
	for id, exp := range t.tombstones {
		if now.After(exp) {
			delete(t.tombstones, id)
		}
	}
	t.mu.Unlock()

	for _, v := range kill {
		t.logger().Debug("session idle-GC", "id", v.s.ID, "kind", v.s.Kind, "target", v.s.Target)
		v.s.Close(v.why)
	}
	return len(kill)
}
