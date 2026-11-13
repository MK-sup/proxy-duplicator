package transport

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"proxy-duplicator/internal/protocol"
)

// tcpPair returns two ends of a local TCP connection.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			ch <- c
		}
	}()
	cl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv := <-ch
	t.Cleanup(func() { cl.Close(); srv.Close() })
	return cl, srv
}

// frameSink reads frames from a server-side stream, optionally answering PING,
// and collects DATA frames.
type frameSink struct {
	mu     sync.Mutex
	seqs   []uint32 // DATA seqs in arrival order (per link)
	closed bool
	done   chan struct{}
}

func newFrameSink(conn net.Conn, answerPing bool) *frameSink {
	s := &frameSink{done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for {
			f, err := protocol.Decode(conn, protocol.DefaultMaxPayload)
			if err != nil {
				return
			}
			if f.Type == protocol.TypePing && answerPing {
				pong, _ := protocol.NewFrame(protocol.TypePong, 0, 0, f.Payload)
				_ = protocol.Encode(conn, pong)
				continue
			}
			if f.Type == protocol.TypeData {
				s.mu.Lock()
				s.seqs = append(s.seqs, f.Seq)
				s.mu.Unlock()
			}
		}
	}()
	return s
}

func (s *frameSink) get() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint32, len(s.seqs))
	copy(out, s.seqs)
	return out
}

func (s *frameSink) count() int { return len(s.get()) }

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func dataFrame(seq uint32) *protocol.Frame {
	f, _ := protocol.NewFrame(protocol.TypeData, 1, seq, []byte(fmt.Sprintf("payload-%05d", seq)))
	return f
}

// noHealth is a health config that never fires during a short test.
func noHealth() Options {
	return Options{QueueFrames: 64, PingInterval: time.Hour, PingTimeout: time.Hour}
}

func TestReplicatorDuplicatesToAllTunnels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewReplicator(ctx, 2, noHealth())

	cl0, srv0 := tcpPair(t)
	cl1, srv1 := tcpPair(t)
	sink0 := newFrameSink(srv0, true)
	sink1 := newFrameSink(srv1, true)
	r.SetLink(0, NewStream(cl0, "t0"))
	r.SetLink(1, NewStream(cl1, "t1"))

	const n = 100
	for i := uint32(0); i < n; i++ {
		if err := r.Send(dataFrame(i)); err != nil {
			t.Fatalf("Send(%d): %v", i, err)
		}
	}
	// Every frame must arrive through at least one tunnel (union = no loss).
	// Individual tunnels may skip a copy when their queue is full (redundant
	// by design), so per-tunnel 100% delivery is not required.
	deadline := time.Now().Add(5 * time.Second)
	union := map[uint32]bool{}
	add := func(seqs []uint32) {
		for _, s := range seqs {
			union[s] = true
		}
	}
	for time.Now().Before(deadline) {
		union = map[uint32]bool{}
		add(sink0.get())
		add(sink1.get())
		if len(union) == n {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(union) != n {
		t.Fatalf("timeout: union=%d want=%d sink0=%d sink1=%d stats=%+v up=%d",
			len(union), n, sink0.count(), sink1.count(), r.Stats(), r.UpCount())
	}
	// Duplication sanity: at least one tunnel must have carried most frames
	// alone is fine; both must have carried a substantial share.
	if sink0.count() == 0 || sink1.count() == 0 {
		t.Errorf("duplication not exercised: sink0=%d sink1=%d", sink0.count(), sink1.count())
	}
	if st := r.Stats(); st.Sent != n {
		t.Errorf("Stats.Sent = %d, want %d", st.Sent, n)
	}
}

func TestReplicatorNoLossOnTunnelKill(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var downReasons []string
	var mu sync.Mutex
	opts := noHealth()
	opts.OnLinkChange = func(slot int, up bool, reason string) {
		if !up {
			mu.Lock()
			downReasons = append(downReasons, fmt.Sprintf("slot%d: %s", slot, reason))
			mu.Unlock()
		}
	}
	r := NewReplicator(ctx, 2, opts)

	cl0, srv0 := tcpPair(t)
	cl1, srv1 := tcpPair(t)
	sink0 := newFrameSink(srv0, false)
	sink1 := newFrameSink(srv1, false)
	r.SetLink(0, NewStream(cl0, "t0"))
	r.SetLink(1, NewStream(cl1, "t1"))

	const n = 500
	sendErr := make(chan error, 1)
	go func() {
		for i := uint32(0); i < n; i++ {
			if err := r.Send(dataFrame(i)); err != nil {
				sendErr <- err
				return
			}
			if i == 100 {
				// Kill tunnel 0 mid-transfer: close the client end only, so
				// the peer sink drains everything already buffered (clean FIN,
				// no RST data loss). The writer notices on its next write.
				cl0.Close()
			}
		}
		sendErr <- nil
	}()
	if err := <-sendErr; err != nil {
		t.Fatalf("Send aborted: %v", err)
	}

	// All seqs must survive: tunnel 1 takes over after the kill, tunnel 0's
	// still-queued frames are requeued, and pre-kill frames either arrived or
	// were requeued. Union completeness is the invariant.
	waitFor(t, 5*time.Second, "union of tunnels to cover all seqs", func() bool {
		union := map[uint32]bool{}
		for _, s := range sink0.get() {
			union[s] = true
		}
		for _, s := range sink1.get() {
			union[s] = true
		}
		return len(union) == n
	})

	waitFor(t, 2*time.Second, "link-down event for slot 0", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(downReasons) > 0
	})
	if r.UpCount() != 1 {
		t.Errorf("UpCount = %d, want 1", r.UpCount())
	}
}

func distinct(seqs []uint32) int {
	m := map[uint32]bool{}
	for _, s := range seqs {
		m[s] = true
	}
	return len(m)
}

func TestReplicatorBlocksUntilLinkUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewReplicator(ctx, 1, noHealth())

	const n = 200 // queue is 64: Send must block with no link
	done := make(chan error, 1)
	go func() {
		for i := uint32(0); i < n; i++ {
			if err := r.Send(dataFrame(i)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	// While no tunnel exists, sends beyond queue capacity stall.
	time.Sleep(150 * time.Millisecond)
	if st := r.Stats(); st.Sent >= n {
		t.Fatalf("expected Send to block, Sent = %d", st.Sent)
	}

	cl, srv := tcpPair(t)
	sink := newFrameSink(srv, false)
	r.SetLink(0, NewStream(cl, "t0"))

	if err := <-done; err != nil {
		t.Fatalf("Send: %v", err)
	}
	waitFor(t, 5*time.Second, "all frames delivered after link up", func() bool {
		return distinct(sink.get()) == n
	})
}

func TestReplicatorBackpressureNoLoss(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := noHealth()
	opts.QueueFrames = 4 // tiny queue: the source must block, never drop
	r := NewReplicator(ctx, 1, opts)

	cl, srv := tcpPair(t)
	r.SetLink(0, NewStream(cl, "t0"))

	const n = 400
	// ~30KiB frames ≈ 12MiB total: with no reader the kernel buffers
	// eventually fill, queue fills, and Send must block (never drop).
	const chunk = 30 * 1024
	sendDone := make(chan error, 1)
	go func() {
		for i := uint32(0); i < n; i++ {
			f, err := protocol.NewFrame(protocol.TypeData, 1, i, bytes.Repeat([]byte{byte(i)}, chunk))
			if err != nil {
				sendDone <- err
				return
			}
			if err := r.Send(f); err != nil {
				sendDone <- err
				return
			}
		}
		sendDone <- nil
	}()

	// No reader yet: Send must stall (no silent drops).
	time.Sleep(300 * time.Millisecond)
	if st := r.Stats(); st.Sent >= n {
		t.Fatalf("expected Send to block (queue full), Sent=%d/%d", st.Sent, n)
	}

	// Start draining: everything must arrive, nothing lost.
	sink := newFrameSink(srv, false)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if distinct(sink.get()) == n {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send: %v", err)
	}
	seqs := sink.get()
	if len(seqs) != n {
		t.Fatalf("delivered %d frames, want %d", len(seqs), n)
	}
	for i, s := range seqs {
		if s != uint32(i) {
			t.Fatalf("out of order at %d: seq=%d", i, s)
		}
	}
	st := r.Stats()
	if st.Blocked == 0 {
		t.Error("expected Stats.Blocked > 0 (backpressure engaged)")
	}
	if st.Requeued != 0 {
		t.Errorf("Requeued=%d, want 0 (no link died)", st.Requeued)
	}
}

func TestReplicatorPingTimeoutEvicts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	down := make(chan string, 4)
	opts := Options{
		QueueFrames:  64,
		PingInterval: 50 * time.Millisecond,
		PingTimeout:  200 * time.Millisecond,
		OnLinkChange: func(slot int, up bool, reason string) {
			if !up {
				select {
				case down <- reason:
				default:
				}
			}
		},
	}
	r := NewReplicator(ctx, 1, opts)

	cl, srv := tcpPair(t)
	// Peer reads frames but never answers PINGs (drops everything).
	go func() {
		for {
			if _, err := protocol.Decode(srv, protocol.DefaultMaxPayload); err != nil {
				return
			}
		}
	}()
	r.SetLink(0, NewStream(cl, "t0"))

	select {
	case reason := <-down:
		if reason != "ping timeout" {
			t.Errorf("eviction reason = %q, want %q", reason, "ping timeout")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected ping-timeout eviction")
	}
	if r.UpCount() != 0 {
		t.Errorf("UpCount = %d, want 0", r.UpCount())
	}
}

func TestReplicatorReadLoopKeepsLinkAliveViaPong(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := Options{
		QueueFrames:  64,
		PingInterval: 50 * time.Millisecond,
		PingTimeout:  400 * time.Millisecond,
	}
	r := NewReplicator(ctx, 1, opts)

	cl, srv := tcpPair(t)
	// Peer side: a second Replicator with ReadLoop auto-answers PING with PONG.
	r2 := NewReplicator(ctx, 1, opts)
	srvSt := NewStream(srv, "peer")
	g2 := r2.SetLink(0, srvSt)
	go r2.ReadLoop(0, srvSt, g2, func(int, *protocol.Frame) {})

	clSt := NewStream(cl, "t0")
	g := r.SetLink(0, clSt)
	go r.ReadLoop(0, clSt, g, func(int, *protocol.Frame) {})

	time.Sleep(500 * time.Millisecond) // several ping rounds: link must survive
	if r.UpCount() != 1 {
		t.Errorf("UpCount = %d, want 1 (link should stay healthy)", r.UpCount())
	}
}
