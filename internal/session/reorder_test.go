package session

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"proxy-duplicator/internal/protocol"
)

func frame(seq uint32) *protocol.Frame {
	f, _ := protocol.NewFrame(protocol.TypeData, 1, seq, []byte(fmt.Sprintf("d%05d", seq)))
	return f
}

// collect builds a deliver sink that records delivered seqs.
func collect() (func(*protocol.Frame), func() []uint32) {
	var got []uint32
	return func(f *protocol.Frame) { got = append(got, f.Seq) },
		func() []uint32 { return append([]uint32(nil), got...) }
}

func TestReorderInOrder(t *testing.T) {
	o := NewReorder(time.Now(), 1024, 1<<20, time.Hour, nil)
	deliver, got := collect()
	for i := uint32(0); i < 100; i++ {
		o.Push(frame(i), time.Now(), deliver)
	}
	seqs := got()
	for i, s := range seqs {
		if s != uint32(i) {
			t.Fatalf("delivered[%d]=%d, want %d (all: %v)", i, s, i, seqs)
		}
	}
	if o.Pending() != 0 || o.Dups != 0 || o.Skips != 0 {
		t.Errorf("pending=%d dups=%d skips=%d, want 0", o.Pending(), o.Dups, o.Skips)
	}
}

func TestReorderDuplicatesDropped(t *testing.T) {
	o := NewReorder(time.Now(), 1024, 1<<20, time.Hour, nil)
	deliver, got := collect()
	o.Push(frame(0), time.Now(), deliver)
	o.Push(frame(0), time.Now(), deliver) // dup
	o.Push(frame(1), time.Now(), deliver)
	o.Push(frame(1), time.Now(), deliver) // dup
	if len(got()) != 2 {
		t.Fatalf("delivered %v, want [0 1]", got())
	}
	if o.Dups != 2 {
		t.Errorf("Dups=%d, want 2", o.Dups)
	}
}

func TestReorderOutOfOrderBuffered(t *testing.T) {
	o := NewReorder(time.Now(), 1024, 1<<20, time.Hour, nil)
	deliver, got := collect()
	o.Push(frame(0), time.Now(), deliver)
	o.Push(frame(2), time.Now(), deliver) // hole at 1
	o.Push(frame(3), time.Now(), deliver)
	if len(got()) != 1 {
		t.Fatalf("delivered %v, want only [0] while hole exists", got())
	}
	o.Push(frame(1), time.Now(), deliver) // fills the hole
	seqs := got()
	want := []uint32{0, 1, 2, 3}
	for i, s := range seqs {
		if s != want[i] {
			t.Fatalf("delivered %v, want %v", seqs, want)
		}
	}
}

func TestReorderGapSkipAfterTimeout(t *testing.T) {
	gap := 100 * time.Millisecond
	var skippedFrom, skippedTo uint32
	skips := 0
	o := NewReorder(time.Now(), 1024, 1<<20, gap, func(from, to uint32) {
		skips++
		skippedFrom, skippedTo = from, to
	})
	deliver, got := collect()
	base := time.Now()
	o.Push(frame(0), base, deliver)
	o.Push(frame(2), base.Add(10*time.Millisecond), deliver) // hole at 1
	o.Push(frame(3), base.Add(50*time.Millisecond), deliver) // still fresh
	if len(got()) != 1 {
		t.Fatalf("hole must persist while fresh: %v", got())
	}
	// Next arrival after the gap window → skip hole at 1.
	o.Push(frame(4), base.Add(gap+200*time.Millisecond), deliver)
	seqs := got()
	want := []uint32{0, 2, 3, 4}
	for i, s := range seqs {
		if s != want[i] {
			t.Fatalf("delivered %v, want %v", seqs, want)
		}
	}
	if skips != 1 || skippedFrom != 1 || skippedTo != 2 {
		t.Errorf("skip = from %d to %d (n=%d), want from 1 to 2 (n=1)", skippedFrom, skippedTo, skips)
	}
	if o.Skips != 1 || o.Overflows != 0 {
		t.Errorf("stats skips=%d overflows=%d", o.Skips, o.Overflows)
	}
}

func TestReorderGapSkipToBufferedWhenAvailable(t *testing.T) {
	gap := 50 * time.Millisecond
	var from, to uint32
	o := NewReorder(time.Now(), 1024, 1<<20, gap, func(f, tt uint32) { from, to = f, tt })
	deliver, got := collect()
	base := time.Now()
	o.Push(frame(0), base, deliver)
	o.Push(frame(3), base.Add(10*time.Millisecond), deliver)
	o.Push(frame(4), base.Add(20*time.Millisecond), deliver) // buf {3,4}, hole 1
	// Stale arrival beyond gap: jump should start at 3 (earliest buffered).
	o.Push(frame(5), base.Add(gap+time.Second), deliver)
	seqs := got()
	want := []uint32{0, 3, 4, 5}
	for i, s := range seqs {
		if s != want[i] {
			t.Fatalf("delivered %v, want %v", seqs, want)
		}
	}
	if from != 1 || to != 3 {
		t.Errorf("skip from %d to %d, want 1 -> 3", from, to)
	}
}

func TestReorderBufferOverflow(t *testing.T) {
	o := NewReorder(time.Now(), 4 /*maxFrames*/, 1<<20, time.Hour, nil)
	deliver, got := collect()
	o.Push(frame(0), time.Now(), deliver)
	for i := uint32(2); i <= 10; i++ {
		o.Push(frame(i), time.Now(), deliver)
	}
	if o.Pending() != 4 {
		t.Errorf("Pending=%d, want 4 (cap)", o.Pending())
	}
	if o.Overflows == 0 {
		t.Error("expected overflow drops")
	}
	// Hole at 1 still blocks until it arrives; then everything contiguous drains.
	o.Push(frame(1), time.Now(), deliver)
	if len(got()) == 1 {
		t.Errorf("after hole fill, delivery must resume: %v", got())
	}
}

func TestReorderPropertyRandomDupReorder(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	o := NewReorder(time.Now(), 2048, 16<<20, time.Hour, nil)
	deliver, got := collect()

	const n = 1000
	var frames []*protocol.Frame
	for i := uint32(0); i < n; i++ {
		frames = append(frames, frame(i))
	}
	// Shuffle, then interleave duplicates (what two tunnels produce).
	rng.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })
	now := time.Now()
	for _, f := range frames {
		o.Push(f, now, deliver)
		if f.Seq%3 == 0 { // duplicate copy from the other tunnel
			o.Push(f, now, deliver)
		}
	}
	// Everything fits in the window: after the full shuffle the last push may
	// still leave a hole only if a seq never arrived — all n arrived exactly.
	// Drain by pushing any missing (shouldn't exist).
	seqs := got()
	if len(seqs) != n {
		t.Fatalf("delivered %d frames, want %d (dups=%d overflows=%d)", len(seqs), n, o.Dups, o.Overflows)
	}
	for i, s := range seqs {
		if s != uint32(i) {
			t.Fatalf("out of order at %d: got %d (dups=%d)", i, s, o.Dups)
		}
	}
	if o.Skips != 0 {
		t.Errorf("unexpected skips=%d", o.Skips)
	}
}

func TestTableAllocCreateIdempotent(t *testing.T) {
	tab := NewTable(Options{MaxSessions: 4})
	s1, err := tab.Alloc(KindTCP, "example.com:443", nil, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if s1.ID == 0 {
		t.Error("id 0 is reserved")
	}
	// Server-side duplicate OPEN with same target.
	again, created, err := tab.Create(s1.ID, KindTCP, "example.com:443", nil, Hooks{})
	if err != nil || created || again != s1 {
		t.Fatalf("duplicate OPEN: created=%v err=%v", created, err)
	}
	// Conflicting target is an error.
	if _, _, err := tab.Create(s1.ID, KindTCP, "other:443", nil, Hooks{}); err == nil {
		t.Fatal("expected conflict error")
	}
}

func TestTableMaxSessionsAndTombstone(t *testing.T) {
	tab := NewTable(Options{MaxSessions: 2, TCPIdle: time.Hour})
	closed := 0
	onClose := func(string) { closed++ }
	s1, err := tab.Alloc(KindTCP, "a:1", nil, Hooks{OnClose: onClose})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tab.Alloc(KindTCP, "b:2", nil, Hooks{OnClose: onClose}); err != nil {
		t.Fatal(err)
	}
	if _, err := tab.Alloc(KindTCP, "c:3", nil, Hooks{OnClose: onClose}); err == nil {
		t.Fatal("expected max sessions error")
	}
	tab.Destroy(s1.ID, "test")
	if closed != 1 {
		t.Errorf("onClose calls = %d, want 1", closed)
	}
	tab.Destroy(s1.ID, "test again") // idempotent
	if closed != 1 {
		t.Errorf("onClose calls = %d after second destroy, want 1", closed)
	}
	if tab.Get(s1.ID) != nil {
		t.Error("destroyed session must not be returned (tombstone)")
	}
	if _, _, err := tab.Create(s1.ID, KindTCP, "a:1", nil, Hooks{}); err == nil {
		t.Error("tombstoned id must not be recreated immediately")
	}
	// Slot freed for a fresh id.
	if _, err := tab.Alloc(KindTCP, "d:4", nil, Hooks{}); err != nil {
		t.Errorf("Alloc after destroy: %v", err)
	}
}

func TestTableGCIdle(t *testing.T) {
	tab := NewTable(Options{TCPIdle: 100 * time.Millisecond, UDPIdle: 50 * time.Millisecond})
	closed := make(chan string, 1)
	if _, err := tab.Alloc(KindTCP, "x:1", nil, Hooks{OnClose: func(r string) { closed <- r }}); err != nil {
		t.Fatal(err)
	}
	if n := tab.GC(time.Now()); n != 0 {
		t.Fatalf("early GC destroyed %d", n)
	}
	if n := tab.GC(time.Now().Add(300 * time.Millisecond)); n != 1 {
		t.Fatalf("GC destroyed %d, want 1", n)
	}
	select {
	case reason := <-closed:
		if reason != "idle timeout" {
			t.Errorf("close reason = %q", reason)
		}
	default:
		t.Fatal("onClose not called")
	}
	// Tombstone expires after TCPIdle and is swept.
	tab.GC(time.Now().Add(300*time.Millisecond + time.Second))
	if tab.Len() != 0 {
		t.Errorf("Len=%d", tab.Len())
	}
}

func TestTableSeqAllocation(t *testing.T) {
	tab := NewTable(Options{})
	s, err := tab.Alloc(KindTCP, "x:1", nil, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < 5; i++ {
		if got := s.NextSeq(); got != i {
			t.Fatalf("NextSeq=%d, want %d", got, i)
		}
	}
}

func TestTableTouchRefreshesGC(t *testing.T) {
	tab := NewTable(Options{TCPIdle: 100 * time.Millisecond})
	s, err := tab.Alloc(KindTCP, "x:1", nil, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := tab.Get(s.ID); got == nil {
			t.Fatal("session vanished")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := tab.GC(time.Now()); n != 0 {
		t.Errorf("touched session was GC'd (%d)", n)
	}
}
