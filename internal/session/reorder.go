// Package session manages multiplexed sessions: ID allocation, per-session
// sequencing, first-seen-wins dedup with reordering, and idle GC.
package session

import (
	"time"

	"proxy-duplicator/internal/protocol"
)

// Reorder implements dedup + in-order delivery for one direction of one
// session. Frames arrive from N duplicated tunnels: first copy of each seq
// wins, later duplicates are dropped, future seqs wait in a bounded buffer.
//
// A "hole" (missing expected seq) can only persist if the frame was lost on
// every tunnel; after gapSkip without delivery progress the buffer jumps over
// the hole (logged via onSkip) so one lost frame never wedges the session
// forever. For TCP the jump effectively means the stream is broken anyway —
// the alternative would be a permanent stall until idle GC.
type Reorder struct {
	expected   uint32
	buf        map[uint32]*protocol.Frame
	frames     int
	bytes      int
	lastDeliver time.Time

	maxFrames int
	maxBytes  int
	gapSkip   time.Duration
	onSkip    func(from, to uint32)

	Dups      uint64
	Overflows uint64
	Skips     uint64
}

// NewReorder creates an empty buffer; delivery starts at seq 0.
func NewReorder(now time.Time, maxFrames, maxBytes int, gapSkip time.Duration, onSkip func(uint32, uint32)) *Reorder {
	if maxFrames <= 0 {
		maxFrames = 1024
	}
	if maxBytes <= 0 {
		maxBytes = 4 * 1024 * 1024
	}
	return &Reorder{
		expected:    0,
		buf:         make(map[uint32]*protocol.Frame),
		lastDeliver: now,
		maxFrames:   maxFrames,
		maxBytes:    maxBytes,
		gapSkip:     gapSkip,
		onSkip:      onSkip,
	}
}

// Push ingests one sequenced frame; deliver is called for each frame in
// strictly increasing seq order.
func (o *Reorder) Push(f *protocol.Frame, now time.Time, deliver func(*protocol.Frame)) {
	// Stale hole: jump to the earliest data we have (or this frame).
	if f.Seq > o.expected && o.gapSkip > 0 && now.Sub(o.lastDeliver) > o.gapSkip {
		target := f.Seq
		if m, ok := o.minKey(); ok && m < target {
			target = m
		}
		o.Skips++
		if o.onSkip != nil {
			o.onSkip(o.expected, target)
		}
		o.expected = target
		o.lastDeliver = now
	}
	o.drain(now, deliver)

	switch {
	case f.Seq == o.expected:
		deliver(f)
		o.expected++
		o.lastDeliver = now
		o.drain(now, deliver)
	case f.Seq < o.expected:
		o.Dups++
	default:
		if _, ok := o.buf[f.Seq]; ok {
			o.Dups++
			return
		}
		if o.frames >= o.maxFrames || o.bytes+len(f.Payload) > o.maxBytes {
			o.Overflows++
			return
		}
		o.buf[f.Seq] = f
		o.frames++
		o.bytes += len(f.Payload)
	}
}

// drain delivers the contiguous run starting at expected.
func (o *Reorder) drain(now time.Time, deliver func(*protocol.Frame)) {
	for {
		f, ok := o.buf[o.expected]
		if !ok {
			return
		}
		delete(o.buf, o.expected)
		o.frames--
		o.bytes -= len(f.Payload)
		deliver(f)
		o.expected++
		o.lastDeliver = now
	}
}

func (o *Reorder) minKey() (uint32, bool) {
	var min uint32
	first := true
	for k := range o.buf {
		if first || k < min {
			min = k
			first = false
		}
	}
	return min, !first
}

// Pending returns the number of buffered out-of-order frames.
func (o *Reorder) Pending() int { return o.frames }

// Expected returns the next seq that will be delivered.
func (o *Reorder) Expected() uint32 { return o.expected }
