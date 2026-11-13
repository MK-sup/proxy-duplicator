package session

import (
	"testing"
	"time"

	"proxy-duplicator/internal/protocol"
)

// A stalled consumer (OnInbound blocks) must not stall HandleInbound: tunnel
// readers keep queueing frames and stay free to process PONGs.
func TestHandleInboundDoesNotBlockOnSlowConsumer(t *testing.T) {
	tab := NewTable(Options{MaxSessions: 4, TCPIdle: time.Hour})
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	s, err := tab.Alloc(KindTCP, "slow:1", nil, Hooks{
		OnInbound: func(f *protocol.Frame) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release // consumer wedged
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer close(release)

	done := make(chan struct{})
	go func() {
		// Fill the inbox without overflowing it: worst case all frames land
		// in the channel (capacity inboundQueue) — HandleInbound must still
		// return for every frame while the consumer is wedged.
		for i := uint32(0); i < inboundQueue; i++ {
			s.HandleInbound(frame(i))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleInbound blocked while consumer was stalled")
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("delivery goroutine never invoked OnInbound")
	}
}

// When the inbox overflows the session is destroyed instead of blocking the
// reader; HandleInbound after Close is a no-op.
func TestHandleInboundOverflowDestroysSession(t *testing.T) {
	tab := NewTable(Options{MaxSessions: 4, TCPIdle: time.Hour})
	release := make(chan struct{})
	s, err := tab.Alloc(KindTCP, "overflow:1", nil, Hooks{
		OnInbound: func(f *protocol.Frame) { <-release },
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan string, 1)
	s.hooks.OnClose = func(reason string) { closed <- reason }

	// Fill inbox + in-flight frame in deliverLoop, then one more → overflow.
	for i := uint32(0); i <= inboundQueue+1; i++ {
		s.HandleInbound(frame(i))
	}

	select {
	case reason := <-closed:
		if reason == "" {
			t.Fatal("empty destroy reason")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("session not destroyed on inbox overflow (closed=%v)", s.Closed())
	}

	// Post-close calls are dropped silently.
	s.HandleInbound(frame(9999))

	tab.mu.Lock()
	_, exists := tab.sessions[s.ID]
	tab.mu.Unlock()
	if exists {
		t.Error("destroyed session still registered")
	}
	close(release)
}
