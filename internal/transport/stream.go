package transport

import (
	"io"

	"proxy-duplicator/internal/protocol"
)

// Stream is a framed point-to-point link (an SSH direct-tcpip channel, a plain
// TCP conn, ...). Writes must come from a single goroutine (the queue writer);
// reads from a single reader goroutine.
type Stream struct {
	conn io.ReadWriteCloser
	name string
}

// NewStream wraps an existing connection.
func NewStream(conn io.ReadWriteCloser, name string) *Stream {
	return &Stream{conn: conn, name: name}
}

// Name identifies the link in logs (e.g. "ssh#0", "plain#1").
func (s *Stream) Name() string { return s.name }

// ReadFrame decodes one frame; io.EOF/ErrUnexpectedEOF mark a closed link, any
// other error (bad magic/size) is fatal for the stream.
func (s *Stream) ReadFrame(maxPayload int) (*protocol.Frame, error) {
	return protocol.Decode(s.conn, maxPayload)
}

// WriteFrame encodes one frame fully to the underlying conn.
func (s *Stream) WriteFrame(f *protocol.Frame) error {
	return protocol.Encode(s.conn, f)
}

// Close closes the underlying conn. Safe to call multiple times.
func (s *Stream) Close() error { return s.conn.Close() }
