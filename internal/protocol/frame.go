// Package protocol defines the wire frame format shared by all tunnel
// transports (SSH channels, plain TCP): a fixed 20-byte big-endian header
// followed by the payload.
package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// Magic is the frame magic "DPD1".
	Magic uint32 = 0x44504431
	// Version is the current protocol version.
	Version byte = 1
	// HeaderSize is the fixed frame header size in bytes.
	HeaderSize = 20
	// MaxPayloadAbs is the hard upper bound for a single frame payload (64 KiB).
	MaxPayloadAbs = 64 * 1024
	// DefaultMaxPayload matches the default limits.max_frame_payload (32 KiB).
	DefaultMaxPayload = 32 * 1024
	// ReadChunk is the source read chunk size: one chunk = one DATA frame.
	ReadChunk = 16 * 1024
)

// Type is the frame type byte.
type Type byte

const (
	TypeData    Type = 0x01 // sequenced: raw byte-pipe payload
	TypeOpen    Type = 0x02 // c->s, sequenced 0: target address
	TypeOpenAck Type = 0x03 // s->c, sequenced 0: verbatim SOCKS5 reply
	TypeClose   Type = 0x04 // sequenced: 1 byte reason (0=half-close, 1=abort)
	TypePing    Type = 0x05 // not sequenced, session 0: echo payload
	TypePong    Type = 0x06 // not sequenced, session 0: echo payload
	TypeUDPData Type = 0x07 // c->s, sequenced: RFC1928 datagram
	TypeUDPReply Type = 0x08 // s->c, sequenced: compact src addr + payload
)

func (t Type) String() string {
	switch t {
	case TypeData:
		return "DATA"
	case TypeOpen:
		return "OPEN"
	case TypeOpenAck:
		return "OPEN_ACK"
	case TypeClose:
		return "CLOSE"
	case TypePing:
		return "PING"
	case TypePong:
		return "PONG"
	case TypeUDPData:
		return "UDP_DATA"
	case TypeUDPReply:
		return "UDP_REPLY"
	default:
		return fmt.Sprintf("Type(0x%02x)", byte(t))
	}
}

// Valid reports whether t is a known frame type.
func (t Type) Valid() bool { return t >= TypeData && t <= TypeUDPReply }

// Sequenced reports whether t participates in per-session dedup/reorder.
func (t Type) Sequenced() bool { return t != TypePing && t != TypePong }

// Close reasons carried by TypeClose payloads.
const (
	CloseHalf = 0 // write-side EOF (peer should CloseWrite)
	CloseAbort = 1 // abort / error: close both directions
)

// Frame is a single protocol frame. Frames built by NewFrame carry a sealed
// wire image (header+payload) ready for concurrent fan-out writes; frames
// returned by ReadFrame encode lazily and must not be written from multiple
// goroutines before their first write.
type Frame struct {
	Type      Type
	SessionID uint32
	Seq       uint32
	Payload   []byte

	sealed []byte // header+payload wire image
}

// NewFrame builds and seals a frame, validating type and payload size.
func NewFrame(typ Type, sessionID, seq uint32, payload []byte) (*Frame, error) {
	if !typ.Valid() {
		return nil, fmt.Errorf("invalid frame type 0x%02x", byte(typ))
	}
	if len(payload) > MaxPayloadAbs {
		return nil, fmt.Errorf("payload %d exceeds max %d", len(payload), MaxPayloadAbs)
	}
	f := &Frame{Type: typ, SessionID: sessionID, Seq: seq, Payload: payload}
	f.seal()
	return f, nil
}

// NewClose builds a sequenced CLOSE frame with the given reason.
func NewClose(sessionID, seq uint32, reason byte) *Frame {
	f, _ := NewFrame(TypeClose, sessionID, seq, []byte{reason})
	return f
}

// Reason returns the close reason (CloseHalf/CloseAbort); abort on bad payload.
func (f *Frame) Reason() byte {
	if len(f.Payload) != 1 {
		return CloseAbort
	}
	return f.Payload[0]
}

func (f *Frame) seal() {
	buf := make([]byte, HeaderSize+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], Magic)
	buf[4] = Version
	buf[5] = byte(f.Type)
	binary.BigEndian.PutUint16(buf[6:8], 0) // flags
	binary.BigEndian.PutUint32(buf[8:12], f.SessionID)
	binary.BigEndian.PutUint32(buf[12:16], f.Seq)
	binary.BigEndian.PutUint32(buf[16:20], uint32(len(f.Payload)))
	copy(buf[HeaderSize:], f.Payload)
	f.sealed = buf
}

// Bytes returns the wire image, sealing lazily if needed.
func (f *Frame) Bytes() []byte {
	if f.sealed == nil {
		f.seal()
	}
	return f.sealed
}

// Encode writes the full frame to w (single buffered write).
func Encode(w io.Writer, f *Frame) error {
	return writeAll(w, f.Bytes())
}

// Decode reads exactly one frame from r. maxPayload caps payloadLen
// (<= MaxPayloadAbs); any validation error is fatal for the stream — a corrupt
// stream cannot be resynchronized.
func Decode(r io.Reader, maxPayload int) (*Frame, error) {
	if maxPayload <= 0 || maxPayload > MaxPayloadAbs {
		maxPayload = MaxPayloadAbs
	}
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if magic := binary.BigEndian.Uint32(hdr[0:4]); magic != Magic {
		return nil, fmt.Errorf("bad frame magic 0x%08x", magic)
	}
	if hdr[4] != Version {
		return nil, fmt.Errorf("unsupported frame version %d", hdr[4])
	}
	typ := Type(hdr[5])
	if !typ.Valid() {
		return nil, fmt.Errorf("invalid frame type 0x%02x", hdr[5])
	}
	length := binary.BigEndian.Uint32(hdr[16:20])
	if length > uint32(maxPayload) {
		return nil, fmt.Errorf("frame payload %d exceeds max %d", length, maxPayload)
	}
	f := &Frame{
		Type:      typ,
		SessionID: binary.BigEndian.Uint32(hdr[8:12]),
		Seq:       binary.BigEndian.Uint32(hdr[12:16]),
	}
	if length > 0 {
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
	}
	// Keep the header image for potential re-write; payload already known.
	f.sealed = append(hdr[:], f.Payload...)
	return f, nil
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
