package protocol

import "fmt"

// ParseUDPDatagram splits an RFC1928 UDP request:
//
//	RSV(2) FRAG(1) DST.ADDR DST.PORT DATA
//
// FRAG must be 0 (fragmentation unsupported). Returns the destination and
// the UDP payload.
func ParseUDPDatagram(b []byte) (Addr, []byte, error) {
	if len(b) < 4 {
		return Addr{}, nil, fmt.Errorf("datagram too short (%d bytes)", len(b))
	}
	if b[2] != 0 {
		return Addr{}, nil, fmt.Errorf("fragmented udp (FRAG=%d) unsupported", b[2])
	}
	addr, n, err := ParseAddr(b[3:])
	if err != nil {
		return Addr{}, nil, err
	}
	return addr, b[3+n:], nil
}
