package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 address types (RFC1928 ATYP).
const (
	ATYPIPv4   byte = 0x01
	ATYPDomain byte = 0x03
	ATYPIPv6   byte = 0x02
)

// Addr is a SOCKS5-style address: ATYP + host + port. ATYP preserves the
// original encoding when parsed from the wire (IPv4 vs IPv6 vs domain).
type Addr struct {
	Host string
	Port uint16
	ATYP byte // as received/parsed; 0 = derive on encode
}

// IPv4Addr builds an IPv4 address.
func IPv4Addr(ip net.IP, port uint16) Addr {
	return Addr{Host: ip.To4().String(), Port: port, ATYP: ATYPIPv4}
}

// ParseHostPort derives an Addr from "host:port" (IP literals keep IP ATYP,
// names become domains).
func ParseHostPort(hostport string) (Addr, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return Addr{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Addr{}, fmt.Errorf("bad port %q: %w", portStr, err)
	}
	return Addr{Host: host, Port: uint16(port)}, nil
}

// String renders "host:port".
func (a Addr) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

// atyp returns the ATYP to encode with (explicit if set, else derived).
func (a Addr) atyp() byte {
	if a.ATYP != 0 {
		return a.ATYP
	}
	ip := net.ParseIP(a.Host)
	if ip == nil {
		return ATYPDomain
	}
	if ip.To4() != nil {
		return ATYPIPv4
	}
	return ATYPIPv6
}

// AppendTo appends the encoded address (ATYP + addr + port) to b.
func (a Addr) AppendTo(b []byte) []byte {
	atyp := a.atyp()
	switch atyp {
	case ATYPIPv4:
		ip := net.ParseIP(a.Host).To4()
		if ip != nil {
			b = append(b, ATYPIPv4)
			b = append(b, ip...)
			return appendPort(b, a.Port)
		}
		// Not really IPv4: fall back to domain encoding.
		return a.appendToDomain(b)
	case ATYPIPv6:
		ip := net.ParseIP(a.Host).To16()
		if ip != nil && ip.To4() == nil {
			b = append(b, ATYPIPv6)
			b = append(b, ip...)
			return appendPort(b, a.Port)
		}
		return a.appendToDomain(b)
	default:
		return a.appendToDomain(b)
	}
}

func appendPort(b []byte, port uint16) []byte {
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(b, p[:]...)
}

func (a Addr) appendToDomain(b []byte) []byte {
	host := []byte(a.Host)
	if len(host) > 255 {
		host = host[:255]
	}
	b = append(b, ATYPDomain, byte(len(host)))
	b = append(b, host...)
	return appendPort(b, a.Port)
}

// ParseAddr decodes an address from b, returning the addr and bytes consumed.
func ParseAddr(b []byte) (Addr, int, error) {
	if len(b) < 1 {
		return Addr{}, 0, io.ErrUnexpectedEOF
	}
	atyp := b[0]
	var host string
	var need int
	switch atyp {
	case ATYPIPv4:
		need = 1 + 4
		if len(b) < need {
			return Addr{}, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(b[1:5]).String()
	case ATYPIPv6:
		need = 1 + 16
		if len(b) < need {
			return Addr{}, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(b[1:17]).String()
	case ATYPDomain:
		if len(b) < 2 {
			return Addr{}, 0, io.ErrUnexpectedEOF
		}
		l := int(b[1])
		need = 2 + l
		if len(b) < need {
			return Addr{}, 0, io.ErrUnexpectedEOF
		}
		host = string(b[2 : 2+l])
	default:
		return Addr{}, 0, fmt.Errorf("unknown ATYP 0x%02x", atyp)
	}
	if len(b) < need+2 {
		return Addr{}, 0, io.ErrUnexpectedEOF
	}
	port := binary.BigEndian.Uint16(b[need : need+2])
	return Addr{Host: host, Port: port, ATYP: atyp}, need + 2, nil
}

// ReadAddr reads one address from r (used for SOCKS5 requests and payloads).
func ReadAddr(r io.Reader) (Addr, error) {
	var head [1]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Addr{}, err
	}
	var rest int
	switch head[0] {
	case ATYPIPv4:
		rest = 4 + 2
	case ATYPIPv6:
		rest = 16 + 2
	case ATYPDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Addr{}, err
		}
		rest = int(l[0]) + 2
		buf := make([]byte, rest)
		if _, err := io.ReadFull(r, buf); err != nil {
			return Addr{}, err
		}
		a, _, err := ParseAddr(append([]byte{ATYPDomain, l[0]}, buf...))
		return a, err
	default:
		return Addr{}, fmt.Errorf("unknown ATYP 0x%02x", head[0])
	}
	buf := make([]byte, rest)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Addr{}, err
	}
	a, _, err := ParseAddr(append(head[:], buf...))
	return a, err
}
