package transport

import (
	"context"
	"fmt"
	"net"
	"time"
)

// DialPlain opens a plain TCP link to addr (test harness / transport: plain).
func DialPlain(ctx context.Context, addr, name string, timeout time.Duration) (*Stream, error) {
	d := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("plain dial %s (%s): %w", name, addr, err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	return NewStream(conn, name), nil
}
