package client

import (
	"testing"

	"proxy-duplicator/internal/config"
	"proxy-duplicator/internal/protocol"
)

func TestIsOwnEndpoint(t *testing.T) {
	// Addresses wins over Address when set (Endpoints() semantics).
	c := &Client{cfg: &config.Config{
		Transport: config.TransportSSH,
		SSH: config.SSHConfig{
			Addresses: []string{
				"87.236.146.208:22",
				"203.0.113.10:22",
				"203.0.113.10:2222",
			},
		},
	}}

	cases := []struct {
		name string
		tgt  protocol.Addr
		want bool
	}{
		{"ssh endpoint ip:port", protocol.Addr{Host: "87.236.146.208", Port: 22}, true},
		{"addresses entry", protocol.Addr{Host: "203.0.113.10", Port: 22}, true},
		{"addresses entry alt port", protocol.Addr{Host: "203.0.113.10", Port: 2222}, true},
		{"same host wrong port", protocol.Addr{Host: "87.236.146.208", Port: 443}, false},
		{"other host", protocol.Addr{Host: "1.2.3.4", Port: 22}, false},
		{"domain form of endpoint", protocol.Addr{Host: "203.0.113.10", Port: 22, ATYP: protocol.ATYPDomain}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.isOwnEndpoint(tc.tgt); got != tc.want {
				t.Fatalf("isOwnEndpoint(%v)=%v want %v", tc.tgt, got, tc.want)
			}
		})
	}

	// Single address field (no addresses list).
	c2 := &Client{cfg: &config.Config{
		Transport: config.TransportSSH,
		SSH:       config.SSHConfig{Address: "198.51.100.7:22"},
	}}
	if !c2.isOwnEndpoint(protocol.Addr{Host: "198.51.100.7", Port: 22}) {
		t.Fatal("single ssh.address must match")
	}
}

func TestIsOwnEndpointPlain(t *testing.T) {
	c := &Client{cfg: &config.Config{
		Transport: config.TransportPlain,
		Plain:     config.PlainConfig{Address: "127.0.0.1:9000"},
	}}
	if !c.isOwnEndpoint(protocol.Addr{Host: "127.0.0.1", Port: 9000}) {
		t.Fatal("plain endpoint should match")
	}
	if c.isOwnEndpoint(protocol.Addr{Host: "127.0.0.1", Port: 9001}) {
		t.Fatal("different port must not match")
	}
}
