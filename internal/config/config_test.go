package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadYAML(t *testing.T, body string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestServerDefaults(t *testing.T) {
	cfg := loadYAML(t, "mode: server\n")
	if err := cfg.Validate(ModeServer); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9000" {
		t.Errorf("Listen default = %q", cfg.Listen)
	}
	if cfg.SOCKS5Upstream != "127.0.0.1:1080" {
		t.Errorf("SOCKS5Upstream default = %q", cfg.SOCKS5Upstream)
	}
	if cfg.Tunnels != 2 {
		t.Errorf("Tunnels default = %d", cfg.Tunnels)
	}
	if cfg.Limits.GapSkipTimeout.D() != 3*time.Second {
		t.Errorf("GapSkipTimeout = %v", cfg.Limits.GapSkipTimeout.D())
	}
	if cfg.PingInterval.D() != 5*time.Second {
		t.Errorf("PingInterval = %v", cfg.PingInterval.D())
	}
}

func TestModeMismatch(t *testing.T) {
	cfg := loadYAML(t, "mode: server\n")
	if err := cfg.Validate(ModeClient); err == nil {
		t.Fatal("expected mode mismatch error")
	}
}

func TestClientSSHValidation(t *testing.T) {
	cfg := loadYAML(t, `
mode: client
ssh:
  address: "203.0.113.10:22"
  user: dup
  key_file: /home/u/.ssh/id_ed25519
`)
	if err := cfg.Validate(ModeClient); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestClientSSHNoAuth(t *testing.T) {
	cfg := loadYAML(t, "mode: client\nssh:\n  address: \"1.2.3.4:22\"\n  user: dup\n")
	if err := cfg.Validate(ModeClient); err == nil {
		t.Fatal("expected missing auth error")
	}
}

func TestClientAddressesRoundRobin(t *testing.T) {
	cfg := loadYAML(t, `
mode: client
transport: ssh
ssh:
  addresses: ["1.2.3.4:22", "5.6.7.8:2222"]
  user: dup
  password: pw
  key_file: ""
`)
	eps := cfg.SSH.Endpoints()
	if len(eps) != 2 || eps[1] != "5.6.7.8:2222" {
		t.Fatalf("Endpoints = %v", eps)
	}
	if err := cfg.Validate(ModeClient); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestClientPlainValidation(t *testing.T) {
	cfg := loadYAML(t, "mode: client\ntransport: plain\nplain:\n  address: \"127.0.0.1:9000\"\n")
	if err := cfg.Validate(ModeClient); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	bad := loadYAML(t, "mode: client\ntransport: plain\n")
	if err := bad.Validate(ModeClient); err == nil {
		t.Fatal("expected missing plain.address error")
	}
}

func TestTunnelsValidation(t *testing.T) {
	cfg := loadYAML(t, `
mode: client
transport: plain
plain: {address: "127.0.0.1:9000"}
tunnels: 4
`)
	if err := cfg.Validate(ModeClient); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.Tunnels != 4 {
		t.Fatalf("Tunnels = %d", cfg.Tunnels)
	}
}

func TestUnknownLogLevel(t *testing.T) {
	cfg := loadYAML(t, "log:\n  level: verbose\n")
	if err := cfg.Validate(ModeServer); err == nil {
		t.Fatal("expected unknown level error")
	}
}

func TestDurationStringAndSeconds(t *testing.T) {
	cfg := loadYAML(t, `
ping_interval: 750ms
relay_close_grace: 45
`)
	if cfg.PingInterval.D() != 750*time.Millisecond {
		t.Errorf("PingInterval = %v", cfg.PingInterval.D())
	}
	if cfg.RelayCloseGrace.D() != 45*time.Second {
		t.Errorf("RelayCloseGrace = %v", cfg.RelayCloseGrace.D())
	}
}

func TestExampleConfigs(t *testing.T) {
	for _, tc := range []struct {
		file, mode string
	}{
		{"../../configs/server.example.yaml", ModeServer},
		{"../../configs/client.example.yaml", ModeClient},
	} {
		cfg, err := Load(tc.file)
		if err != nil {
			t.Errorf("%s: Load: %v", tc.file, err)
			continue
		}
		if err := cfg.Validate(tc.mode); err != nil {
			t.Errorf("%s: Validate: %v", tc.file, err)
		}
	}
}
