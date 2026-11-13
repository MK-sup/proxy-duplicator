package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Log levels / formats.
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"

	FormatText = "text"
	FormatJSON = "json"

	ModeServer = "server"
	ModeClient = "client"

	TransportSSH   = "ssh"
	TransportPlain = "plain"
)

// Duration is a YAML-friendly time.Duration: "150ms", "5s", "2m" or an integer
// number of seconds.
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err == nil {
		if parsed, err := time.ParseDuration(s); err == nil {
			*d = Duration(parsed)
			return nil
		}
		// Bare integer = seconds ("45" -> 45s).
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			*d = Duration(time.Duration(n) * time.Second)
			return nil
		}
		return fmt.Errorf("invalid duration %q: use e.g. \"5s\", \"500ms\", \"2m\"", s)
	}
	return fmt.Errorf("duration must be a string like \"5s\" or an integer of seconds")
}

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

type LimitsConfig struct {
	MaxSessions      int      `yaml:"max_sessions"`
	MaxFramePayload  int      `yaml:"max_frame_payload"`
	ReorderMaxFrames int      `yaml:"reorder_max_frames"`
	ReorderMaxBytes  int      `yaml:"reorder_max_bytes"`
	GapSkipTimeout   Duration `yaml:"gap_skip_timeout"`
	SessionIdleTCP   Duration `yaml:"session_idle_tcp"`
	UDPIdle          Duration `yaml:"udp_idle"`
}

type SSHConfig struct {
	Address           string   `yaml:"address"`
	Addresses         []string `yaml:"addresses"`
	User              string   `yaml:"user"`
	Password          string   `yaml:"password"`
	KeyFile           string   `yaml:"key_file"`
	KeyPassphrase     string   `yaml:"key_passphrase"`
	HostKey           string   `yaml:"host_key"`
	// ForwardPort is the server-side dupd listen port reached via direct-tcpip
	// (127.0.0.1:<port> on the server; must match the server's `listen` port).
	ForwardPort    uint16 `yaml:"forward_port"`
	ConnectTimeout Duration `yaml:"connect_timeout"`
	// KeepaliveInterval is a *Duration so YAML `keepalive_interval: 0`
	// explicitly disables SSH keepalive (nil = unset → default 15s).
	KeepaliveInterval *Duration `yaml:"keepalive_interval"`
}

// Endpoints returns the SSH endpoint list (addresses wins over address when set).
func (s SSHConfig) Endpoints() []string {
	if len(s.Addresses) > 0 {
		return s.Addresses
	}
	if s.Address != "" {
		return []string{s.Address}
	}
	return nil
}

type PlainConfig struct {
	Address   string   `yaml:"address"`
	Addresses []string `yaml:"addresses"`
}

// Endpoints returns the plain endpoint list (addresses wins over address).
func (p PlainConfig) Endpoints() []string {
	if len(p.Addresses) > 0 {
		return p.Addresses
	}
	if p.Address != "" {
		return []string{p.Address}
	}
	return nil
}

type QueueConfig struct {
	Frames int `yaml:"frames"`
}

type ReconnectConfig struct {
	Initial Duration `yaml:"initial"`
	Max     Duration `yaml:"max"`
}

type Config struct {
	Mode string `yaml:"mode"`

	// server
	Listen           string   `yaml:"listen"`
	SOCKS5Upstream   string   `yaml:"socks5_upstream"`
	SOCKS5DialTimeout Duration `yaml:"socks5_dial_timeout"`

	// client
	SSH                SSHConfig      `yaml:"ssh"`
	Transport          string         `yaml:"transport"`
	Plain              PlainConfig    `yaml:"plain"`
	SOCKS5Listen       string         `yaml:"socks5_listen"`
	UDPRelay           string         `yaml:"udp_relay"`
	Tunnels            int            `yaml:"tunnels"`
	Queue              QueueConfig    `yaml:"queue"`
	PingInterval       Duration       `yaml:"ping_interval"`
	PingTimeout        Duration       `yaml:"ping_timeout"`
	Reconnect          ReconnectConfig `yaml:"reconnect"`
	BothDeadCloseAfter Duration       `yaml:"both_dead_close_after"`

	Log               LogConfig     `yaml:"log"`
	Limits            LimitsConfig  `yaml:"limits"`
	RelayCloseGrace   Duration      `yaml:"relay_close_grace"`
}

// Load reads and decodes the YAML file without validation.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Log.Level == "" {
		c.Log.Level = LevelInfo
	}
	if c.Log.Format == "" {
		c.Log.Format = FormatText
	}

	setDur(&c.Limits.GapSkipTimeout, 3*time.Second)
	setDur(&c.Limits.SessionIdleTCP, 120*time.Second)
	setDur(&c.Limits.UDPIdle, 60*time.Second)
	if c.Limits.MaxSessions <= 0 {
		c.Limits.MaxSessions = 8192
	}
	if c.Limits.MaxFramePayload <= 0 {
		c.Limits.MaxFramePayload = 32 * 1024
	}
	if c.Limits.ReorderMaxFrames <= 0 {
		c.Limits.ReorderMaxFrames = 1024
	}
	if c.Limits.ReorderMaxBytes <= 0 {
		c.Limits.ReorderMaxBytes = 4 * 1024 * 1024
	}
	setDur(&c.RelayCloseGrace, 30*time.Second)

	// server
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9000"
	}
	if c.SOCKS5Upstream == "" {
		c.SOCKS5Upstream = "127.0.0.1:1080"
	}
	setDur(&c.SOCKS5DialTimeout, 10*time.Second)

	// client
	if c.Transport == "" {
		c.Transport = TransportSSH
	}
	if c.SOCKS5Listen == "" {
		c.SOCKS5Listen = "127.0.0.1:1080"
	}
	if c.UDPRelay == "" {
		c.UDPRelay = "127.0.0.1:0"
	}
	if c.Tunnels <= 0 {
		c.Tunnels = 2
	}
	if c.Queue.Frames <= 0 {
		c.Queue.Frames = 512
	}
	setDur(&c.PingInterval, 5*time.Second)
	setDur(&c.PingTimeout, 15*time.Second)
	setDur(&c.Reconnect.Initial, time.Second)
	setDur(&c.Reconnect.Max, 30*time.Second)
	setDur(&c.BothDeadCloseAfter, 10*time.Second)
	setDur(&c.SSH.ConnectTimeout, 10*time.Second)
	if c.SSH.KeepaliveInterval == nil {
		ka := Duration(15 * time.Second)
		c.SSH.KeepaliveInterval = &ka
	}
	if c.SSH.ForwardPort == 0 {
		// Derive from the server-side default listen port (127.0.0.1:9000).
		if _, port, err := net.SplitHostPort(c.Listen); err == nil {
			if p, perr := strconv.ParseUint(port, 10, 16); perr == nil && p != 0 {
				c.SSH.ForwardPort = uint16(p)
			}
		}
		if c.SSH.ForwardPort == 0 {
			c.SSH.ForwardPort = 9000
		}
	}
}

func setDur(d *Duration, def time.Duration) {
	if *d <= 0 {
		*d = Duration(def)
	}
}

// Validate checks the config for the given mode ("server" or "client").
func (c *Config) Validate(mode string) error {
	if mode != ModeServer && mode != ModeClient {
		return fmt.Errorf("unknown mode %q", mode)
	}
	if c.Mode != "" && c.Mode != mode {
		return fmt.Errorf("config mode %q does not match subcommand %q", c.Mode, mode)
	}
	switch c.Log.Level {
	case LevelDebug, LevelInfo, LevelWarn, LevelError:
	default:
		return fmt.Errorf("log.level: unknown level %q", c.Log.Level)
	}
	switch c.Log.Format {
	case FormatText, FormatJSON:
	default:
		return fmt.Errorf("log.format: unknown format %q", c.Log.Format)
	}
	if c.Limits.MaxFramePayload > 64*1024 {
		return fmt.Errorf("limits.max_frame_payload: %d exceeds 64KiB", c.Limits.MaxFramePayload)
	}

	if mode == ModeServer {
		if err := checkHostPort(c.Listen, false); err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		if err := checkHostPort(c.SOCKS5Upstream, false); err != nil {
			return fmt.Errorf("socks5_upstream: %w", err)
		}
		return nil
	}

	// client
	if c.Tunnels < 1 {
		return fmt.Errorf("tunnels: must be >= 1, got %d", c.Tunnels)
	}
	if err := checkHostPort(c.SOCKS5Listen, false); err != nil {
		return fmt.Errorf("socks5_listen: %w", err)
	}
	if err := checkHostPort(c.UDPRelay, false); err != nil {
		return fmt.Errorf("udp_relay: %w", err)
	}
	switch c.Transport {
	case TransportSSH:
		if len(c.SSH.Endpoints()) == 0 {
			return fmt.Errorf("ssh.address or ssh.addresses is required")
		}
		for _, ep := range c.SSH.Endpoints() {
			if err := checkHostPort(ep, false); err != nil {
				return fmt.Errorf("ssh endpoint %q: %w", ep, err)
			}
		}
		if c.SSH.User == "" {
			return fmt.Errorf("ssh.user is required")
		}
		if c.SSH.Password == "" && c.SSH.KeyFile == "" {
			return fmt.Errorf("one of ssh.password or ssh.key_file is required")
		}
	case TransportPlain:
		eps := c.Plain.Endpoints()
		if len(eps) == 0 {
			return fmt.Errorf("plain.address or plain.addresses is required when transport=plain")
		}
		for _, ep := range eps {
			if err := checkHostPort(ep, false); err != nil {
				return fmt.Errorf("plain endpoint %q: %w", ep, err)
			}
		}
	default:
		return fmt.Errorf("transport: unknown %q (want ssh or plain)", c.Transport)
	}
	return nil
}

func checkHostPort(addr string, allowEmpty bool) error {
	if addr == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("address is empty")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid host:port %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("invalid host:port %q: missing port", addr)
	}
	_ = host
	return nil
}
