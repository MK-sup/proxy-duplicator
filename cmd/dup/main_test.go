package main

import (
	"os"
	"path/filepath"
	"testing"

	"proxy-duplicator/internal/config"
)

func write(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("mode: "+name[:len(name)-len(".yaml")]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDiscoverConfigInEmpty(t *testing.T) {
	dir := t.TempDir()
	if p, m := discoverConfigIn([]string{dir}, ""); p != "" || m != "" {
		t.Fatalf("got (%q,%q), want empty", p, m)
	}
}

func TestDiscoverConfigInClientPriority(t *testing.T) {
	dir := t.TempDir()
	cp := write(t, dir, "client.yaml")
	write(t, dir, "server.yaml")

	p, m := discoverConfigIn([]string{dir}, "")
	if p != cp || m != config.ModeClient {
		t.Fatalf("got (%q,%q), want client first", p, m)
	}
}

func TestDiscoverConfigInServerOnly(t *testing.T) {
	dir := t.TempDir()
	sp := write(t, dir, "server.yaml")

	p, m := discoverConfigIn([]string{dir}, "")
	if p != sp || m != config.ModeServer {
		t.Fatalf("got (%q,%q), want server", p, m)
	}
}

func TestDiscoverConfigInModeFilter(t *testing.T) {
	dir := t.TempDir()
	cp := write(t, dir, "client.yaml")
	write(t, dir, "server.yaml")

	// Requesting server must not pick client.yaml even though it exists.
	sp := filepath.Join(dir, "server.yaml")
	p, m := discoverConfigIn([]string{dir}, config.ModeServer)
	if p != sp || m != config.ModeServer {
		t.Fatalf("server mode: got (%q,%q)", p, m)
	}

	// Requesting client.
	p, m = discoverConfigIn([]string{dir}, config.ModeClient)
	if p != cp || m != config.ModeClient {
		t.Fatalf("client mode: got (%q,%q)", p, m)
	}

	// Requesting client when only server.yaml exists → empty.
	dir2 := t.TempDir()
	write(t, dir2, "server.yaml")
	if p, m := discoverConfigIn([]string{dir2}, config.ModeClient); p != "" || m != "" {
		t.Fatalf("client-only-search with server file: got (%q,%q)", p, m)
	}
}

func TestDiscoverConfigInDirOrder(t *testing.T) {
	d1 := t.TempDir()
	d2 := t.TempDir()
	p2 := write(t, d2, "client.yaml")

	// First dir has nothing → falls through to second.
	p, m := discoverConfigIn([]string{d1, d2}, "")
	if p != p2 || m != config.ModeClient {
		t.Fatalf("got (%q,%q), want %q", p, m, p2)
	}

	// First dir wins when both have client.yaml.
	p1 := write(t, d1, "client.yaml")
	p, _ = discoverConfigIn([]string{d1, d2}, "")
	if p != p1 {
		t.Fatalf("got %q, want first-dir %q", p, p1)
	}
}
