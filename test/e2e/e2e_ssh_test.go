package e2e

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSSHTransport runs the whole chain over two real SSH tunnels
// (in-process sshd, password auth, pinned host key) instead of plain TCP.
func TestSSHTransport(t *testing.T) {
	const bigSize = 4 << 20
	big := patternBody(bigSize)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			w.Header().Set("Content-Length", fmt.Sprint(len(big)))
			_, _ = io.Copy(w, bytes.NewReader(big))
			return
		}
		_, _ = w.Write([]byte("hello-ssh"))
	})
	e := startEnvBase(t, handler)

	sshdAddr, hostKey := startTestSSHD(t, "dup-pass", e.serverAddr)
	_, dupdPort, err := net.SplitHostPort(e.serverAddr)
	if err != nil {
		t.Fatal(err)
	}

	clientYaml := fmt.Sprintf(`
mode: client
tunnels: 2
transport: ssh
ssh:
  address: %q
  user: dup
  password: dup-pass
  host_key: %q
  forward_port: %s
  connect_timeout: 5s
  keepalive_interval: 2s
ping_interval: 1s
ping_timeout: 5s
reconnect: {initial: 200ms, max: 1s}
relay_close_grace: 5s
queue: {frames: 512}
log: {level: error}
`, sshdAddr, strings.TrimSpace(hostKey), dupdPort)
	e.startClient(t, clientYaml)

	// Warmup (retries while the SSH tunnels establish).
	var body []byte
	var gerr error
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		body, gerr = httpGet(t, e.socksAddr, e.target.URL+"/", 5*time.Second)
		if gerr == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if gerr != nil {
		t.Fatalf("warmup GET over SSH: %v", gerr)
	}
	if string(body) != "hello-ssh" {
		t.Fatalf("body = %q", body)
	}

	// 4 MiB integrity through the SSH tunnels.
	got, err := httpGet(t, e.socksAddr, e.target.URL+"/big", 60*time.Second)
	if err != nil {
		t.Fatalf("big GET over SSH: %v", err)
	}
	if err := bytesEqual(got, big); err != nil {
		t.Fatalf("big body mismatch: %v", err)
	}
}

// TestSSHWrongHostKey verifies pinning: with a mismatched host key no tunnel
// can ever come up, so requests fail.
func TestSSHWrongHostKey(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("nope"))
	})
	e := startEnvBase(t, handler)

	sshdAddr, _ := startTestSSHD(t, "dup-pass", e.serverAddr)
	_, dupdPort, _ := net.SplitHostPort(e.serverAddr)

	clientYaml := fmt.Sprintf(`
mode: client
tunnels: 2
transport: ssh
ssh:
  address: %q
  user: dup
  password: dup-pass
  host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbLry9FnH0UTQu1PsQvJhXqV4OqRZl9w1z0dVYq0000"
  forward_port: %s
  connect_timeout: 3s
  keepalive_interval: 2s
ping_interval: 1s
ping_timeout: 4s
reconnect: {initial: 200ms, max: 1s}
log: {level: error}
`, sshdAddr, dupdPort)
	e.startClient(t, clientYaml)

	_, err := httpGet(t, e.socksAddr, e.target.URL+"/", 4*time.Second)
	if err == nil {
		t.Fatal("expected failure with pinned wrong host key")
	}
	t.Logf("correctly failed: %v", err)
}
