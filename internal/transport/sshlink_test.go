package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestHostKeyCallbackEmptyAcceptsAny(t *testing.T) {
	cb, err := hostKeyCallback("")
	if err != nil || cb == nil {
		t.Fatalf("cb=%v err=%v", cb, err)
	}
}

func TestHostKeyCallbackRejectsGarbage(t *testing.T) {
	if _, err := hostKeyCallback("not-a-key"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestHostKeyCallbackPinnedMatches(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	cb, err := hostKeyCallback(line)
	if err != nil {
		t.Fatalf("parse pinned key: %v", err)
	}
	// The pinned callback must accept exactly this key and reject another.
	if err := cb("dummy", nil, signer.PublicKey()); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromKey(priv2)
	if err := cb("dummy", nil, other.PublicKey()); err == nil {
		t.Fatal("unpinned key must be rejected")
	}
}

func TestAuthMethods(t *testing.T) {
	// Neither configured → error.
	if _, err := authMethods(SSHDialConfig{}); err == nil {
		t.Fatal("expected error with no auth")
	}
	// Password only → ok.
	m, err := authMethods(SSHDialConfig{Password: "x"})
	if err != nil || len(m) != 1 {
		t.Fatalf("password: m=%d err=%v", len(m), err)
	}
	// Missing key file → error.
	_, err = authMethods(SSHDialConfig{KeyFile: filepath.Join(t.TempDir(), "nokey")})
	if err == nil {
		t.Fatal("expected missing key error")
	}
	// Unparsable key file → error.
	bad := filepath.Join(t.TempDir(), "badkey")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := authMethods(SSHDialConfig{KeyFile: bad}); err == nil {
		t.Fatal("expected parse error")
	}
	// Password + key: key parse error still surfaces first.
	if _, err := authMethods(SSHDialConfig{Password: "x", KeyFile: bad}); err == nil {
		t.Fatal("expected key parse error to surface")
	}
}

func TestDialSSHDialTimeout(t *testing.T) {
	// Closed port on loopback: dial must fail fast, not hang.
	cfg := SSHDialConfig{
		Address:        "127.0.0.1:1",
		User:           "nobody",
		Password:       "x",
		ConnectTimeout: 500 * time.Millisecond,
	}
	if _, err := DialSSH(t.Context(), cfg, "test#0"); err == nil {
		t.Fatal("expected dial failure")
	}
}

func TestKeepaliveTrackerRefuseIsNotFatal(t *testing.T) {
	// !ok without err (REQUEST_FAILURE) must never tear down.
	k := &keepaliveTracker{threshold: keepaliveFails}
	for i := 0; i < 20; i++ {
		if k.record(nil) {
			t.Fatalf("refused keepalive counted as fatal at i=%d", i)
		}
	}
	if k.fails != 0 {
		t.Fatalf("fails=%d, want 0 after successes", k.fails)
	}
}

func TestKeepaliveTrackerHardErrThreshold(t *testing.T) {
	k := &keepaliveTracker{threshold: keepaliveFails}
	err := errors.New("broken pipe")
	for i := 0; i < keepaliveFails-1; i++ {
		if k.record(err) {
			t.Fatalf("premature teardown at fail %d/%d", i+1, keepaliveFails)
		}
	}
	if !k.record(err) {
		t.Fatalf("expected teardown at fail %d/%d", keepaliveFails, keepaliveFails)
	}
	// Success resets the counter.
	k2 := &keepaliveTracker{threshold: keepaliveFails}
	_ = k2.record(err)
	_ = k2.record(err)
	_ = k2.record(nil)
	if k2.fails != 0 {
		t.Fatalf("fails=%d after success, want 0", k2.fails)
	}
}
