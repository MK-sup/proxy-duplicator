package transport

import (
	"crypto/ed25519"
	"crypto/rand"
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
