package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testSSHD is a minimal in-process SSH server supporting password auth and
// direct-tcpip forwarding — enough to exercise transport.DialSSH end-to-end
// without a system sshd.
type testSSHD struct {
	ln        net.Listener
	signer    ssh.Signer
	forwardTo string // default backend (127.0.0.1:port of dupd)

	mu    sync.Mutex
	conns []net.Conn
}

// startTestSSHD runs the server on a random loopback port. Returns the listen
// address and the pinned host-key line (authorized_keys format).
func startTestSSHD(t *testing.T, password, forwardTo string) (addr, hostKeyLine string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	sc := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("bad password")
		},
	}
	sc.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSSHD{ln: ln, signer: signer, forwardTo: forwardTo}
	go s.serve(sc)
	t.Cleanup(func() {
		ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
	})
	return ln.Addr().String(), string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

func (s *testSSHD) serve(sc *ssh.ServerConfig) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()
		go s.handle(conn, sc)
	}
}

type directTCPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func (s *testSSHD) handle(conn net.Conn, sc *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sc)
	if err != nil {
		conn.Close()
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "direct-tcpip" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(chReqs)

		var payload directTCPPayload
		if err := ssh.Unmarshal(newCh.ExtraData(), &payload); err != nil {
			ch.Close()
			continue
		}
		backendAddr := net.JoinHostPort(payload.DestAddr, fmt.Sprint(payload.DestPort))
		backend, err := net.Dial("tcp", backendAddr)
		if err != nil {
			ch.Close()
			continue
		}
		go func() {
			io.Copy(backend, ch)
			backend.Close()
		}()
		go func() {
			io.Copy(ch, backend)
			ch.Close()
		}()
	}
}
