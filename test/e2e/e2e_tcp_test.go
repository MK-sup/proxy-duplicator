package e2e

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestTCPBasicStreams walks the full chain (dupc → 2 tunnels → dupd →
// fixture SOCKS5 → httptest target) for small and multi-MB transfers.
func TestTCPBasicStreams(t *testing.T) {
	const bigSize = 10 << 20 // 10 MiB
	big := patternBody(bigSize)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Header().Set("Content-Length", strconv.Itoa(len(big)))
			_, _ = io.Copy(w, bytes.NewReader(big))
		case "/echo":
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body)
		default:
			_, _ = w.Write([]byte("hello-proxy"))
		}
	})
	e := startEnv(t, handler, "")

	// Small GET (retries while tunnels establish).
	var body []byte
	var err error
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		body, err = httpGet(t, e.socksAddr, e.target.URL+"/", 5*time.Second)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("small GET: %v", err)
	}
	if string(body) != "hello-proxy" {
		t.Fatalf("body = %q", body)
	}

	// 10 MiB download must arrive byte-identical.
	got, err := httpGet(t, e.socksAddr, e.target.URL+"/big", 60*time.Second)
	if err != nil {
		t.Fatalf("big GET: %v", err)
	}
	if err := bytesEqual(got, big); err != nil {
		t.Fatalf("big body mismatch: %v", err)
	}

	// 1 MiB POST exercises the upstream direction with many DATA frames.
	post := patternBody(1 << 20)
	echoed, err := httpPost(t, e.socksAddr, e.target.URL+"/echo", post, 60*time.Second)
	if err != nil {
		t.Fatalf("POST echo: %v", err)
	}
	if err := bytesEqual(echoed, post); err != nil {
		t.Fatalf("echo mismatch: %v", err)
	}
}

// TestTCPFailover kills one tunnel mid-transfer: the download must complete
// without corruption, and the dead tunnel must reconnect after revival.
func TestTCPFailover(t *testing.T) {
	const bigSize = 20 << 20
	big := patternBody(bigSize)

	var written atomic.Int64
	reached := make(chan struct{}, 1)
	var fired atomic.Bool

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/big" {
			_, _ = w.Write([]byte("hello-proxy"))
			return
		}
		chunk := 64 << 10
		for off := 0; off < len(big); off += chunk {
			end := off + chunk
			if end > len(big) {
				end = len(big)
			}
			n, err := w.Write(big[off:end])
			written.Add(int64(n))
			if err != nil {
				return
			}
			if f, _ := w.(http.Flusher); f != nil {
				f.Flush()
			}
			if written.Load() > 2<<20 && fired.CompareAndSwap(false, true) {
				select {
				case reached <- struct{}{}:
				default:
				}
			}
		}
	})
	e := startEnv(t, handler, "")

	// Establish the route first.
	if _, err := httpGet(t, e.socksAddr, e.target.URL+"/", 10*time.Second); err != nil {
		t.Fatalf("warmup GET: %v", err)
	}

	type result struct {
		body []byte
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		b, err := httpGet(t, e.socksAddr, e.target.URL+"/big", 120*time.Second)
		resCh <- result{b, err}
	}()

	// Kill tunnel 0 once ≥2 MiB of the body are in flight.
	select {
	case <-reached:
	case <-time.After(30 * time.Second):
		t.Fatal("transfer never reached 2 MiB")
	}
	e.proxies[0].Kill()

	res := <-resCh
	if res.err != nil {
		t.Fatalf("transfer after tunnel kill: %v", res.err)
	}
	if err := bytesEqual(res.body, big); err != nil {
		t.Fatalf("body corrupted after failover: %v", err)
	}

	// Revive the proxy: the client must re-establish tunnel 0 and keep working.
	e.proxies[0].Revive()
	deadline := time.Now().Add(20 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		var b []byte
		b, err = httpGet(t, e.socksAddr, e.target.URL+"/", 5*time.Second)
		if err == nil && string(b) == "hello-proxy" {
			return // success: redial works
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("no successful GET after tunnel revival: %v", err)
}

// TestTCPFourTunnelsHalfKilled: with 4 tunnels, killing half of them must not
// disturb an active transfer; traffic continues over the survivors.
func TestTCPFourTunnelsHalfKilled(t *testing.T) {
	const bigSize = 16 << 20
	big := patternBody(bigSize)

	var written atomic.Int64
	reached := make(chan struct{}, 1)
	var fired atomic.Bool

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/big" {
			_, _ = w.Write([]byte("hello4"))
			return
		}
		chunk := 64 << 10
		for off := 0; off < len(big); off += chunk {
			end := off + chunk
			if end > len(big) {
				end = len(big)
			}
			n, err := w.Write(big[off:end])
			written.Add(int64(n))
			if err != nil {
				return
			}
			if f, _ := w.(http.Flusher); f != nil {
				f.Flush()
			}
			if written.Load() > 2<<20 && fired.CompareAndSwap(false, true) {
				select {
				case reached <- struct{}{}:
				default:
				}
			}
		}
	})
	e := startEnvN(t, handler, 4, "")

	if _, err := httpGet(t, e.socksAddr, e.target.URL+"/", 10*time.Second); err != nil {
		t.Fatalf("warmup GET: %v", err)
	}

	resCh := make(chan error, 1)
	go func() {
		b, err := httpGet(t, e.socksAddr, e.target.URL+"/big", 120*time.Second)
		if err == nil {
			err = bytesEqual(b, big)
		}
		resCh <- err
	}()

	select {
	case <-reached:
	case <-time.After(30 * time.Second):
		t.Fatal("transfer never reached 2 MiB")
	}
	// Kill half the tunnels mid-transfer.
	e.proxies[0].Kill()
	e.proxies[2].Kill()

	if err := <-resCh; err != nil {
		t.Fatalf("transfer after killing 2 of 4 tunnels: %v", err)
	}

	// Revive and confirm full service.
	e.proxies[0].Revive()
	e.proxies[2].Revive()
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		b, err := httpGet(t, e.socksAddr, e.target.URL+"/", 5*time.Second)
		if err == nil && string(b) == "hello4" {
			return
		}
		lastErr = err
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("no success after revival: %v", lastErr)
}

// TestTCPBothTunnelsDown kills both routes: requests fail fast while both
// tunnels are down, then recovery brings the service back.
func TestTCPBothTunnelsDown(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("alive"))
	})
	e := startEnv(t, handler, "")

	// Warmup.
	var err error
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err = httpGet(t, e.socksAddr, e.target.URL+"/", 5*time.Second); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("warmup: %v", err)
	}

	e.proxies[0].Kill()
	e.proxies[1].Kill()

	// The next request must fail (dial timeout) while both tunnels are dead.
	start := time.Now()
	_, err = httpGet(t, e.socksAddr, e.target.URL+"/", 4*time.Second)
	if err == nil {
		t.Fatal("expected request to fail with both tunnels down")
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("failure took too long: %v", elapsed)
	}
	t.Logf("request failed as expected after %v: %v", time.Since(start), err)

	// Restore both tunnels — service must come back.
	e.proxies[0].Revive()
	e.proxies[1].Revive()
	deadline = time.Now().Add(30 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		body, err = httpGet(t, e.socksAddr, e.target.URL+"/", 5*time.Second)
		if err == nil && string(body) == "alive" {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("no recovery after both tunnels revived: %v (last body %q)", err, body)
}
