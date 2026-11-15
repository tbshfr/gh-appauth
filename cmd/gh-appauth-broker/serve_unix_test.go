//go:build unix

package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startServe runs serve() in the background and returns the bound
// addresses. It stops the server with SIGTERM, which serve() handles.
func startServe(t *testing.T, c serveConfig) ([]string, <-chan error) {
	t.Helper()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- serve(c, ready) }()
	select {
	case a := <-ready:
		return strings.Fields(a), done
	case err := <-done:
		t.Fatalf("serve: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not start")
	}
	return nil, nil
}

func stopServe(t *testing.T, done <-chan error) {
	t.Helper()
	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestServeSelfSignedTLSStableFingerprint(t *testing.T) {
	db := filepath.Join(t.TempDir(), "b.db")
	cfg := serveConfig{DB: db, Listen: "127.0.0.1:0", UIListen: "127.0.0.1:0", TLSMode: tlsSelf, GitHubAPI: "http://127.0.0.1:1", HistoryDays: 30}
	var fps []string
	for i := 0; i < 2; i++ {
		addrs, done := startServe(t, cfg)
		var fp string
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // the test checks the fingerprint itself
			VerifyConnection: func(cs tls.ConnectionState) error {
				fp = certFingerprint(cs.PeerCertificates[0].Raw)
				if cs.Version < tls.VersionTLS12 {
					t.Errorf("TLS version %x", cs.Version)
				}
				return nil
			},
		}}}
		resp, err := c.Get("https://" + addrs[0] + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "ok\n" {
			t.Fatalf("healthz = %q", b)
		}
		// The UI is on its own listener, not on the API one.
		resp, err = c.Get("https://" + addrs[0] + "/ui/login")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("UI on API listener: %d", resp.StatusCode)
		}
		resp, err = c.Get("https://" + addrs[1] + "/ui/login")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("UI listener: %d", resp.StatusCode)
		}
		fps = append(fps, fp)
		stopServe(t, done)
	}
	if fps[0] == "" || fps[0] != fps[1] {
		t.Fatalf("fingerprint changed across restarts: %v", fps)
	}
}

func TestServeTLSOff(t *testing.T) {
	db := filepath.Join(t.TempDir(), "b.db")
	addrs, done := startServe(t, serveConfig{DB: db, Listen: "127.0.0.1:0", TLSMode: tlsOff, GitHubAPI: "http://127.0.0.1:1", HistoryDays: 30})
	resp, err := http.Get("http://" + addrs[0] + "/ui/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("shared UI: %d", resp.StatusCode)
	}
	stopServe(t, done)
}

func TestServeRejectsBadTLSMode(t *testing.T) {
	err := serve(serveConfig{DB: filepath.Join(t.TempDir(), "b.db"), Listen: "127.0.0.1:0", TLSMode: "maybe"}, nil)
	if err == nil {
		t.Fatal("bad -tls accepted")
	}
	err = serve(serveConfig{DB: filepath.Join(t.TempDir(), "b.db"), Listen: "127.0.0.1:0", TLSMode: tlsFiles}, nil)
	if err == nil {
		t.Fatal("-tls files without cert accepted")
	}
}

func TestListenUnix(t *testing.T) {
	p := filepath.Join(t.TempDir(), "broker.sock")
	for i := 0; i < 2; i++ { // the second round replaces a stale socket
		ln, err := listenUnix(p)
		if err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o660 {
			t.Fatalf("socket mode %v, err %v", fi.Mode().Perm(), err)
		}
		c, err := net.Dial("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		ln.Close()
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".sock-*")); len(left) != 0 {
		t.Fatalf("temporary directory left behind: %v", left)
	}
}
