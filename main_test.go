package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tbshfr/gh-appauth/internal/api"
)

type fakeBroker struct {
	mu          sync.Mutex
	srv         *httptest.Server
	tokenCalls  int
	invalidated []string
	fail500     bool
	n           int
}

const testSecret = "gaa_test-secret"

func newFakeBroker(t *testing.T, useTLS bool) *fakeBroker {
	fb := &fakeBroker{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fb.mu.Lock()
		defer fb.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+testSecret {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(api.Error{Error: "unknown client secret"})
			return
		}
		if fb.fail500 {
			w.WriteHeader(500)
			return
		}
		switch r.URL.Path {
		case "/v1/whoami":
			json.NewEncoder(w).Encode(api.WhoAmI{Client: "tester", IP: "127.0.0.1", Grants: []api.Grant{{App: "a", Repos: []string{"acme/*"}}}})
		case "/v1/token":
			fb.tokenCalls++
			var req api.TokenRequest
			json.NewDecoder(r.Body).Decode(&req)
			if strings.HasPrefix(req.Repository, "acme/denied") {
				w.WriteHeader(403)
				json.NewEncoder(w).Encode(api.Error{Error: `client "tester" has no grant for acme/denied`})
				return
			}
			fb.n++
			json.NewEncoder(w).Encode(api.TokenResponse{
				Token:     "ghs_tok" + string(rune('0'+fb.n)) + "_" + strings.ReplaceAll(req.Repository, "/", "_"),
				ExpiresAt: time.Now().Add(time.Hour).UTC(), Repository: strings.ToLower(req.Repository), App: "a",
				Permissions: map[string]string{"contents": "write"}, BotName: "a[bot]", BotEmail: "1+a[bot]@users.noreply.github.com",
			})
		case "/v1/invalidate":
			var req api.InvalidateRequest
			json.NewDecoder(r.Body).Decode(&req)
			fb.invalidated = append(fb.invalidated, req.Token)
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	})
	if useTLS {
		fb.srv = httptest.NewTLSServer(h)
	} else {
		fb.srv = httptest.NewServer(h)
	}
	t.Cleanup(fb.srv.Close)
	return fb
}

func (fb *fakeBroker) calls() int {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return fb.tokenCalls
}

func (fb *fakeBroker) fingerprint() string {
	sum := sha256.Sum256(fb.srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

// isolate points config and cache at temp dirs and clears overrides.
func isolate(t *testing.T) (cfgDir, cacheDirPath string) {
	t.Helper()
	d := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(d, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(d, "cache"))
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", d)
	for _, k := range []string{"GH_APPAUTH_BROKER", "GH_APPAUTH_SECRET", "GH_APPAUTH_CA_FILE", "GH_APPAUTH_FINGERPRINT", "GH_APPAUTH_INSECURE_HTTP", "GH_APPAUTH_REPO"} {
		t.Setenv(k, "")
	}
	return filepath.Join(d, "config", "gh-appauth"), filepath.Join(d, "cache", "gh-appauth")
}

func useBroker(t *testing.T, fb *fakeBroker) {
	t.Helper()
	t.Setenv("GH_APPAUTH_BROKER", fb.srv.URL)
	t.Setenv("GH_APPAUTH_SECRET", testSecret)
	if strings.HasPrefix(fb.srv.URL, "https") {
		t.Setenv("GH_APPAUTH_FINGERPRINT", fb.fingerprint())
	}
}

func cred(t *testing.T, op, input string) (string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := run([]string{"git-credential", op}, strings.NewReader(input), &out, &errb)
	return out.String(), errb.String(), err
}

func TestCredentialGet(t *testing.T) {
	isolate(t)
	fb := newFakeBroker(t, true)
	useBroker(t, fb)
	out, _, err := cred(t, "get", "protocol=https\nhost=github.com\npath=acme/web.git\n\n")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || lines[0] != "username=x-access-token" || !strings.HasPrefix(lines[1], "password=ghs_") || !strings.HasPrefix(lines[2], "password_expiry_utc=") {
		t.Fatalf("output:\n%s", out)
	}
	if !strings.Contains(lines[1], "acme_web") {
		t.Fatalf("token for wrong repo: %s", lines[1])
	}
}

func TestCredentialIgnoresOtherHosts(t *testing.T) {
	isolate(t)
	fb := newFakeBroker(t, true)
	useBroker(t, fb)
	for _, in := range []string{
		"protocol=https\nhost=gitlab.com\npath=acme/web.git\n",
		"protocol=http\nhost=github.com\npath=acme/web.git\n",
	} {
		out, _, err := cred(t, "get", in)
		if err != nil || out != "" {
			t.Fatalf("%q: out %q err %v", in, out, err)
		}
	}
	if fb.calls() != 0 {
		t.Fatal("broker contacted for a foreign host")
	}
	if out, _, err := cred(t, "store", "protocol=https\nhost=github.com\npath=a/b\npassword=x\n"); err != nil || out != "" {
		t.Fatal("store should be a no-op")
	}
}

func TestCredentialMissingPath(t *testing.T) {
	isolate(t)
	useBroker(t, newFakeBroker(t, true))
	_, stderr, err := cred(t, "get", "protocol=https\nhost=github.com\n")
	if err == nil || !strings.Contains(stderr, "gh appauth git-setup") || !strings.Contains(stderr, "useHttpPath") {
		t.Fatalf("err %v stderr %q", err, stderr)
	}
}

func TestCredentialDenied(t *testing.T) {
	isolate(t)
	useBroker(t, newFakeBroker(t, true))
	out, stderr, err := cred(t, "get", "protocol=https\nhost=github.com\npath=acme/denied.git\n")
	if err == nil || !strings.Contains(out, "quit=1") || !strings.Contains(stderr, "denied for acme/denied") {
		t.Fatalf("out %q stderr %q err %v", out, stderr, err)
	}
	if strings.Contains(stderr, testSecret) {
		t.Fatal("secret leaked in error")
	}
}

func TestCredentialEraseDeletesCache(t *testing.T) {
	_, cdir := isolate(t)
	fb := newFakeBroker(t, true)
	useBroker(t, fb)
	out, _, _ := cred(t, "get", "protocol=https\nhost=github.com\npath=acme/web\n")
	tok := strings.TrimPrefix(strings.Split(out, "\n")[1], "password=")
	if files, _ := os.ReadDir(cdir); len(files) != 1 {
		t.Fatalf("want 1 cache file, got %d", len(files))
	}
	if _, _, err := cred(t, "erase", "protocol=https\nhost=github.com\npath=acme/web\nusername=x-access-token\npassword="+tok+"\n"); err != nil {
		t.Fatal(err)
	}
	if files, _ := os.ReadDir(cdir); len(files) != 0 {
		t.Fatalf("cache not erased: %d files", len(files))
	}
	fb.mu.Lock()
	inv := fb.invalidated
	fb.mu.Unlock()
	if len(inv) != 1 || inv[0] != tok {
		t.Fatalf("broker invalidations = %v", inv)
	}
	out2, _, _ := cred(t, "get", "protocol=https\nhost=github.com\npath=acme/web\n")
	if out2 == out || fb.calls() != 2 {
		t.Fatal("expected a fresh token after erase")
	}
}

func TestTokenCache(t *testing.T) {
	_, cdir := isolate(t)
	fb := newFakeBroker(t, true)
	useBroker(t, fb)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	t1, src, err := getToken(cfg, "acme/web", nil)
	if err != nil || src != fromBroker {
		t.Fatal(src, err)
	}
	t2, src, _ := getToken(cfg, "ACME/web", nil)
	if src != fromCache || t2.Token != t1.Token || fb.calls() != 1 {
		t.Fatalf("expected cache hit, got %s (%d calls)", src, fb.calls())
	}
	// Permissions are part of the key.
	if _, src, _ := getToken(cfg, "acme/web", map[string]string{"contents": "read"}); src != fromBroker {
		t.Fatal("different perms should miss the cache")
	}
	// Directory 0700, files 0600.
	if fi, _ := os.Stat(cdir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir mode %v", fi.Mode().Perm())
	}
	files, _ := os.ReadDir(cdir)
	for _, f := range files {
		fi, _ := f.Info()
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("cache file mode %v", fi.Mode().Perm())
		}
	}

	// A token with <10 min left is refreshed.
	p, _ := cacheFile(cfg, "acme/web", nil)
	writeCached(p, &api.TokenResponse{Token: "ghs_old", ExpiresAt: time.Now().Add(5 * time.Minute), Repository: "acme/web"})
	t3, src, _ := getToken(cfg, "acme/web", nil)
	if src != fromBroker || t3.Token == "ghs_old" {
		t.Fatal("near-expiry token should be refreshed")
	}

	// Broker unreachable: fall back to a cached token with >1 min left.
	writeCached(p, &api.TokenResponse{Token: "ghs_old", ExpiresAt: time.Now().Add(5 * time.Minute), Repository: "acme/web"})
	fb.srv.Close()
	t4, src, err := getToken(cfg, "acme/web", nil)
	if err != nil || src != fromFallback || t4.Token != "ghs_old" {
		t.Fatalf("fallback: %v %s", err, src)
	}
	// ...but not with <1 min left.
	writeCached(p, &api.TokenResponse{Token: "ghs_old", ExpiresAt: time.Now().Add(30 * time.Second), Repository: "acme/web"})
	if _, _, err := getToken(cfg, "acme/web", nil); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("expected unreachable error, got %v", err)
	}
}

func TestRefusalIsNotMaskedByCache(t *testing.T) {
	isolate(t)
	fb := newFakeBroker(t, true)
	useBroker(t, fb)
	cfg, _ := loadConfig()
	p, _ := cacheFile(cfg, "acme/web", nil)
	writeCached(p, &api.TokenResponse{Token: "ghs_old", ExpiresAt: time.Now().Add(5 * time.Minute), Repository: "acme/web"})
	cfg.Secret = "gaa_revoked"
	if _, _, err := getToken(cfg, "acme/web", nil); err == nil {
		t.Fatal("a revoked client must not fall back to cached tokens")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("cache entry should be removed after refusal")
	}
}

func TestRetryOn5xx(t *testing.T) {
	isolate(t)
	fb := newFakeBroker(t, true)
	useBroker(t, fb)
	fb.mu.Lock()
	fb.fail500 = true
	fb.mu.Unlock()
	go func() {
		time.Sleep(200 * time.Millisecond)
		fb.mu.Lock()
		fb.fail500 = false
		fb.mu.Unlock()
	}()
	cfg, _ := loadConfig()
	if _, _, err := getToken(cfg, "acme/web", nil); err != nil {
		t.Fatalf("expected retry to succeed: %v", err)
	}
}

func TestTLSVerification(t *testing.T) {
	isolate(t)
	fb := newFakeBroker(t, true)
	base := &Config{Broker: fb.srv.URL, Secret: testSecret}

	// Self-signed cert, no trust configured: rejected.
	bc, _ := newBrokerClient(base)
	if _, _, err := bc.whoami(); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	// ca_file is honoured.
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fb.srv.Certificate().Raw}), 0o600)
	withCA := *base
	withCA.CAFile = caFile
	bc, _ = newBrokerClient(&withCA)
	if _, _, err := bc.whoami(); err != nil {
		t.Fatalf("ca_file: %v", err)
	}
	// Fingerprint pin: right one works, wrong one fails.
	pinned := *base
	pinned.Fingerprint = fb.fingerprint()
	bc, _ = newBrokerClient(&pinned)
	if _, _, err := bc.whoami(); err != nil {
		t.Fatalf("pin: %v", err)
	}
	wrong := *base
	wrong.Fingerprint = strings.Repeat("ab", 32)
	bc, _ = newBrokerClient(&wrong)
	if _, _, err := bc.whoami(); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("wrong pin accepted: %v", err)
	}
}

func TestBrokerURLValidation(t *testing.T) {
	cases := []struct {
		cfg Config
		ok  bool
	}{
		{Config{Broker: "https://broker.lan:8443"}, true},
		{Config{Broker: "http://127.0.0.1:8080"}, true},
		{Config{Broker: "http://localhost:8080"}, true},
		{Config{Broker: "http://[::1]:8080"}, true},
		{Config{Broker: "http://192.168.1.10:8443"}, false},
		{Config{Broker: "http://broker.lan"}, false},
		{Config{Broker: "http://192.168.1.10:8443", InsecureHTTP: true}, true},
		{Config{Broker: "ftp://x"}, false},
		{Config{Broker: "broker.lan"}, false},
		{Config{Broker: "https://x", Fingerprint: "abc"}, false},
		{Config{Broker: "https://x", Fingerprint: "SHA256:" + strings.Repeat("AB:", 31) + "AB"}, true},
	}
	for _, c := range cases {
		cfg := c.cfg
		if err := cfg.validate(); (err == nil) != c.ok {
			t.Errorf("%+v: err=%v, want ok=%v", c.cfg, err, c.ok)
		}
	}
}

func TestConfigPermissions(t *testing.T) {
	dir, _ := isolate(t)
	if err := saveConfig(&Config{Broker: "https://b", Secret: "s"}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.json")
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v", fi.Mode().Perm())
	}
	os.Chmod(p, 0o644)
	if _, err := loadFileConfig(); err == nil {
		t.Fatal("world-readable config accepted")
	}
	if err := saveConfig(&Config{Broker: "https://b", Secret: "s"}); err == nil {
		t.Fatal("saved over a world-readable config")
	}
}

func TestEnvOverrides(t *testing.T) {
	isolate(t)
	saveConfig(&Config{Broker: "https://file.example", Secret: "file-secret"})
	t.Setenv("GH_APPAUTH_BROKER", "https://env.example")
	t.Setenv("GH_APPAUTH_SECRET", "env-secret")
	c, err := loadConfig()
	if err != nil || c.Broker != "https://env.example" || c.Secret != "env-secret" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestSetup(t *testing.T) {
	dir, _ := isolate(t)
	fb := newFakeBroker(t, true)
	var out, errb bytes.Buffer
	// Without trust, setup fails and shows the fingerprint to pin.
	err := run([]string{"setup", "--broker", fb.srv.URL}, strings.NewReader(testSecret+"\n"), &out, &errb)
	if err == nil || !strings.Contains(err.Error(), colonHex(mustHex(fb.fingerprint()))) {
		t.Fatalf("expected fingerprint hint, got %v", err)
	}
	err = run([]string{"setup", "--broker", fb.srv.URL, "--fingerprint", colonHex(mustHex(fb.fingerprint()))}, strings.NewReader(testSecret+"\n"), &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `client "tester"`) {
		t.Fatalf("output: %s", out.String())
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	var c Config
	json.Unmarshal(b, &c)
	if c.Secret != testSecret || c.Fingerprint != fb.fingerprint() {
		t.Fatalf("saved %+v", c)
	}
	// A wrong secret is not saved.
	err = run([]string{"setup", "--broker", fb.srv.URL, "--fingerprint", fb.fingerprint()}, strings.NewReader("gaa_wrong\n"), &out, &errb)
	if err == nil {
		t.Fatal("wrong secret accepted")
	}
	// Plain http to a LAN host needs --insecure-http.
	err = run([]string{"setup", "--broker", "http://192.168.1.10:8443"}, strings.NewReader(testSecret+"\n"), &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "insecure-http") {
		t.Fatalf("http to LAN host: %v", err)
	}
}

func TestRepoFlag(t *testing.T) {
	cases := map[string]string{
		"pr list -R acme/web":         "acme/web",
		"pr list -Racme/web":          "acme/web",
		"pr list --repo acme/web":     "acme/web",
		"pr list --repo=acme/web":     "acme/web",
		"-R acme/web pr list":         "acme/web",
		"pr view 3 -R=acme/web":       "acme/web",
		"pr list":                     "",
		"api repos -- -R acme/web":    "",
		"pr create --title -R":        "",
		"issue list --repository x/y": "",
	}
	for in, want := range cases {
		got, _ := repoFlag(strings.Fields(in))
		if got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestPassthrough(t *testing.T) {
	for _, a := range [][]string{nil, {"--version"}, {"version"}, {"help"}, {"auth", "status"}, {"extension", "list"}, {"ext"}, {"config", "get"}, {"alias"}, {"completion"}, {"appauth", "status"}} {
		if needsToken(a) {
			t.Errorf("%v should pass through", a)
		}
	}
	for _, a := range [][]string{{"pr", "list"}, {"issue", "create"}, {"api", "/user"}, {"repo", "view"}, {"run", "list"}} {
		if !needsToken(a) {
			t.Errorf("%v should get a token", a)
		}
	}
}

func TestPermFlags(t *testing.T) {
	p := permFlags{}
	if err := p.Set("contents=read"); err != nil || p["contents"] != "read" {
		t.Fatal(err)
	}
	for _, bad := range []string{"contents", "contents=rw", "=read"} {
		if err := p.Set(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
