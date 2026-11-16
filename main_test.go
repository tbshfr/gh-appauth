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
	tokenStatus int // if set, /v1/token answers with this status
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
			if fb.tokenStatus != 0 {
				w.WriteHeader(fb.tokenStatus)
				json.NewEncoder(w).Encode(api.Error{Error: "refused"})
				return
			}
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
		case "/v1/repos":
			if r.URL.Query().Get("owner") != "acme" {
				w.WriteHeader(403)
				json.NewEncoder(w).Encode(api.Error{Error: "no grant"})
				return
			}
			json.NewEncoder(w).Encode(api.RepoList{Repos: []api.Repo{
				{FullName: "acme/api", DefaultBranch: "main", Private: true, App: "a"},
				{FullName: "acme/old", DefaultBranch: "master", Archived: true, App: "a"},
			}})
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
	fb.tokenStatus = 403
	if _, _, err := getToken(cfg, "acme/web", nil); err == nil {
		t.Fatal("a revoked client must not fall back to cached tokens")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("cache entry should be removed after refusal")
	}
}

func TestRateLimitKeepsCache(t *testing.T) {
	isolate(t)
	fb := newFakeBroker(t, true)
	useBroker(t, fb)
	cfg, _ := loadConfig()
	p, _ := cacheFile(cfg, "acme/web", nil)
	writeCached(p, &api.TokenResponse{Token: "ghs_old", ExpiresAt: time.Now().Add(5 * time.Minute), Repository: "acme/web"})
	fb.tokenStatus = 429
	tok, src, err := getToken(cfg, "acme/web", nil)
	if err != nil || src != fromFallback || tok.Token != "ghs_old" {
		t.Fatalf("rate limited with a valid cached token: %v %s", err, src)
	}
	// A bad request is an error, but no reason to drop the cached token.
	fb.tokenStatus = 400
	if _, _, err := getToken(cfg, "acme/web", nil); err == nil {
		t.Fatal("400 was masked by the cache")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("cache entry removed after a 400")
	}
}

func TestCacheIsPerClient(t *testing.T) {
	isolate(t)
	fb := newFakeBroker(t, true)
	useBroker(t, fb)
	cfg, _ := loadConfig()
	if _, _, err := getToken(cfg, "acme/web", nil); err != nil {
		t.Fatal(err)
	}
	other := *cfg
	other.Secret = "gaa_other-client"
	if _, src, err := getToken(&other, "acme/web", nil); err == nil {
		t.Fatalf("another client's secret was served from %s", src)
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

func TestPositionalArg(t *testing.T) {
	cases := map[string]string{
		"repo clone acme/web":                                            "acme/web",
		"repo clone https://github.com/acme/web":                         "https://github.com/acme/web",
		"repo clone acme/web dir -- --depth 1":                           "acme/web",
		"repo clone -u up acme/web":                                      "acme/web",
		"repo clone --upstream-remote-name up acme/web":                  "acme/web",
		"repo clone --no-upstream acme/web":                              "acme/web",
		"repo clone -- acme/web":                                         "",
		"repo view acme/web --json name":                                 "acme/web",
		"repo view --json name acme/web":                                 "acme/web",
		"repo view -b feat/x acme/web":                                   "acme/web",
		"repo view -w":                                                   "",
		"repo list acme":                                                 "",
		"repo fork --org o acme/web -- --depth 1":                        "acme/web",
		"repo fork --clone":                                              "",
		"repo set-default acme/web":                                      "acme/web",
		"repo set-default --view":                                        "",
		"co https://github.com/a/b/pull/1":                               "https://github.com/a/b/pull/1",
		"co":                                                             "",
		"pr merge --match-head-commit abc https://github.com/a/b/pull/1": "https://github.com/a/b/pull/1",
		"pr view 12":                                                     "12",
		"pr view --web https://github.com/a/b/pull/1":                    "https://github.com/a/b/pull/1",
		"pr comment 3 -b https://github.com/a/b/pull/1":                  "3",
		"pr comment -b https://github.com/a/b/pull/1":                    "",
		"issue view -R x/y --json title 7":                               "7",
		"pr list https://github.com/a/b/pull/1":                          "",
	}
	for in, want := range cases {
		_, got, _ := positionalArg(strings.Fields(in))
		if got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestShimRepo(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := &Config{}
	cases := []struct {
		args, ghRepo, want string
	}{
		{"pr view https://github.com/url/r/pull/1/files -R flag/r", "env/r", "url/r"},
		{"issue view https://github.com/url/r/issues/2", "", "url/r"},
		{"pr view 1 -R flag/r", "env/r", "flag/r"},
		{"pr list", "env/r", "env/r"},
		{"pr list", "github.com/env/r", "env/r"},
		{"repo clone acme/web", "env/r", "acme/web"},
		{"co https://github.com/url/r/pull/1", "env/r", "url/r"},
		{"pr list", "", ""},
	}
	for _, c := range cases {
		t.Setenv("GH_REPO", c.ghRepo)
		t.Setenv("GH_APPAUTH_REPO", "")
		got, err := shimRepo(cfg, strings.Fields(c.args))
		if err != nil || got != c.want {
			t.Errorf("%q GH_REPO=%q: got %q, %v want %q", c.args, c.ghRepo, got, err, c.want)
		}
	}
	if _, err := shimRepo(cfg, []string{"pr", "view", "https://gitlab.com/a/b/pull/1"}); err == nil {
		t.Error("URL on another host should be refused")
	}
}

func TestPickBaseRepo(t *testing.T) {
	remote := func(name, url string) string {
		return name + "\t" + url + " (fetch)\n" + name + "\t" + url + " (push)\n"
	}
	origin := remote("origin", "https://github.com/me/fork.git")
	upstream := remote("acme", "git@github.com:acme/other.git") + remote("upstream", "https://github.com/acme/parent")
	cases := []struct {
		name, remotes, resolved, want string
	}{
		{"origin only", origin, "", "me/fork"},
		{"partial clone", "origin\thttps://github.com/me/fork (fetch) [blob:none]\norigin\thttps://github.com/me/fork (push)\n", "", "me/fork"},
		{"upstream beats origin", upstream + origin, "", "acme/parent"},
		{"github beats origin", remote("github", "https://github.com/gh/r") + origin, "", "gh/r"},
		{"origin beats others", remote("aaa", "https://github.com/a/a") + origin, "", "me/fork"},
		{"others in git order", remote("aaa", "https://github.com/a/a") + remote("bbb", "https://github.com/b/b"), "", "a/a"},
		{"set-default base", upstream + origin, "remote.origin.gh-resolved base\n", "me/fork"},
		{"set-default name", upstream + origin, "remote.origin.gh-resolved other/thing\n", "other/thing"},
		{"other hosts skipped", remote("upstream", "https://gitlab.com/x/y") + origin, "remote.upstream.gh-resolved base\n", "me/fork"},
	}
	for _, c := range cases {
		got, err := pickBaseRepo(c.remotes, c.resolved, "github.com")
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v want %q", c.name, got, err, c.want)
		}
	}
	if _, err := pickBaseRepo(remote("origin", "https://gitlab.com/x/y"), "", "github.com"); err == nil {
		t.Error("no GitHub remote should be an error")
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

func TestVersionCommand(t *testing.T) {
	for _, arg := range []string{"version", "--version"} {
		var out bytes.Buffer
		var errb bytes.Buffer
		if err := run([]string{arg}, strings.NewReader(""), &out, &errb); err != nil {
			t.Fatalf("%s: %v", arg, err)
		}
		if !strings.HasPrefix(out.String(), "gh-appauth ") {
			t.Errorf("%s printed %q", arg, out.String())
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

func TestRepos(t *testing.T) {
	isolate(t)
	fb := newFakeBroker(t, false)
	useBroker(t, fb)
	var out bytes.Buffer
	if err := run([]string{"repos", "acme"}, nil, &out, &out); err != nil {
		t.Fatal(err)
	}
	if want := "acme/api\tmain\tprivate\ta\nacme/old\tmaster\tpublic, archived\ta\n"; out.String() != want {
		t.Fatalf("output %q", out.String())
	}
	out.Reset()
	if err := run([]string{"repos", "--no-archived", "--json", "acme"}, nil, &out, &out); err != nil {
		t.Fatal(err)
	}
	var l api.RepoList
	if err := json.Unmarshal(out.Bytes(), &l); err != nil || len(l.Repos) != 1 || l.Repos[0].FullName != "acme/api" {
		t.Fatalf("json %s (%v)", out.String(), err)
	}
	if err := run([]string{"repos", "other"}, nil, &out, &out); err == nil || !strings.Contains(err.Error(), "no grant") {
		t.Fatalf("other owner: %v", err)
	}
	for _, args := range [][]string{{"repos"}, {"repos", "a/b"}, {"repos", "a", "b"}} {
		if err := run(args, nil, &out, &out); err == nil {
			t.Fatalf("%v: no error", args)
		}
	}
}

func gitRepo(t *testing.T, origin string) {
	t.Helper()
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "gitconfig"))
	dir := t.TempDir()
	t.Chdir(dir)
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", origin}} {
		if _, err := gitOut(args...); err != nil {
			t.Fatal(err)
		}
	}
}

func localIdentity(t *testing.T) string {
	t.Helper()
	v, _ := gitOut("config", "--local", "--get-regexp", `^user\.(name|email)$`)
	return v
}

func TestCredentialSetsIdentity(t *testing.T) {
	const get = "protocol=https\nhost=github.com\npath=acme/web.git\n\n"
	t.Run("empty repo config", func(t *testing.T) {
		isolate(t)
		useBroker(t, newFakeBroker(t, true))
		gitRepo(t, "https://github.com/Acme/Web.git")
		if _, err := gitOut("config", "--global", "user.name", "Human"); err != nil {
			t.Fatal(err)
		}
		_, stderr, err := cred(t, "get", get)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := localIdentity(t), "user.name a[bot]\nuser.email 1+a[bot]@users.noreply.github.com"; got != want {
			t.Fatalf("local identity %q, want %q", got, want)
		}
		if !strings.Contains(stderr, "authored as a[bot]") {
			t.Fatalf("stderr: %q", stderr)
		}
	})
	for name, setup := range map[string][]string{
		"own email":        {"config", "user.email", "me@example.com"},
		"auto off":         {"config", "--global", "gh-appauth.autoIdentity", "off"},
		"auto typo":        {"config", "--global", "gh-appauth.autoIdentity", "flase"},
		"different origin": {"remote", "set-url", "origin", "https://github.com/acme/fork.git"},
	} {
		t.Run(name, func(t *testing.T) {
			isolate(t)
			useBroker(t, newFakeBroker(t, true))
			gitRepo(t, "https://github.com/acme/web.git")
			if _, err := gitOut(setup...); err != nil {
				t.Fatal(err)
			}
			before := localIdentity(t)
			_, stderr, err := cred(t, "get", get)
			if err != nil {
				t.Fatal(err)
			}
			if got := localIdentity(t); got != before || stderr != "" {
				t.Fatalf("identity changed to %q (stderr %q)", got, stderr)
			}
		})
	}
}

func TestGitHookSetsIdentityOnClone(t *testing.T) {
	isolate(t)
	fb := newFakeBroker(t, true)
	useBroker(t, fb)
	gitRepo(t, "https://github.com/acme/web.git")
	hook := func(old string) {
		t.Helper()
		var out, errb bytes.Buffer
		if err := run([]string{"git-hook", "post-checkout", old, strings.Repeat("a", 40), "1"}, nil, &out, &errb); err != nil {
			t.Fatal(err)
		}
	}
	hook(strings.Repeat("b", 40))
	if fb.calls() != 0 || localIdentity(t) != "" {
		t.Fatal("a plain checkout must not touch the identity")
	}
	hook(strings.Repeat("0", 40))
	if !strings.Contains(localIdentity(t), "a[bot]") {
		t.Fatalf("identity after clone: %q", localIdentity(t))
	}

	gitRepo(t, "https://github.com/acme/denied.git")
	hook(strings.Repeat("0", 64))
	if localIdentity(t) != "" {
		t.Fatal("denied repo got an identity")
	}
}

func TestHookCommandToleratesMissingBinary(t *testing.T) {
	gitRepo(t, "https://github.com/acme/web.git")
	for _, args := range [][]string{
		{"config", "--global", "hook." + hookName + ".command", hookCommand(filepath.Join(t.TempDir(), "gone"))},
		{"config", "--global", "hook." + hookName + ".event", "post-checkout"},
		{"-c", "user.name=x", "-c", "user.email=x@x", "commit", "-q", "--allow-empty", "-m", "init"},
		{"checkout", "-q", "-b", "other"},
	} {
		if _, err := gitOut(args...); err != nil {
			t.Fatal(err)
		}
	}
}
