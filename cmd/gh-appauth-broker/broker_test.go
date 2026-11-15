package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tbshfr/gh-appauth/internal/api"
	"github.com/tbshfr/gh-appauth/internal/fakegithub"
)

var (
	keyOnce        sync.Once
	key1, key2     *rsa.PrivateKey
	key1PEM, k2PEM string
)

func keys(t *testing.T) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if key1, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if key2, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		key1PEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key1)}))
		p8, _ := x509.MarshalPKCS8PrivateKey(key2)
		k2PEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))
	})
}

const (
	secretA  = "gaa_secret-alice"
	secretA2 = "gaa_secret-alice-rotated"
	secretB  = "gaa_secret-bob"
)

type env struct {
	t      *testing.T
	b      *Broker
	store  *Store
	gh     *fakegithub.Server
	ghSrv  *httptest.Server
	h      http.Handler
	logBuf *syncBuf
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newEnv(t *testing.T, mod func(*Options)) *env {
	t.Helper()
	keys(t)
	gh := fakegithub.New(
		&fakegithub.App{ID: 123456, Slug: "backend-bot", BotID: 555, PublicKey: &key1.PublicKey, Installations: []*fakegithub.Installation{
			{ID: 11, Owner: "acme", Repos: []string{"api-core", "api-auth", "web"}, Permissions: map[string]string{
				"contents": "write", "pull_requests": "write", "issues": "write", "metadata": "read", "administration": "read"}},
		}},
		&fakegithub.App{ID: 234567, Slug: "frontend-bot", BotID: 777, PublicKey: &key2.PublicKey, Installations: []*fakegithub.Installation{
			{ID: 22, Owner: "acme", Permissions: map[string]string{"contents": "write", "metadata": "read"}},
		}},
	)
	ghSrv := httptest.NewServer(gh)
	t.Cleanup(ghSrv.Close)

	st, err := OpenStore(filepath.Join(t.TempDir(), "broker.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	must(t, st.PutApp(AppRow{Name: "backend-bot", AppID: 123456, PrivateKey: key1PEM}))
	must(t, st.PutApp(AppRow{Name: "frontend-bot", AppID: 234567, PrivateKey: k2PEM}))
	must(t, st.CreateClient(ClientRow{Name: "alice"}))
	must(t, st.AddSecret("alice", sha256Hex(secretA), "a1"))
	must(t, st.AddSecret("alice", sha256Hex(secretA2), "a2"))
	must(t, st.AddGrant(GrantRow{Client: "alice", App: "backend-bot", Repos: []string{"acme/api-*"},
		Permissions: map[string]string{"contents": "write", "pull_requests": "write", "issues": "write", "metadata": "read"}}))
	must(t, st.AddGrant(GrantRow{Client: "alice", App: "frontend-bot", Repos: []string{"Acme/Web", "nope/*"}}))
	must(t, st.CreateClient(ClientRow{Name: "bob", AllowedCIDRs: []string{"10.1.0.0/16"}}))
	must(t, st.AddSecret("bob", sha256Hex(secretB), ""))
	must(t, st.AddGrant(GrantRow{Client: "bob", App: "backend-bot", Repos: []string{"acme/api-core"}}))

	lb := &syncBuf{}
	opts := Options{GitHubAPI: ghSrv.URL, Log: lb}
	if mod != nil {
		mod(&opts)
	}
	b, err := NewBroker(st, opts)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, b: b, store: st, gh: gh, ghSrv: ghSrv, h: b.APIHandler(true), logBuf: lb}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type resp struct {
	code int
	body []byte
	tok  api.TokenResponse
	err  string
}

func (e *env) do(method, path, secret, remote string, body any, hdr map[string]string) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = strings.NewReader(s)
		} else {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
	}
	r := httptest.NewRequest(method, path, rd)
	if remote == "" {
		remote = "10.1.2.3:5555"
	}
	r.RemoteAddr = remote
	if secret != "" {
		r.Header.Set("Authorization", "Bearer "+secret)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	out := resp{code: w.Code, body: w.Body.Bytes()}
	if w.Code == 200 && path == "/v1/token" {
		must(e.t, json.Unmarshal(out.body, &out.tok))
	} else {
		var er api.Error
		_ = json.Unmarshal(out.body, &er)
		out.err = er.Error
	}
	return out
}

func (e *env) token(secret, repo string, perms map[string]string) resp {
	e.t.Helper()
	return e.do("POST", "/v1/token", secret, "", api.TokenRequest{Repository: repo, Permissions: perms}, nil)
}

func (e *env) noJWTErrors() {
	e.t.Helper()
	if errs := e.gh.JWTErrors(); len(errs) > 0 {
		e.t.Fatalf("fake GitHub rejected JWTs: %v", errs)
	}
}

func mintBodies(gh *fakegithub.Server) []map[string]any {
	var out []map[string]any
	for _, c := range gh.Calls() {
		if c.Method == "POST" && strings.HasSuffix(c.Path, "/access_tokens") {
			var m map[string]any
			json.Unmarshal([]byte(c.Body), &m)
			out = append(out, m)
		}
	}
	return out
}

func TestTokenIssued(t *testing.T) {
	e := newEnv(t, nil)
	r := e.token(secretA, "acme/api-core", nil)
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	e.noJWTErrors()
	if !strings.HasPrefix(r.tok.Token, "ghs_") || r.tok.Repository != "acme/api-core" || r.tok.App != "backend-bot" || r.tok.Cached {
		t.Fatalf("unexpected response %+v", r.tok)
	}
	if r.tok.BotName != "backend-bot[bot]" || r.tok.BotEmail != "555+backend-bot[bot]@users.noreply.github.com" {
		t.Fatalf("bot identity: %q %q", r.tok.BotName, r.tok.BotEmail)
	}
	bodies := mintBodies(e.gh)
	if len(bodies) != 1 {
		t.Fatalf("want 1 mint call, got %d", len(bodies))
	}
	repos := bodies[0]["repositories"].([]any)
	if len(repos) != 1 || repos[0] != "api-core" {
		t.Fatalf("repositories = %v", repos)
	}
	perms := bodies[0]["permissions"].(map[string]any)
	want := map[string]string{"contents": "write", "pull_requests": "write", "issues": "write", "metadata": "read"}
	if len(perms) != len(want) {
		t.Fatalf("permissions = %v", perms)
	}
	for k, v := range want {
		if perms[k] != v {
			t.Fatalf("permissions = %v", perms)
		}
	}
	if !strings.Contains(e.logBuf.String(), `"event":"issued"`) || strings.Contains(e.logBuf.String(), r.tok.Token) {
		t.Fatalf("audit log wrong or leaks token: %s", e.logBuf.String())
	}
	rows, _ := e.store.Requests(RequestFilter{})
	if len(rows) != 1 || rows[0].Event != "issued" || rows[0].Client != "alice" || rows[0].Repo != "acme/api-core" {
		t.Fatalf("history = %+v", rows)
	}
}

func TestEmptyGrantMeansInstallationPermissions(t *testing.T) {
	e := newEnv(t, nil)
	r := e.token(secretA, "ACME/web", nil)
	if r.code != 200 || r.tok.App != "frontend-bot" || r.tok.Repository != "acme/web" {
		t.Fatalf("code %d %s", r.code, r.body)
	}
	if _, has := mintBodies(e.gh)[0]["permissions"]; has {
		t.Fatal("empty grant should not send permissions")
	}
	if r.tok.Permissions["contents"] != "write" {
		t.Fatalf("permissions = %v", r.tok.Permissions)
	}
	e.noJWTErrors() // PKCS#8 key works
}

func TestCacheHit(t *testing.T) {
	e := newEnv(t, nil)
	r1 := e.token(secretA, "acme/api-core", nil)
	r2 := e.token(secretA, "acme/API-core", nil)
	if r1.code != 200 || r2.code != 200 {
		t.Fatal(r1.code, r2.code)
	}
	if r1.tok.Token != r2.tok.Token || !r2.tok.Cached {
		t.Fatalf("expected cached token")
	}
	if n := e.gh.CallCount("POST /app/installations"); n != 1 {
		t.Fatalf("mint calls = %d", n)
	}
	// Same repo, different permissions: different cache entry, but the
	// installation lookup for the owner is cached.
	r3 := e.token(secretA, "acme/api-core", map[string]string{"contents": "read"})
	r4 := e.token(secretA, "acme/api-auth", nil)
	if r3.code != 200 || r4.code != 200 || r3.tok.Token == r1.tok.Token {
		t.Fatal("expected fresh tokens")
	}
	if n := e.gh.CallCount("GET /repos/"); n != 1 {
		t.Fatalf("installation lookups = %d, want 1 (cached per owner)", n)
	}
	if n := e.gh.CallCount("GET /app"); n != 1 {
		t.Fatalf("GET /app calls = %d, want 1 (identity cached)", n)
	}
}

func TestNarrowedPermissions(t *testing.T) {
	e := newEnv(t, nil)
	r := e.token(secretA, "acme/api-core", map[string]string{"contents": "read", "metadata": "read"})
	if r.code != 200 {
		t.Fatalf("code %d %s", r.code, r.body)
	}
	perms := mintBodies(e.gh)[0]["permissions"].(map[string]any)
	if len(perms) != 2 || perms["contents"] != "read" || perms["metadata"] != "read" {
		t.Fatalf("permissions sent = %v", perms)
	}
}

func TestUnauthorized(t *testing.T) {
	e := newEnv(t, nil)
	for _, s := range []string{"", "gaa_wrong"} {
		if r := e.token(s, "acme/api-core", nil); r.code != 401 {
			t.Errorf("secret %q: code %d", s, r.code)
		}
	}
	if r := e.do("GET", "/v1/whoami", "nope", "", nil, nil); r.code != 401 {
		t.Errorf("whoami: %d", r.code)
	}
}

func TestForbidden(t *testing.T) {
	e := newEnv(t, nil)
	cases := []struct {
		repo  string
		perms map[string]string
		want  string
	}{
		{"acme/other", nil, "no grant"},
		{"evil/api-core", nil, "no grant"},
		{"acme/api-core", map[string]string{"contents": "admin"}, "exceeds"},
		{"acme/api-core", map[string]string{"workflows": "write"}, "not in the grant"},
		{"acme/api-core", map[string]string{"contents": "superuser"}, "level"},
		{"nope/thing", nil, "not installed"}, // 404 on installation lookup
	}
	for _, c := range cases {
		r := e.token(secretA, c.repo, c.perms)
		if r.code != 403 || !strings.Contains(r.err, c.want) {
			t.Errorf("%s %v: code %d err %q, want 403 containing %q", c.repo, c.perms, r.code, r.err, c.want)
		}
	}
	// api-zzz matches the grant, but isn't among the installation's selected
	// repos. The installation for acme is already cached, so GitHub answers
	// the mint with 422.
	if r := e.token(secretA, "acme/api-core", nil); r.code != 200 {
		t.Fatal(r.code)
	}
	r := e.token(secretA, "acme/api-zzz", nil)
	if r.code != 403 || !strings.Contains(r.err, "not installed") {
		t.Fatalf("422 mapping: %d %q", r.code, r.err)
	}
}

func TestBadRequests(t *testing.T) {
	e := newEnv(t, nil)
	for _, repo := range []string{"acme/../../app", "acme/x/y", "acme", "", "acme/web?x=1"} {
		if r := e.token(secretA, repo, nil); r.code != 400 {
			t.Errorf("%q: code %d", repo, r.code)
		}
	}
	if r := e.do("POST", "/v1/token", secretA, "", `{"repository":"acme/api-core","bogus":1}`, nil); r.code != 400 {
		t.Errorf("unknown field: %d", r.code)
	}
	if r := e.do("POST", "/v1/token", secretA, "", strings.Repeat("x", maxBody+10), nil); r.code != 400 {
		t.Errorf("oversized body: %d", r.code)
	}
}

func TestAllowedCIDRs(t *testing.T) {
	e := newEnv(t, nil)
	in := e.do("POST", "/v1/token", secretB, "10.1.200.1:4000", api.TokenRequest{Repository: "acme/api-core"}, nil)
	if in.code != 200 {
		t.Fatalf("inside range: %d %s", in.code, in.body)
	}
	out := e.do("POST", "/v1/token", secretB, "192.168.1.5:4000", api.TokenRequest{Repository: "acme/api-core"}, nil)
	if out.code != 403 {
		t.Fatalf("outside range: %d", out.code)
	}
	// A spoofed X-Forwarded-For from an untrusted peer is ignored.
	spoof := e.do("POST", "/v1/token", secretB, "192.168.1.5:4000", api.TokenRequest{Repository: "acme/api-core"},
		map[string]string{"X-Forwarded-For": "10.1.0.9"})
	if spoof.code != 403 {
		t.Fatalf("spoofed XFF accepted: %d", spoof.code)
	}
}

func TestTrustedProxies(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")} })
	via := func(remote, xff string) int {
		return e.do("POST", "/v1/token", secretB, remote, api.TokenRequest{Repository: "acme/api-core"},
			map[string]string{"X-Forwarded-For": xff}).code
	}
	if c := via("127.0.0.1:1234", "10.1.5.5"); c != 200 {
		t.Fatalf("trusted proxy with allowed client: %d", c)
	}
	if c := via("127.0.0.1:1234", "192.168.1.1"); c != 403 {
		t.Fatalf("trusted proxy with disallowed client: %d", c)
	}
	// Client-supplied left-most entries can't override the proxy's view.
	if c := via("127.0.0.1:1234", "10.1.5.5, 192.168.1.1"); c != 403 {
		t.Fatalf("XFF left-most spoof accepted: %d", c)
	}
	if c := via("192.168.9.9:1234", "10.1.5.5"); c != 403 {
		t.Fatalf("untrusted peer XFF accepted: %d", c)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-For", "10.9.9.9, 127.0.0.1")
	if ip := e.b.clientIP(r); ip.String() != "10.9.9.9" {
		t.Fatalf("clientIP = %s", ip)
	}
}

func TestSecretRotation(t *testing.T) {
	e := newEnv(t, nil)
	for _, s := range []string{secretA, secretA2} {
		r := e.do("GET", "/v1/whoami", s, "", nil, nil)
		if r.code != 200 {
			t.Fatalf("%s: %d", s, r.code)
		}
		var who api.WhoAmI
		json.Unmarshal(r.body, &who)
		if who.Client != "alice" || len(who.Grants) != 2 {
			t.Fatalf("whoami = %+v", who)
		}
	}
}

func TestRateLimits(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.TokensPerMinute = 3; o.FailsPerMinute = 3 })
	for i := 0; i < 3; i++ {
		if r := e.token(secretA, "acme/api-core", nil); r.code != 200 {
			t.Fatalf("request %d: %d", i, r.code)
		}
	}
	if r := e.token(secretA, "acme/api-core", nil); r.code != 429 {
		t.Fatalf("token rate limit: %d", r.code)
	}
	bad := func() int { return e.do("GET", "/v1/whoami", "gaa_bad", "10.7.7.7:1", nil, nil).code }
	for i := 0; i < 3; i++ {
		if c := bad(); c != 401 {
			t.Fatalf("fail %d: %d", i, c)
		}
	}
	if c := bad(); c != 429 {
		t.Fatalf("auth failure limit: %d", c)
	}
	// Valid secret from the blocked IP is also refused; other IPs aren't affected.
	if c := e.do("GET", "/v1/whoami", secretA, "10.7.7.7:1", nil, nil).code; c != 429 {
		t.Fatalf("blocked IP with good secret: %d", c)
	}
	if c := e.do("GET", "/v1/whoami", secretA, "10.7.7.8:1", nil, nil).code; c != 200 {
		t.Fatalf("other IP: %d", c)
	}
}

func TestReloadRevokesAndKeepsOldOnError(t *testing.T) {
	e := newEnv(t, nil)
	r := e.token(secretA, "acme/api-core", nil)
	if r.code != 200 {
		t.Fatal(r.code)
	}
	// Invalid config (bad key) must not replace the running one.
	_, err := e.store.db.Exec(`UPDATE apps SET private_key='garbage' WHERE name='frontend-bot'`)
	must(t, err)
	if err := e.b.Reload(); err == nil {
		t.Fatal("reload accepted a bad key")
	}
	if c := e.token(secretB, "acme/api-core", nil).code; c != 200 {
		t.Fatalf("old config should still serve: %d", c)
	}
	must(t, e.store.PutApp(AppRow{Name: "frontend-bot", AppID: 234567, PrivateKey: k2PEM}))

	// Revoke alice: 401 right away, and her token is revoked at GitHub.
	must(t, e.store.DeleteClient("alice"))
	must(t, e.b.Reload())
	if c := e.token(secretA, "acme/api-core", nil).code; c != 401 {
		t.Fatalf("revoked client got %d", c)
	}
	waitFor(t, func() bool { return !e.gh.TokenValid(r.tok.Token) })
	toks, _ := e.store.ActiveTokens(e.b.now())
	for _, tk := range toks {
		if tk.Client == "alice" {
			t.Fatal("alice still has active tokens")
		}
	}
}

func TestDisabledClient(t *testing.T) {
	e := newEnv(t, nil)
	must(t, e.store.UpdateClient(ClientRow{Name: "alice", Disabled: true}))
	must(t, e.b.Reload())
	if c := e.token(secretA, "acme/api-core", nil).code; c != 401 {
		t.Fatalf("disabled client: %d", c)
	}
}

func TestInvalidate(t *testing.T) {
	e := newEnv(t, nil)
	r1 := e.token(secretA, "acme/api-core", nil)
	// bob can't invalidate alice's token
	e.do("POST", "/v1/invalidate", secretB, "", api.InvalidateRequest{Token: r1.tok.Token}, nil)
	if r := e.token(secretA, "acme/api-core", nil); r.tok.Token != r1.tok.Token {
		t.Fatal("bob invalidated alice's token")
	}
	if c := e.do("POST", "/v1/invalidate", secretA, "", api.InvalidateRequest{Token: r1.tok.Token}, nil).code; c != 204 {
		t.Fatalf("invalidate: %d", c)
	}
	r2 := e.token(secretA, "acme/api-core", nil)
	if r2.code != 200 || r2.tok.Token == r1.tok.Token || r2.tok.Cached {
		t.Fatal("expected a freshly minted token after invalidate")
	}
}

func TestIdentityFailureDoesNotFail(t *testing.T) {
	e := newEnv(t, nil)
	e.gh.FailIdentity = true
	r := e.token(secretA, "acme/api-core", nil)
	if r.code != 200 || r.tok.BotName != "backend-bot[bot]" || r.tok.BotEmail != "" {
		t.Fatalf("code %d name %q email %q", r.code, r.tok.BotName, r.tok.BotEmail)
	}
	// Within the retry window no new lookup is made.
	e.token(secretA, "acme/api-auth", nil)
	if n := e.gh.CallCount("GET /users/"); n != 1 {
		t.Fatalf("identity lookups = %d", n)
	}
}

func TestRevokeToken(t *testing.T) {
	e := newEnv(t, nil)
	r := e.token(secretA, "acme/api-core", nil)
	toks, _ := e.store.ActiveTokens(e.b.now())
	must(t, e.b.RevokeToken(toks[0].ID, "test"))
	if e.gh.TokenValid(r.tok.Token) {
		t.Fatal("token still valid at GitHub")
	}
	if r2 := e.token(secretA, "acme/api-core", nil); r2.tok.Token == r.tok.Token {
		t.Fatal("revoked token served from cache")
	}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t, nil)
	r := e.do("GET", "/healthz", "", "", nil, nil)
	if r.code != 200 || string(r.body) != "ok\n" {
		t.Fatalf("%d %q", r.code, r.body)
	}
}

func TestBuildStateValidation(t *testing.T) {
	keys(t)
	good := func() *ConfigRows {
		return &ConfigRows{
			Apps:    []AppRow{{Name: "a", AppID: 1, PrivateKey: key1PEM}},
			Clients: []ClientRow{{Name: "c"}, {Name: "d"}},
			Secrets: []SecretRow{{ID: 1, Client: "c", SHA256: sha256Hex("x")}},
			Grants:  []GrantRow{{Client: "c", App: "a", Repos: []string{"acme/*"}, Permissions: map[string]string{"contents": "read"}}},
		}
	}
	if _, err := buildState(good()); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*ConfigRows){
		"bad key":     func(c *ConfigRows) { c.Apps[0].PrivateKey = "nope" },
		"zero app id": func(c *ConfigRows) { c.Apps[0].AppID = 0 },
		"bad hash":    func(c *ConfigRows) { c.Secrets[0].SHA256 = "abc" },
		"dup hash": func(c *ConfigRows) {
			c.Secrets = append(c.Secrets, SecretRow{ID: 2, Client: "d", SHA256: sha256Hex("x")})
		},
		"bad pattern": func(c *ConfigRows) { c.Grants[0].Repos = []string{"acme/x/y"} },
		"no slash":    func(c *ConfigRows) { c.Grants[0].Repos = []string{"acme"} },
		"bad glob":    func(c *ConfigRows) { c.Grants[0].Repos = []string{"acme/[x"} },
		"bad level":   func(c *ConfigRows) { c.Grants[0].Permissions = map[string]string{"contents": "rw"} },
		"unknown app": func(c *ConfigRows) { c.Grants[0].App = "zzz" },
		"bad cidr":    func(c *ConfigRows) { c.Clients[0].AllowedCIDRs = []string{"10.0.0.0/99"} },
		"empty repos": func(c *ConfigRows) { c.Grants[0].Repos = nil },
		"ec key (not RSA)": func(c *ConfigRows) {
			_, kp, _ := generateSelfSigned([]string{"x"})
			c.Apps[0].PrivateKey = kp
		},
	}
	for name, mut := range bad {
		c := good()
		mut(c)
		if _, err := buildState(c); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestNarrow(t *testing.T) {
	g := map[string]string{"contents": "write", "metadata": "read"}
	if p, _ := narrow(g, nil); p["contents"] != "write" {
		t.Fatal("default should be the grant")
	}
	if p, _ := narrow(nil, nil); p != nil {
		t.Fatal("empty grant + empty request = nil")
	}
	if p, err := narrow(nil, map[string]string{"issues": "write"}); err != nil || p["issues"] != "write" {
		t.Fatal("empty grant allows any valid request")
	}
	if _, err := narrow(g, map[string]string{"metadata": "write"}); err == nil {
		t.Fatal("escalation allowed")
	}
}
