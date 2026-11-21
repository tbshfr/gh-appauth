package main

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tbshfr/gh-appauth/internal/fakeoidc"
)

// testPasswordHash is hashed once: PBKDF2 is slow, more so with -race.
var testPasswordHash = sync.OnceValue(func() string {
	h, err := hashPassword("correct horse battery")
	if err != nil {
		panic(err)
	}
	return h
})

type ssoEnv struct {
	*env
	idp    *fakeoidc.Server
	srv    *httptest.Server
	offset atomic.Int64 // added to the broker's clock
}

// newSSOEnv runs the broker's UI on 127.0.0.1 against a fake provider on
// localhost. An empty secret makes a public client.
func newSSOEnv(t *testing.T, secret string, mod func(*serveConfig), opts func(*Options)) *ssoEnv {
	t.Helper()
	s := &ssoEnv{idp: fakeoidc.Start("broker", secret)}
	t.Cleanup(s.idp.Close)
	s.idp.Next(member("alice"))
	srv := httptest.NewUnstartedServer(nil)
	c := serveConfig{OIDCIssuer: s.idp.URL, OIDCClientID: "broker", OIDCAllowedGroups: "broker-admins,ops",
		OIDCRedirectURL: "http://" + srv.Listener.Addr().String() + oidcCallbackPath}
	if secret != "" {
		c.OIDCClientSecretFile = filepath.Join(t.TempDir(), "secret")
		must(t, os.WriteFile(c.OIDCClientSecretFile, []byte(secret+"\n"), 0o600))
	}
	if mod != nil {
		mod(&c)
	}
	cfg, err := oidcConfig(c)
	must(t, err)
	s.env = newEnv(t, func(o *Options) {
		o.OIDC = cfg
		o.Now = func() time.Time { return time.Now().Add(time.Duration(s.offset.Load())) }
		o.FailsPerMinute = 1000
		if opts != nil {
			opts(o)
		}
	})
	must(t, s.store.SetSetting("admin_password", testPasswordHash()))
	srv.Config.Handler = s.b.UIHandler()
	srv.Start()
	t.Cleanup(srv.Close)
	s.srv = srv
	return s
}

func member(name string, groups ...any) fakeoidc.Login {
	if groups == nil {
		groups = []any{"broker-admins"}
	}
	return fakeoidc.Login{Claims: map[string]any{"preferred_username": name, "groups": groups}}
}

type browser struct {
	*uiClient
	chain []string
}

func (s *ssoEnv) browser() *browser {
	jar, _ := cookiejar.New(nil)
	b := &browser{}
	b.uiClient = &uiClient{t: s.t, srv: s.srv, c: &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		b.chain = append(b.chain, r.URL.String())
		return nil
	}}}
	return b
}

// open follows redirects from rawURL and returns where it ended.
func (b *browser) open(rawURL string) (int, *url.URL, string) {
	b.t.Helper()
	b.chain = nil
	resp, err := b.c.Get(rawURL)
	must(b.t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Request.URL, string(body)
}

// sso signs in from the login page, which goes straight on to the provider.
func (b *browser) sso() (int, string) {
	b.t.Helper()
	code, _, body := b.open(b.srv.URL + "/ui/login")
	return code, body
}

// peek fetches path without following redirects.
func (b *browser) peek(path string) *http.Response {
	b.t.Helper()
	c := *b.c
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Get(b.srv.URL + path)
	must(b.t, err)
	resp.Body.Close()
	return resp
}

func (b *browser) signedIn() bool { return b.peek("/ui/").StatusCode == 200 }

// start begins a sign-in and stops before the provider, returning the
// authorization URL.
func (b *browser) start() *url.URL {
	b.t.Helper()
	resp := b.peek("/ui/oidc/login")
	loc, err := resp.Location()
	if resp.StatusCode != 302 || err != nil {
		b.t.Fatalf("oidc login: %d %v", resp.StatusCode, err)
	}
	return loc
}

func (s *ssoEnv) denials() int {
	rows, err := s.store.Requests(RequestFilter{Event: "denied", Limit: 1000})
	must(s.t, err)
	return len(rows)
}

func TestSSOLogin(t *testing.T) {
	s := newSSOEnv(t, "s3cret", nil, nil)
	b := s.browser()
	code, body := b.sso()
	if code != 200 || !strings.Contains(body, `<meta http-equiv="refresh" content="0;url=/ui/">`) || !strings.Contains(body, `href="/ui/">Continue</a>`) {
		t.Fatalf("callback should answer with the continue page: %d %s", code, body)
	}
	var paths []string
	for _, u := range b.chain {
		p, _ := url.Parse(u)
		paths = append(paths, p.Path)
	}
	if !slices.Equal(paths, []string{"/ui/oidc/login", "/authorize", oidcCallbackPath}) {
		t.Fatalf("redirects: %v", b.chain)
	}
	_, dash := b.get("/ui/")
	if !strings.Contains(dash, "Active tokens") || !strings.Contains(dash, "Signed in as <strong>alice</strong>") {
		t.Fatalf("dashboard after SSO: %.300s", dash)
	}
	rows, _ := s.store.Requests(RequestFilter{Event: "ui_login", Limit: 10})
	if len(rows) != 1 || rows[0].Client != "alice" || rows[0].Reason != "SSO" {
		t.Fatalf("ui_login rows: %+v", rows)
	}
	reqs := s.idp.TokenRequests()
	if len(reqs) != 1 || !reqs[0].BasicAuth || reqs[0].Form.Get("code_verifier") == "" {
		t.Fatalf("token requests: %+v", reqs)
	}
	if _, hist := b.get("/ui/history?event=ui_login"); !strings.Contains(hist, `<span class="user">alice</span>`) || strings.Contains(hist, "/ui/clients/alice\">alice") {
		t.Fatal("history should list the login without a client link")
	}
	if _, set := b.get("/ui/settings"); !strings.Contains(set, s.idp.URL) || !strings.Contains(set, "broker-admins, ops") || strings.Contains(set, "s3cret") {
		t.Fatal("settings should show the SSO configuration but not the secret")
	}
}

func TestSSOGroupClaims(t *testing.T) {
	s := newSSOEnv(t, "s3cret", nil, nil)
	for _, tc := range []struct {
		name  string
		login fakeoidc.Login
		code  int
	}{
		{"array", member("a", "other", "ops"), 200},
		{"string", fakeoidc.Login{Claims: map[string]any{"groups": "broker-admins"}}, 200},
		{"object", fakeoidc.Login{Claims: map[string]any{"groups": map[string]any{"broker-admins": map[string]any{"1": "org"}}}}, 200},
		{"userinfo only", fakeoidc.Login{UserInfo: map[string]any{"groups": []string{"ops"}}}, 200},
		{"not a member", member("a", "other"), 403},
		{"case differs", member("a", "Broker-Admins"), 403},
		{"number", member("a", 5), 403},
		{"null", fakeoidc.Login{Claims: map[string]any{"groups": nil}, UserInfo: map[string]any{"groups": []string{"ops"}}}, 403},
		{"non-string items", member("a", 1, true, []string{"ops"}), 403},
		{"empty but present", fakeoidc.Login{Claims: map[string]any{"groups": []string{}}, UserInfo: map[string]any{"groups": []string{"ops"}}}, 403},
		{"userinfo sub differs", fakeoidc.Login{UserInfo: map[string]any{"sub": "mallory", "groups": []string{"ops"}}}, 400},
	} {
		s.idp.Next(tc.login)
		before := s.denials()
		b := s.browser()
		code, body := b.sso()
		if code != tc.code || b.signedIn() != (tc.code == 200) {
			t.Errorf("%s: %d, signed in %v", tc.name, code, b.signedIn())
		}
		if tc.code == 403 && !strings.Contains(body, "Your account is not allowed to use this broker.") {
			t.Errorf("%s: no refusal message", tc.name)
		}
		if tc.code != 200 && s.denials() != before+1 {
			t.Errorf("%s: denial not audited", tc.name)
		}
	}

	z := newSSOEnv(t, "s3cret", func(c *serveConfig) { c.OIDCGroupsClaim = "urn:zitadel:iam:org:project:42:roles" }, nil)
	z.idp.Next(fakeoidc.Login{UserInfo: map[string]any{"urn:zitadel:iam:org:project:42:roles": map[string]any{"ops": map[string]any{"9": "acme"}}}})
	zb := z.browser()
	if zb.sso(); !zb.signedIn() {
		t.Error("custom claim from userinfo: not signed in")
	}
}

func TestSSOPublicClient(t *testing.T) {
	s := newSSOEnv(t, "", nil, nil)
	b := s.browser()
	b.sso()
	if !b.signedIn() {
		t.Fatalf("not signed in; provider errors: %v", s.idp.Errors())
	}
	reqs := s.idp.TokenRequests()
	if len(reqs) != 1 || reqs[0].BasicAuth || reqs[0].Form.Get("client_id") != "broker" || reqs[0].Form.Has("client_secret") {
		t.Fatalf("public client should send only client_id in the body: %+v", reqs)
	}
}

func TestSSOCallbackChecks(t *testing.T) {
	s := newSSOEnv(t, "s3cret", nil, nil)
	cb := s.srv.URL + oidcCallbackPath + "?"
	expect := func(name string, b *browser, rawURL string, code int, want string) {
		t.Helper()
		before := s.denials()
		got, _, body := b.open(rawURL)
		if got != code || !strings.Contains(body, want) || strings.Contains(body, "555-0100") || b.signedIn() {
			t.Errorf("%s: %d, want %d with %q: %s", name, got, code, want, body[strings.Index(body, "<main"):])
		}
		if s.denials() != before+1 {
			t.Errorf("%s: not audited", name)
		}
	}

	expect("no cookie", s.browser(), cb+"code=x&state=y", 400, "Sign-in expired or was already used")

	b := s.browser()
	state := b.start().Query().Get("state")
	expect("state mismatch", b, cb+"code=x&state=wrong", 400, "Sign-in failed")
	expect("cookie used up", b, cb+"code=x&state="+state, 400, "Sign-in expired or was already used")

	for _, q := range []string{"state=wrong&", ""} {
		b = s.browser()
		b.start()
		expect("error= without our state", b, cb+q+"error=access_denied&error_description=call+555-0100", 400, "Sign-in failed")
	}

	s.idp.Next(fakeoidc.Login{Error: "access_denied"})
	b = s.browser()
	if code, body := b.sso(); code != 400 || !strings.Contains(body, "Sign-in was cancelled or refused by the provider.") || strings.Contains(body, "555-0100") {
		t.Errorf("access_denied: %d %.400s", code, body)
	}
	s.idp.Next(fakeoidc.Login{Error: "temporarily_unavailable"})
	if code, body := b.sso(); code != 400 || !strings.Contains(body, "could not complete the sign-in") || strings.Contains(body, "555-0100") {
		t.Errorf("other error: %d %.400s", code, body)
	}

	s.idp.Next(member("alice"))
	b = s.browser()
	b.sso()
	callback := b.chain[len(b.chain)-1]
	b.get("/ui/")
	b.post("/ui/logout", nil)
	expect("replayed callback", b, callback, 400, "Sign-in expired or was already used")
	b.start()
	expect("replayed callback with a new sign-in", b, callback, 400, "Sign-in failed")
}

func TestSSOIDTokenChecks(t *testing.T) {
	s := newSSOEnv(t, "s3cret", nil, nil)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	b64 := base64.RawURLEncoding.EncodeToString
	edit := func(f func(map[string]any)) fakeoidc.Login {
		l := member("alice")
		l.Edit = f
		return l
	}
	for _, tc := range []struct {
		name  string
		login fakeoidc.Login
		clock time.Duration
		ok    bool
	}{
		{"wrong issuer", edit(func(c map[string]any) { c["iss"] = "https://idp.example" }), 0, false},
		{"wrong audience", edit(func(c map[string]any) { c["aud"] = "someone-else" }), 0, false},
		{"wrong nonce", edit(func(c map[string]any) { c["nonce"] = "guess" }), 0, false},
		{"several audiences without azp", edit(func(c map[string]any) { c["aud"] = []string{"broker", "api"} }), 0, false},
		{"azp of another client", edit(func(c map[string]any) { c["azp"] = "api" }), 0, false},
		{"several audiences with azp", edit(func(c map[string]any) { c["aud"], c["azp"] = []string{"broker", "api"}, "broker" }), 0, true},
		{"no id_token", fakeoidc.Login{Claims: member("a").Claims, NoIDToken: true}, 0, false},
		{"other key", fakeoidc.Login{Claims: member("a").Claims, Sign: func(c []byte) string { return fakeoidc.SignWith(other, c) }}, 0, false},
		{"alg none", fakeoidc.Login{Claims: member("a").Claims, Sign: func(c []byte) string {
			return b64([]byte(`{"alg":"none","kid":"k1"}`)) + "." + b64(c) + "."
		}}, 0, false},
		{"expired by the broker's clock", member("alice"), 10 * time.Minute, false}, // last: the clock must not go back
	} {
		s.idp.Next(tc.login)
		s.offset.Store(int64(tc.clock))
		b := s.browser()
		code, _ := b.sso()
		if b.signedIn() != tc.ok || (code == 200) != tc.ok {
			t.Errorf("%s: %d, signed in %v", tc.name, code, b.signedIn())
		}
	}
	if e := s.idp.Errors(); len(e) > 0 {
		t.Errorf("the provider refused, so the broker's checks weren't what failed: %v", e)
	}
}

func TestSSOSendsPKCEVerifier(t *testing.T) {
	s := newSSOEnv(t, "s3cret", nil, nil)
	b := s.browser()
	auth := b.start()
	base, _ := url.Parse(s.srv.URL + "/ui/oidc/")
	var flow oidcFlow
	for _, c := range b.c.Jar.Cookies(base) {
		if c.Name == oidcCookie {
			flow, _ = decodeOIDCFlow(c.Value)
		}
	}
	flow.verifier = "x" + flow.verifier[1:]
	b.c.Jar.SetCookies(base, []*http.Cookie{{Name: oidcCookie, Value: flow.encode(), Path: "/ui/oidc/"}})
	b.open(auth.String())
	if b.signedIn() || !slices.ContainsFunc(s.idp.Errors(), func(e string) bool { return strings.Contains(e, "PKCE") }) {
		t.Fatalf("wrong verifier accepted; provider errors: %v", s.idp.Errors())
	}
}

func TestSSOProviderDown(t *testing.T) {
	s := newSSOEnv(t, "s3cret", nil, nil)
	s.idp.SetDown(true)
	b := s.browser()
	code, final, body := b.open(s.srv.URL + "/ui/login")
	if code != 200 || final.Path != "/ui/login" || !strings.Contains(body, "can't be reached") || !strings.Contains(body, `name="password"`) {
		t.Fatalf("login page while the provider is down: %d %s %.400s", code, final, body)
	}
	if c := s.do("GET", "/v1/whoami", secretA, "", nil, nil).code; c != 200 {
		t.Fatalf("API while the provider is down: %d", c)
	}
	b.post("/ui/login", url.Values{"password": {"correct horse battery"}})
	if !b.signedIn() {
		t.Fatal("password login while the provider is down")
	}
	b.post("/ui/logout", nil)

	s.idp.SetDown(false)
	if _, final, _ := b.open(s.srv.URL + "/ui/login"); final.Path != "/ui/login" {
		t.Fatal("discovery retried sooner than oidcRetry")
	}
	s.offset.Store(int64(oidcRetry + time.Second))
	if b.sso(); !b.signedIn() {
		t.Fatal("SSO did not recover once the provider was back")
	}
}

func TestSSOIssuerMismatch(t *testing.T) {
	s := newSSOEnv(t, "s3cret", nil, nil)
	s.idp.SetIssuer(s.idp.URL + "/")
	b := s.browser()
	if _, final, body := b.open(s.srv.URL + "/ui/login"); final.Path != "/ui/login" || !strings.Contains(body, "can't be reached") {
		t.Fatalf("issuer mismatch: %s", final)
	}
	b.get("/ui/login?password")
	b.post("/ui/login", url.Values{"password": {"correct horse battery"}})
	if _, set := b.get("/ui/settings"); !strings.Contains(set, "unreachable") || !strings.Contains(set, "did not match the issuer URL") {
		t.Fatalf("settings should show the discovery error: %.2000s", set)
	}
}

func TestSSORoutes(t *testing.T) {
	s := newSSOEnv(t, "s3cret", nil, nil)
	for _, tc := range []struct {
		h    http.Handler
		code int
	}{{s.b.APIHandler(true), 302}, {s.b.UIHandler(), 302}, {s.b.APIHandler(false), 404}, {newEnv(t, nil).b.UIHandler(), 404}} {
		w := httptest.NewRecorder()
		tc.h.ServeHTTP(w, httptest.NewRequest("GET", "/ui/oidc/login", nil))
		if w.Code != tc.code {
			t.Errorf("got %d, want %d", w.Code, tc.code)
		}
	}
}

func TestSSOCookies(t *testing.T) {
	s := newSSOEnv(t, "s3cret", nil, func(o *Options) { o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")} })
	roundTrip := func(rawURL, cookie, proto string) *http.Response {
		req, _ := http.NewRequest("GET", rawURL, nil)
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		if proto != "" {
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		resp, err := http.DefaultTransport.RoundTrip(req)
		must(t, err)
		resp.Body.Close()
		return resp
	}
	setCookie := func(resp *http.Response, name string) string {
		for _, v := range resp.Header.Values("Set-Cookie") {
			if strings.HasPrefix(v, name+"=") {
				return v
			}
		}
		t.Fatalf("no %s cookie", name)
		return ""
	}
	if c := setCookie(roundTrip(s.srv.URL+"/ui/oidc/login", "", "https"), oidcCookie); !strings.Contains(c, "; Secure") {
		t.Errorf("behind a TLS proxy: %s", c)
	}
	resp := roundTrip(s.srv.URL+"/ui/oidc/login", "", "")
	c := setCookie(resp, oidcCookie)
	for _, want := range []string{"Path=/ui/oidc/", "Max-Age=600", "HttpOnly", "SameSite=Lax"} {
		if !strings.Contains(c, want) || strings.Contains(c, "Secure") {
			t.Errorf("%s cookie lacks %s or is Secure over HTTP: %s", oidcCookie, want, c)
		}
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	idpResp, err := noFollow.Get(resp.Header.Get("Location"))
	must(t, err)
	idpResp.Body.Close()
	resp = roundTrip(idpResp.Header.Get("Location"), strings.SplitN(c, ";", 2)[0], "")
	if resp.StatusCode != 200 {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	if sc := setCookie(resp, sessionCookie); !strings.Contains(sc, "SameSite=Strict") || !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "Path=/;") {
		t.Errorf("session cookie: %s", sc)
	}
	if oc := setCookie(resp, oidcCookie); !strings.Contains(oc, "Max-Age=0") {
		t.Errorf("%s not cleared: %s", oidcCookie, oc)
	}
}

func TestSSOUserLabel(t *testing.T) {
	s := newSSOEnv(t, "s3cret", nil, nil)
	name := "<script>alert(1)</script>" + strings.Repeat("é", 200)
	s.idp.Next(member(name))
	b := s.browser()
	b.sso()
	_, dash := b.get("/ui/")
	if strings.Contains(dash, "<script>alert") || !strings.Contains(dash, "Signed in as <strong>&lt;script&gt;alert(1)&lt;/script&gt;ééé") {
		t.Fatal("user label not escaped in the header")
	}
	rows, _ := s.store.Requests(RequestFilter{Event: "ui_login", Limit: 1})
	if len(rows) != 1 || !strings.HasPrefix(rows[0].Client, "<script>") || utf8.RuneCountInString(rows[0].Client) != userLabelMax+1 {
		t.Fatalf("audit row: %+v", rows)
	}
	if !strings.Contains(s.logBuf.String(), `"client":"\u003cscript\u003e`) {
		t.Fatalf("audit line not JSON-escaped: %s", s.logBuf.String())
	}
	for _, tc := range []struct {
		claims map[string]any
		want   string
	}{
		{map[string]any{"email": "a@example.com", "name": "A"}, "a@example.com"},
		{map[string]any{"name": "A", "preferred_username": " "}, "A"},
		{map[string]any{}, "user-1"},
		{map[string]any{"name": "eve\ngh-appauth-broker: \u202eforged"}, "evegh-appauth-broker: forged"},
	} {
		claims := map[string]any{"groups": []string{"ops"}}
		maps.Copy(claims, tc.claims)
		s.idp.Next(fakeoidc.Login{Claims: claims})
		b := s.browser()
		b.sso()
		if _, dash := b.get("/ui/"); !strings.Contains(dash, "Signed in as <strong>"+tc.want+"</strong>") {
			t.Errorf("label for %v: want %s", tc.claims, tc.want)
		}
	}
}

func TestSSOLoginPage(t *testing.T) {
	s := newSSOEnv(t, "s3cret", func(c *serveConfig) { c.OIDCName = "Pocket ID" }, nil)
	b := s.browser()
	if code, final, body := b.open(s.srv.URL + "/ui/login?password"); code != 200 || final.Path != "/ui/login" ||
		!strings.Contains(body, `name="password"`) || !strings.Contains(body, "Sign in with Pocket ID") {
		t.Fatalf("?password: %d %s %.400s", code, final, body)
	}
	b.post("/ui/login", url.Values{"password": {"correct horse battery"}})
	if _, dash := b.get("/ui/"); !strings.Contains(dash, "Signed in as <strong>admin</strong>") {
		t.Fatal("password login alongside SSO")
	}
	rows, _ := s.store.Requests(RequestFilter{Event: "ui_login", Limit: 1})
	if len(rows) != 1 || rows[0].Client != "admin" || rows[0].Reason != "password" {
		t.Fatalf("password ui_login row: %+v", rows)
	}
	// Signing out shows the page instead of going straight back in.
	_, final, body := b.post("/ui/logout", nil)
	if !strings.HasSuffix(final, "/ui/login") || !strings.Contains(body, "Signed out.") || !strings.Contains(body, `href="/ui/login?password"`) || strings.Contains(body, `name="password"`) {
		t.Fatalf("after logout: %s %.600s", final, body)
	}

	if err := cmdSetPassword([]string{"-db", s.store.path, "-clear"}); err != nil {
		t.Fatal(err)
	}
	if pw, _ := s.store.GetSetting("admin_password"); pw != "" {
		t.Fatal("set-password -clear left the password")
	}
	_, _, body = b.post("/ui/login", url.Values{"password": {"correct horse battery"}})
	if b.signedIn() || !strings.Contains(body, "wrong password") {
		t.Fatal("password login after -clear")
	}
	_, _, body = b.open(s.srv.URL + "/ui/login?password")
	if strings.Contains(body, `name="password"`) || !strings.Contains(body, "set-password") || strings.Contains(body, "Sign in with password") {
		t.Fatalf("?password without a password: %.600s", body)
	}

	// With SSO only, the settings page sets a password without asking for one.
	b.sso()
	if _, set := b.get("/ui/settings"); strings.Contains(set, `name="current"`) || !strings.Contains(set, "Set an admin password") {
		t.Fatal("settings should offer to set a password")
	}
	_, final, _ = b.post("/ui/settings/password", url.Values{"new": {"a much longer one"}, "confirm": {"a much longer one"}})
	if stored, _ := s.store.GetSetting("admin_password"); !checkPassword(stored, "a much longer one") || !strings.HasSuffix(final, "/ui/login") {
		t.Fatalf("setting a password from SSO: %s", final)
	}
	rows, _ = s.store.Requests(RequestFilter{Event: "ui_password", Limit: 1})
	if len(rows) != 1 || rows[0].Client != "alice" || rows[0].Reason != "admin password set" {
		t.Fatalf("ui_password row: %+v", rows)
	}
	if rows, _ := s.store.Requests(RequestFilter{Client: "alice", Limit: 10}); len(rows) != 0 {
		t.Fatalf("UI events listed under a client of the same name: %+v", rows)
	}
}

func TestSSOProviderDownWithoutPassword(t *testing.T) {
	s := newSSOEnv(t, "s3cret", nil, nil)
	must(t, s.store.DeleteSetting("admin_password"))
	s.idp.SetDown(true)
	if _, _, body := s.browser().open(s.srv.URL + "/ui/login"); !strings.Contains(body, "can't be reached") || !strings.Contains(body, "set-password") {
		t.Fatalf("no way back shown: %.600s", body)
	}
}

func TestSSODiscoveryDoesNotQueue(t *testing.T) {
	sv := newSSO(OIDCConfig{Issuer: "http://127.0.0.1:1"}, time.Now)
	sv.mu.Lock()
	defer sv.mu.Unlock()
	if _, err := sv.get(); err != errSSOUnreachable {
		t.Fatalf("got %v while another attempt is running", err)
	}
}

func TestUISignOutAll(t *testing.T) {
	e := newEnv(t, nil)
	a := newUIClient(t, e)
	jar, _ := cookiejar.New(nil)
	b := &uiClient{t: t, srv: a.srv, c: &http.Client{Jar: jar}}
	for _, u := range []*uiClient{a, b} {
		u.post("/ui/login", url.Values{"password": {"correct horse battery"}})
	}
	a.get("/ui/settings")
	if _, final, body := a.post("/ui/settings/sessions/delete", nil); !strings.HasSuffix(final, "/ui/login") || !strings.Contains(body, "All sessions signed out.") {
		t.Fatalf("sign out all: %s", final)
	}
	for _, u := range []*uiClient{a, b} {
		if _, body := u.get("/ui/"); !strings.Contains(body, `name="password"`) {
			t.Error("session survived sign out all")
		}
	}
}

func TestSessionsUserMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	must(t, err)
	_, err = db.Exec(`CREATE TABLE sessions (id_sha256 TEXT PRIMARY KEY, csrf TEXT NOT NULL, ip TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
		INSERT INTO sessions VALUES ('old', 'c', '127.0.0.1', 0, 9999999999)`)
	must(t, err)
	db.Close()
	must(t, os.Chmod(path, 0o600))
	for range 2 {
		st, err := OpenStore(path)
		must(t, err)
		if csrf, user, ok := st.Session("old", time.Now()); !ok || csrf != "c" || user != "" {
			t.Fatalf("old session: %q %q %v", csrf, user, ok)
		}
		st.Close()
	}
	st, err := OpenStore(path)
	must(t, err)
	defer st.Close()
	must(t, st.CreateSession("new", "c2", "::1", "bob", time.Now(), time.Now().Add(time.Hour)))
	if _, user, ok := st.Session("new", time.Now()); !ok || user != "bob" {
		t.Fatalf("new session user %q", user)
	}
}

func TestOIDCConfig(t *testing.T) {
	dir := t.TempDir()
	secret, empty, open := filepath.Join(dir, "s"), filepath.Join(dir, "e"), filepath.Join(dir, "o")
	must(t, os.WriteFile(secret, []byte("hunter2\r\n"), 0o600))
	must(t, os.WriteFile(empty, []byte("\n"), 0o600))
	must(t, os.WriteFile(open, []byte("x"), 0o644))
	ok := serveConfig{OIDCIssuer: "https://idp.example/", OIDCClientID: "broker", OIDCAllowedGroups: "admins",
		OIDCRedirectURL: "https://broker.example/ui/oidc/callback"}
	for _, tc := range []struct {
		name string
		mod  func(*serveConfig)
		err  string
	}{
		{"valid", func(*serveConfig) {}, ""},
		{"loopback http", func(c *serveConfig) {
			c.OIDCIssuer, c.OIDCRedirectURL = "http://127.0.0.1:9000", "http://localhost:8444/ui/oidc/callback"
		}, ""},
		{"group-readable secret", func(c *serveConfig) { c.OIDCClientSecretFile = open }, ""},
		{"not configured", func(c *serveConfig) { *c = serveConfig{} }, ""},
		{"flags without issuer", func(c *serveConfig) { *c = serveConfig{OIDCClientID: "x", OIDCName: "y"} }, "-oidc-client-id, -oidc-name set without -oidc-issuer"},
		{"UI off", func(c *serveConfig) { c.UIListen = "off" }, "-ui-listen off"},
		{"no client ID", func(c *serveConfig) { c.OIDCClientID = "" }, "-oidc-client-id is required"},
		{"no redirect URL", func(c *serveConfig) { c.OIDCRedirectURL = "" }, "-oidc-redirect-url is required"},
		{"no groups", func(c *serveConfig) { c.OIDCAllowedGroups = " , " }, "-oidc-allowed-groups is required"},
		{"http issuer", func(c *serveConfig) { c.OIDCIssuer = "http://idp.example" }, "-oidc-issuer: \"http://idp.example\" must use https://"},
		{"relative issuer", func(c *serveConfig) { c.OIDCIssuer = "idp.example" }, "not an absolute"},
		{"http redirect", func(c *serveConfig) { c.OIDCRedirectURL = "http://broker.example/ui/oidc/callback" }, "must use https://"},
		{"redirect path", func(c *serveConfig) { c.OIDCRedirectURL = "https://broker.example/callback" }, "must end in /ui/oidc/callback"},
		{"missing secret file", func(c *serveConfig) { c.OIDCClientSecretFile = filepath.Join(dir, "nope") }, "no such file"},
		{"empty secret file", func(c *serveConfig) { c.OIDCClientSecretFile = empty }, "is empty"},
	} {
		c := ok
		tc.mod(&c)
		_, err := oidcConfig(c)
		if (err == nil) != (tc.err == "") || (err != nil && !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.err)
		}
	}
	c := ok
	c.OIDCClientSecretFile, c.OIDCScopes, c.OIDCAllowedGroups = secret, "email,openid email,groups", "a, b"
	cfg, err := oidcConfig(c)
	must(t, err)
	if cfg.ClientSecret != "hunter2" || !slices.Equal(cfg.Scopes, []string{"openid", "email", "groups"}) ||
		!slices.Equal(cfg.AllowedGroups, []string{"a", "b"}) || cfg.GroupsClaim != "groups" || cfg.Name != "SSO" {
		t.Fatalf("%+v", cfg)
	}

	db := filepath.Join(dir, "b.db")
	if err := cmdServe([]string{"-db", db, "-oidc-allowed-groups", "admins"}); err == nil || !strings.Contains(err.Error(), "without -oidc-issuer") {
		t.Fatalf("serve: %v", err)
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Error("database created before the OIDC flags were checked")
	}
}
