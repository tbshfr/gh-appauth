package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type uiClient struct {
	t    *testing.T
	srv  *httptest.Server
	c    *http.Client
	csrf string
}

// flashErr marks an error notice on a rendered page.
const flashErr = `class="flash err"`

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (u *uiClient) get(path string) (int, string) {
	u.t.Helper()
	resp, err := u.c.Get(u.srv.URL + path)
	if err != nil {
		u.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if m := csrfRE.FindStringSubmatch(string(b)); m != nil {
		u.csrf = m[1]
	}
	return resp.StatusCode, string(b)
}

func (u *uiClient) post(path string, form url.Values) (int, string, string) {
	u.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if _, ok := form["csrf"]; !ok {
		form.Set("csrf", u.csrf)
	}
	resp, err := u.c.PostForm(u.srv.URL+path, form)
	if err != nil {
		u.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if m := csrfRE.FindStringSubmatch(string(b)); m != nil {
		u.csrf = m[1]
	}
	return resp.StatusCode, resp.Request.URL.String(), string(b)
}

func newUIClient(t *testing.T, e *env) *uiClient {
	h, err := hashPassword("correct horse battery")
	must(t, err)
	must(t, e.store.SetSetting("admin_password", h))
	srv := httptest.NewServer(e.b.UIHandler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &uiClient{t: t, srv: srv, c: &http.Client{Jar: jar}}
}

func TestUILoginAndCSRF(t *testing.T) {
	e := newEnv(t, nil)
	u := newUIClient(t, e)

	if _, body := u.get("/ui/"); !strings.Contains(body, `name="password"`) {
		t.Fatal("unauthenticated dashboard should redirect to login")
	}
	if _, _, body := u.post("/ui/login", url.Values{"password": {"wrong"}}); !strings.Contains(body, flashErr) {
		t.Fatalf("wrong password not rejected: %s", body)
	}
	_, final, body := u.post("/ui/login", url.Values{"password": {"correct horse battery"}})
	if !strings.HasSuffix(final, "/ui/") || !strings.Contains(body, "Active tokens") {
		t.Fatalf("login failed: %s", final)
	}
	// POST without the CSRF token is refused.
	code, _, _ := u.post("/ui/clients", url.Values{"csrf": {"forged"}, "name": {"mallory"}})
	if code != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d", code)
	}
	// Logout invalidates the session.
	u.post("/ui/logout", nil)
	if _, body := u.get("/ui/clients"); !strings.Contains(body, `name="password"`) {
		t.Fatal("session survived logout")
	}
}

func TestUILoginLimit(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.FailsPerMinute = 3 })
	u := newUIClient(t, e)
	// Parallel guesses can't outrun the limit.
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.PostForm(u.srv.URL+"/ui/login", url.Values{"password": {"wrong"}})
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	rows, err := e.store.Requests(RequestFilter{Event: "denied", Limit: 100})
	must(t, err)
	if len(rows) != 3 {
		t.Fatalf("%d password checks ran, want 3", len(rows))
	}
	if _, _, body := u.post("/ui/login", url.Values{"password": {"correct horse battery"}}); !strings.Contains(body, flashErr) {
		t.Fatalf("login allowed while limited: %s", body)
	}
	// Failed logins don't block API clients on the same address.
	if c := e.do("GET", "/v1/whoami", secretA, "127.0.0.1:1", nil, nil).code; c != 200 {
		t.Fatalf("API after failed logins: %d", c)
	}
}

func TestUINoticesAndSecureCookie(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")} })
	u := newUIClient(t, e)
	// Text in the URL is not shown.
	if _, body := u.get("/ui/login?err=call+this+number&msg=call+this+number"); strings.Contains(body, "call this number") {
		t.Fatal("query string reflected on the page")
	}
	// A notice is shown once.
	if _, _, body := u.post("/ui/login", url.Values{"password": {"wrong"}}); !strings.Contains(body, "wrong password") {
		t.Fatal("notice not shown")
	}
	if _, body := u.get("/ui/login"); strings.Contains(body, "wrong password") {
		t.Fatal("notice shown twice")
	}
	// The session cookie is Secure when a trusted proxy terminated TLS.
	login := func(proto string) *http.Cookie {
		req, _ := http.NewRequest("POST", u.srv.URL+"/ui/login", strings.NewReader("password=correct+horse+battery"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if proto != "" {
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		resp, err := http.DefaultTransport.RoundTrip(req)
		must(t, err)
		resp.Body.Close()
		for _, c := range resp.Cookies() {
			if c.Name == sessionCookie {
				return c
			}
		}
		t.Fatal("no session cookie")
		return nil
	}
	if !login("https").Secure {
		t.Fatal("cookie not Secure behind a TLS-terminating proxy")
	}
	if login("").Secure {
		t.Fatal("cookie Secure over plain HTTP")
	}
}

func TestUIManageClient(t *testing.T) {
	e := newEnv(t, nil)
	u := newUIClient(t, e)
	u.get("/ui/login")
	u.post("/ui/login", url.Values{"password": {"correct horse battery"}})
	u.get("/ui/clients")

	_, final, body := u.post("/ui/clients", url.Values{"name": {"carol"}, "allowed_cidrs": {"10.1.0.0/16"}})
	if !strings.Contains(final, "/ui/clients/carol") {
		t.Fatalf("redirected to %s", final)
	}
	m := regexp.MustCompile(`<code id="secret">(gaa_[A-Za-z0-9_-]+)</code>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("new secret not shown")
	}
	secret := m[1]
	// The secret is shown only once.
	if _, again := u.get("/ui/clients/carol"); strings.Contains(again, secret) {
		t.Fatal("secret shown twice")
	}
	// No grant yet → 403; add one through the UI → 200.
	if c := e.token(secret, "acme/web", nil).code; c != 403 {
		t.Fatalf("before grant: %d", c)
	}
	_, _, body = u.post("/ui/clients/carol/grants", url.Values{
		"app": {"frontend-bot"}, "repos": {"acme/web\nacme/site"}, "perm_contents": {"read"}, "perm_other": {"metadata=read"},
	})
	if strings.Contains(body, flashErr) {
		t.Fatalf("add grant: %s", body)
	}
	r := e.token(secret, "acme/web", nil)
	if r.code != 200 || r.tok.Permissions["contents"] != "read" {
		t.Fatalf("after grant: %d %s", r.code, r.body)
	}
	// Bad grant input is rejected.
	_, _, body = u.post("/ui/clients/carol/grants", url.Values{"app": {"frontend-bot"}, "repos": {"acme/x/y"}})
	if !strings.Contains(body, flashErr) {
		t.Fatal("bad pattern accepted")
	}
	// Active token visible on the dashboard, but the token value isn't.
	_, dash := u.get("/ui/")
	if !strings.Contains(dash, "acme/web") || strings.Contains(dash, r.tok.Token) {
		t.Fatal("dashboard should list the token without its value")
	}
	// History page lists the request.
	if _, hist := u.get("/ui/history?client=carol"); !strings.Contains(hist, "acme/web") {
		t.Fatal("history missing request")
	}
	// Revoke through the UI.
	toks, _ := e.store.ActiveTokens(e.b.now())
	var id int64
	for _, tk := range toks {
		if tk.Client == "carol" {
			id = tk.ID
		}
	}
	u.get("/ui/")
	u.post("/ui/tokens/"+itoa(id)+"/revoke", url.Values{"back": {"/ui/"}})
	if e.gh.TokenValid(r.tok.Token) {
		t.Fatal("UI revoke didn't revoke at GitHub")
	}
	// Disable the client.
	u.get("/ui/clients/carol")
	u.post("/ui/clients/carol", url.Values{"allowed_cidrs": {"10.1.0.0/16"}, "disabled": {"on"}})
	if c := e.token(secret, "acme/web", nil).code; c != 401 {
		t.Fatalf("disabled via UI: %d", c)
	}
	// Delete it.
	u.post("/ui/clients/carol/delete", nil)
	if _, body := u.get("/ui/clients"); strings.Contains(body, ">carol<") {
		t.Fatal("client not deleted")
	}
}

func TestUIApps(t *testing.T) {
	e := newEnv(t, nil)
	u := newUIClient(t, e)
	u.get("/ui/login")
	u.post("/ui/login", url.Values{"password": {"correct horse battery"}})
	u.get("/ui/apps")
	_, _, body := u.post("/ui/apps", url.Values{"name": {"third"}, "app_id": {"999"}, "private_key": {"not a key"}})
	if !strings.Contains(body, flashErr) {
		t.Fatal("bad key accepted")
	}
	_, _, body = u.post("/ui/apps", url.Values{"name": {"third"}, "app_id": {"999"}, "private_key": {key1PEM}})
	if strings.Contains(body, flashErr) {
		t.Fatalf("save app: %s", body)
	}
	if e.b.st.Load().apps["third"] == nil {
		t.Fatal("app not loaded after save")
	}
	_, _, body = u.post("/ui/apps/backend-bot/test", nil)
	if !strings.Contains(body, "works") {
		t.Fatalf("test app: %s", body)
	}
	_, _, body = u.post("/ui/apps/backend-bot/delete", nil)
	if !strings.Contains(body, flashErr) {
		t.Fatal("deleted an app that grants use")
	}
	u.post("/ui/apps/third/delete", nil)
	if e.b.st.Load().apps["third"] != nil {
		t.Fatal("app not deleted")
	}
}

func TestUIPagesRender(t *testing.T) {
	e := newEnv(t, nil)
	e.token(secretA, "acme/api-core", nil)
	e.token("bad", "acme/api-core", nil)
	u := newUIClient(t, e)
	u.get("/ui/login")
	u.post("/ui/login", url.Values{"password": {"correct horse battery"}})
	for _, p := range []string{"/ui/", "/ui/clients", "/ui/clients/alice", "/ui/apps", "/ui/history", "/ui/history?event=denied", "/ui/settings", "/ui/static/style.css", "/ui/static/app.js"} {
		code, body := u.get(p)
		if code != 200 || strings.Contains(body, "template error") {
			t.Errorf("%s: %d %.200s", p, code, body)
		}
	}
	resp, _ := u.c.Get(u.srv.URL + "/ui/")
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP = %q", csp)
	}
	resp.Body.Close()
}

func TestUIVersion(t *testing.T) {
	for _, tc := range []struct{ version, want string }{
		{"v1.2.3", `<a href="https://github.com/tbshfr/gh-appauth/releases/tag/v1.2.3"`},
		{"v1.2.3-4-gabcdef0", `<a href="https://github.com/tbshfr/gh-appauth/releases" target="_blank" rel="noopener" title="gh-appauth releases on GitHub">v1.2.3-4-gabcdef0</a>`},
	} {
		e := newEnv(t, func(o *Options) { o.Info.Version = tc.version })
		u := newUIClient(t, e)
		u.get("/ui/login")
		u.post("/ui/login", url.Values{"password": {"correct horse battery"}})
		_, body := u.get("/ui/settings")
		if !strings.Contains(body, tc.want) {
			t.Errorf("%s: settings page lacks %s", tc.version, tc.want)
		}
	}
}

func TestUIPasswordChange(t *testing.T) {
	e := newEnv(t, nil)
	u := newUIClient(t, e)
	u.get("/ui/login")
	u.post("/ui/login", url.Values{"password": {"correct horse battery"}})
	u.get("/ui/settings")
	_, _, body := u.post("/ui/settings/password", url.Values{"current": {"correct horse battery"}, "new": {"short"}, "confirm": {"short"}})
	if !strings.Contains(body, flashErr) {
		t.Fatal("short password accepted")
	}
	_, final, _ := u.post("/ui/settings/password", url.Values{"current": {"correct horse battery"}, "new": {"a much longer one"}, "confirm": {"a much longer one"}})
	if !strings.Contains(final, "/ui/login") {
		t.Fatalf("password change: %s", final)
	}
	stored, _ := e.store.GetSetting("admin_password")
	if !checkPassword(stored, "a much longer one") || checkPassword(stored, "correct horse battery") {
		t.Fatal("password not changed")
	}
}

func TestUINotOnAPIWhenSeparate(t *testing.T) {
	e := newEnv(t, nil)
	h := e.b.APIHandler(false)
	r := httptest.NewRequest("GET", "/ui/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("UI reachable on API listener: %d", w.Code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
