package main

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed ui/templates/*.html ui/static/*
var uiFS embed.FS

var idSeq atomic.Uint64

const (
	sessionCookie = "gaa_session"
	noticeCookie  = "gaa_notice"
	sessionTTL    = 12 * time.Hour
	pbkdf2Iter    = 600_000
)

// commonPerms are offered as dropdowns in the grant editor; anything else
// can be typed into the "other" field.
var commonPerms = []string{
	"metadata", "contents", "pull_requests", "issues", "workflows", "actions",
	"checks", "statuses", "deployments", "discussions", "packages", "pages",
}

type ui struct {
	b     *Broker
	pages map[string]*template.Template

	mu    sync.Mutex
	flash map[string]flash // keyed by session id hash
}

type flash struct {
	client string
	secret string
}

type session struct {
	idSHA string
	csrf  string
}

type page struct {
	Title    string
	Nav      string
	CSRF     string
	Msg      string
	Err      string
	Info     ServerInfo
	LoggedIn bool
	Data     any
}

func newUI(b *Broker) *ui {
	funcs := template.FuncMap{
		"ago":    ago,
		"until":  until,
		"ts":     func(t time.Time) string { return fmtTime(t) },
		"perms":  permString,
		"spaced": func(s string) string { return strings.ReplaceAll(s, ",", ", ") },
		"join":   strings.Join,
		"lines":  func(s []string) string { return strings.Join(s, "\n") },
		"permIs": func(m map[string]string, k, v string) bool { return m[k] == v },
		"extraPerms": func(m map[string]string) string {
			extra := map[string]string{}
			for k, v := range m {
				if !isCommonPerm(k) {
					extra[k] = v
				}
			}
			return strings.ReplaceAll(permString(extra), ",", ", ")
		},
		"permList":    permList,
		"permSummary": permSummary,
		"uid":         func() string { return "u" + strconv.FormatUint(idSeq.Add(1), 36) },
		"common":      func() []string { return commonPerms },
		"noperms":     func() map[string]string { return map[string]string{} },
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[kv[i].(string)] = kv[i+1]
			}
			return m
		},
		"short": func(s string) string { return s[:min(12, len(s))] },
		"hint": func(tok string) string {
			if len(tok) < 8 {
				return "…"
			}
			return tok[:4] + "…" + tok[len(tok)-4:]
		},
	}
	u := &ui{b: b, pages: map[string]*template.Template{}, flash: map[string]flash{}}
	names, _ := fs.Glob(uiFS, "ui/templates/*.html")
	for _, n := range names {
		base := strings.TrimSuffix(n[strings.LastIndexByte(n, '/')+1:], ".html")
		if base == "layout" {
			continue
		}
		u.pages[base] = template.Must(template.New("layout.html").Funcs(funcs).ParseFS(uiFS, "ui/templates/layout.html", n))
	}
	return u
}

type permEntry struct{ Name, Level string }

func permList(s string) []permEntry {
	var out []permEntry
	for kv := range strings.SplitSeq(s, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out = append(out, permEntry{k, v})
		}
	}
	return out
}

// permSummary counts permissions per level, highest first: "4 write · 2 read".
func permSummary(ps []permEntry) string {
	n := map[string]int{}
	for _, p := range ps {
		n[p.Level]++
	}
	var parts []string
	known := 0
	for _, lvl := range []string{"admin", "write", "read"} {
		if n[lvl] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[lvl], lvl))
			known += n[lvl]
		}
	}
	// Denied requests are logged as sent, so a level can be anything.
	if other := len(ps) - known; other > 0 {
		parts = append(parts, fmt.Sprintf("%d invalid", other))
	}
	return strings.Join(parts, " · ")
}

func isCommonPerm(k string) bool {
	for _, c := range commonPerms {
		if c == k {
			return true
		}
	}
	return false
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func human(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return human(time.Since(t)) + " ago"
}

func until(t time.Time) string {
	d := time.Until(t)
	if d < 0 {
		return "expired"
	}
	return "in " + human(d)
}

// ---- password ----

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}

func checkPassword(stored, pw string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- plumbing ----

func (u *ui) mount(mux *http.ServeMux) {
	static, _ := fs.Sub(uiFS, "ui/static")
	mux.Handle("GET /ui/static/", u.headers(http.StripPrefix("/ui/static/", http.FileServer(http.FS(static)))))
	// A service worker's scope can't be wider than its own directory, so it
	// is served from /ui/ rather than /ui/static/.
	mux.Handle("GET /ui/sw.js", u.headers(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, static, "sw.js")
	})))
	mux.Handle("GET /{$}", http.RedirectHandler("/ui/", http.StatusFound))
	mux.Handle("GET /ui", http.RedirectHandler("/ui/", http.StatusFound))
	mux.Handle("GET /ui/login", u.headers(http.HandlerFunc(u.loginPage)))
	mux.Handle("POST /ui/login", u.headers(http.HandlerFunc(u.login)))
	mux.Handle("POST /ui/logout", u.authed(u.logout))

	mux.Handle("GET /ui/{$}", u.authed(u.dashboard))
	mux.Handle("POST /ui/tokens/{id}/revoke", u.authed(u.revokeToken))
	mux.Handle("GET /ui/history", u.authed(u.history))

	mux.Handle("GET /ui/apps", u.authed(u.apps))
	mux.Handle("POST /ui/apps", u.authed(u.saveApp))
	mux.Handle("POST /ui/apps/{name}/delete", u.authed(u.deleteApp))
	mux.Handle("POST /ui/apps/{name}/test", u.authed(u.testApp))

	mux.Handle("GET /ui/clients", u.authed(u.clients))
	mux.Handle("POST /ui/clients", u.authed(u.createClient))
	mux.Handle("GET /ui/clients/{name}", u.authed(u.client))
	mux.Handle("POST /ui/clients/{name}", u.authed(u.updateClient))
	mux.Handle("POST /ui/clients/{name}/delete", u.authed(u.deleteClient))
	mux.Handle("POST /ui/clients/{name}/secrets", u.authed(u.newSecret))
	mux.Handle("POST /ui/clients/{name}/secrets/{id}/delete", u.authed(u.deleteSecret))
	mux.Handle("POST /ui/clients/{name}/grants", u.authed(u.saveGrant))
	mux.Handle("POST /ui/clients/{name}/grants/{id}", u.authed(u.saveGrant))
	mux.Handle("POST /ui/clients/{name}/grants/{id}/delete", u.authed(u.deleteGrant))
	mux.Handle("POST /ui/clients/{name}/grants/{id}/move", u.authed(u.moveGrant))

	mux.Handle("GET /ui/settings", u.authed(u.settings))
	mux.Handle("POST /ui/settings/password", u.authed(u.changePassword))
	mux.Handle("POST /ui/settings/reload", u.authed(u.reload))
}

func (u *ui) headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func (u *ui) session(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	idSHA := sha256Hex(c.Value)
	csrf, ok := u.b.store.Session(idSHA, u.b.now())
	if !ok {
		return nil
	}
	return &session{idSHA: idSHA, csrf: csrf}
}

type authedFunc func(w http.ResponseWriter, r *http.Request, s *session)

// authed requires a valid session and, for POSTs, a matching CSRF token.
func (u *ui) authed(h authedFunc) http.Handler {
	return u.headers(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := u.session(r)
		if s == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/ui/login", http.StatusFound)
				return
			}
			http.Error(w, "not logged in", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseMultipartForm(1 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(s.csrf)) != 1 {
				http.Error(w, "invalid CSRF token; reload the page", http.StatusForbidden)
				return
			}
		}
		h(w, r, s)
	}))
}

func (u *ui) render(w http.ResponseWriter, r *http.Request, s *session, name, nav, title string, data any) {
	p := page{Title: title, Nav: nav, Info: u.b.info(), Data: data}
	p.Msg, p.Err = takeNotice(w, r)
	if s != nil {
		p.CSRF, p.LoggedIn = s.csrf, true
	}
	var buf bytes.Buffer
	if err := u.pages[name].Execute(&buf, p); err != nil {
		http.Error(w, "template error: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// back redirects to a page that shows msg, or err if there is one. The text
// travels in a short-lived cookie and not in the URL, so a crafted link
// can't put words on the broker's pages.
func back(w http.ResponseWriter, r *http.Request, to, msg string, err error) {
	kind, text := "ok", msg
	if err != nil {
		kind, text = "err", err.Error()
	}
	if text != "" {
		if len(text) > 1000 { // stay well below the 4 KB cookie limit
			text = strings.ToValidUTF8(text[:1000], "") + "…"
		}
		http.SetCookie(w, &http.Cookie{
			Name: noticeCookie, Value: kind + "." + base64.RawURLEncoding.EncodeToString([]byte(text)),
			Path: "/ui/", MaxAge: 60, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// takeNotice returns the message left by back and clears it.
func takeNotice(w http.ResponseWriter, r *http.Request) (msg, errMsg string) {
	c, err := r.Cookie(noticeCookie)
	if err != nil {
		return "", ""
	}
	http.SetCookie(w, &http.Cookie{Name: noticeCookie, Path: "/ui/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	kind, enc, _ := strings.Cut(c.Value, ".")
	text, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", ""
	}
	if kind == "err" {
		return "", string(text)
	}
	return string(text), ""
}

func (b *Broker) info() ServerInfo { return b.opts.Info }

// ---- login ----

func (u *ui) loginPage(w http.ResponseWriter, r *http.Request) {
	if u.session(r) != nil {
		http.Redirect(w, r, "/ui/", http.StatusFound)
		return
	}
	pw, _ := u.b.store.GetSetting("admin_password")
	u.render(w, r, nil, "login", "", "Sign in", map[string]bool{"NoPassword": pw == ""})
}

func (u *ui) login(w http.ResponseWriter, r *http.Request) {
	now := u.b.now()
	addr := u.b.clientIP(r)
	ip, limKey := addr.String(), limitKey(addr)
	if !u.b.loginLim.allow(limKey, now) {
		back(w, r, "/ui/login", "", errors.New("too many failed attempts; wait a minute"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	stored, _ := u.b.store.GetSetting("admin_password")
	if stored == "" || !checkPassword(stored, r.PostFormValue("password")) {
		u.b.audit(&RequestRow{TS: now, Event: "denied", Status: 401, IP: ip, Reason: "admin UI login failed"})
		back(w, r, "/ui/login", "", errors.New("wrong password"))
		return
	}
	u.b.loginLim.refund(limKey, now)
	id := randToken(32)
	if err := u.b.store.CreateSession(sha256Hex(id), randToken(32), ip, now, now.Add(sessionTTL)); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: u.b.viaHTTPS(r), MaxAge: int(sessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
}

func (u *ui) logout(w http.ResponseWriter, r *http.Request, s *session) {
	u.b.store.DeleteSession(s.idSHA)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
}

// ---- dashboard / tokens / history ----

func (u *ui) dashboard(w http.ResponseWriter, r *http.Request, s *session) {
	now := u.b.now()
	toks, err := u.b.store.ActiveTokens(now)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	counts, _ := u.b.store.EventCounts(now.Add(-24 * time.Hour))
	recent, _ := u.b.store.Requests(RequestFilter{Limit: 25})
	st := u.b.st.Load()
	u.render(w, r, s, "dashboard", "dash", "Dashboard", map[string]any{
		"Tokens": toks, "Counts": counts, "Recent": recent, "Clients": len(st.clients), "Apps": len(st.apps),
	})
}

func (u *ui) revokeToken(w http.ResponseWriter, r *http.Request, s *session) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	to := r.PostFormValue("back")
	if !strings.HasPrefix(to, "/ui/") {
		to = "/ui/"
	}
	err := u.b.RevokeToken(id, "revoked in admin UI")
	back(w, r, to, "Token revoked.", err)
}

func (u *ui) history(w http.ResponseWriter, r *http.Request, s *session) {
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	f := RequestFilter{Client: q.Get("client"), Repo: q.Get("repo"), Event: q.Get("event"), Before: before, Limit: 100}
	rows, err := u.b.store.Requests(f)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var next string
	if len(rows) == f.Limit {
		nq := url.Values{"client": {f.Client}, "repo": {f.Repo}, "event": {f.Event}, "before": {strconv.FormatInt(rows[len(rows)-1].ID, 10)}}
		next = "/ui/history?" + nq.Encode()
	}
	var clients []string
	for n := range u.b.st.Load().clients {
		clients = append(clients, n)
	}
	sort.Strings(clients)
	u.render(w, r, s, "history", "history", "Request history", map[string]any{
		"Rows": rows, "Filter": f, "Next": next, "Clients": clients,
		"Events": []string{"issued", "listed", "denied", "error", "revoked", "invalidated"},
	})
}

// ---- apps ----

type appView struct {
	AppRow
	Grants int
}

func (u *ui) apps(w http.ResponseWriter, r *http.Request, s *session) {
	cfg, err := u.b.store.LoadConfig()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var views []appView
	for _, a := range cfg.Apps {
		v := appView{AppRow: a}
		for _, g := range cfg.Grants {
			if g.App == a.Name {
				v.Grants++
			}
		}
		views = append(views, v)
	}
	u.render(w, r, s, "apps", "apps", "GitHub Apps", map[string]any{"Apps": views})
}

func (u *ui) saveApp(w http.ResponseWriter, r *http.Request, s *session) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	appID, _ := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("app_id")), 10, 64)
	key := strings.TrimSpace(r.PostFormValue("private_key"))
	if f, _, err := r.FormFile("private_key_file"); err == nil {
		b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
		f.Close()
		if len(b) > 0 {
			key = string(b)
		}
	}
	err := func() error {
		if err := validateName("app", name); err != nil {
			return err
		}
		if appID <= 0 {
			return errors.New("App ID must be a positive number")
		}
		if key == "" {
			return errors.New("a private key is required")
		}
		if _, err := parsePrivateKey(key); err != nil {
			return fmt.Errorf("private key: %v", err)
		}
		if err := u.b.store.PutApp(AppRow{Name: name, AppID: appID, PrivateKey: key}); err != nil {
			return err
		}
		return u.b.Reload()
	}()
	back(w, r, "/ui/apps", fmt.Sprintf("App %s saved.", name), err)
}

func (u *ui) deleteApp(w http.ResponseWriter, r *http.Request, s *session) {
	name := r.PathValue("name")
	err := u.b.store.DeleteApp(name)
	if err == nil {
		err = u.b.Reload()
	}
	back(w, r, "/ui/apps", fmt.Sprintf("App %s deleted.", name), err)
}

func (u *ui) testApp(w http.ResponseWriter, r *http.Request, s *session) {
	name := r.PathValue("name")
	app := u.b.st.Load().apps[name]
	if app == nil {
		back(w, r, "/ui/apps", "", fmt.Errorf("no app %q", name))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	slug, err := u.b.gh.appSlug(ctx, app)
	if err != nil {
		back(w, r, "/ui/apps", "", fmt.Errorf("app %s: %v", name, err))
		return
	}
	back(w, r, "/ui/apps", fmt.Sprintf("App %s works: GitHub knows it as %q (bot %s[bot]).", name, slug, slug), nil)
}

// ---- clients ----

type clientView struct {
	ClientRow
	Secrets  []SecretRow
	Grants   []GrantRow
	LastUsed time.Time
}

func (u *ui) clientViews() ([]*clientView, *ConfigRows, error) {
	cfg, err := u.b.store.LoadConfig()
	if err != nil {
		return nil, nil, err
	}
	m := map[string]*clientView{}
	var out []*clientView
	for _, c := range cfg.Clients {
		v := &clientView{ClientRow: c}
		m[c.Name] = v
		out = append(out, v)
	}
	for _, s := range cfg.Secrets {
		if v := m[s.Client]; v != nil {
			v.Secrets = append(v.Secrets, s)
			if s.LastUsedAt.After(v.LastUsed) {
				v.LastUsed = s.LastUsedAt
			}
		}
	}
	for _, g := range cfg.Grants {
		if v := m[g.Client]; v != nil {
			v.Grants = append(v.Grants, g)
		}
	}
	return out, cfg, nil
}

func (u *ui) clients(w http.ResponseWriter, r *http.Request, s *session) {
	views, _, err := u.clientViews()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	u.render(w, r, s, "clients", "clients", "Clients", map[string]any{"Clients": views})
}

func splitList(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' })
	out := []string{}
	for _, x := range f {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func newSecretPair() (secret, sha string) {
	secret = "gaa_" + randToken(32)
	return secret, sha256Hex(secret)
}

func (u *ui) setFlash(s *session, f flash) {
	u.mu.Lock()
	u.flash[s.idSHA] = f
	u.mu.Unlock()
}

func (u *ui) takeFlash(s *session, client string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	f, ok := u.flash[s.idSHA]
	if !ok || f.client != client {
		return ""
	}
	delete(u.flash, s.idSHA)
	return f.secret
}

func (u *ui) createClient(w http.ResponseWriter, r *http.Request, s *session) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	cidrs := splitList(r.PostFormValue("allowed_cidrs"))
	err := func() error {
		if err := validateName("client", name); err != nil {
			return err
		}
		if _, err := parseCIDRs(cidrs); err != nil {
			return err
		}
		if err := u.b.store.CreateClient(ClientRow{Name: name, AllowedCIDRs: cidrs, Note: strings.TrimSpace(r.PostFormValue("note"))}); err != nil {
			return err
		}
		secret, sha := newSecretPair()
		if err := u.b.store.AddSecret(name, sha, "initial"); err != nil {
			return err
		}
		u.setFlash(s, flash{client: name, secret: secret})
		return u.b.Reload()
	}()
	if err != nil {
		back(w, r, "/ui/clients", "", err)
		return
	}
	back(w, r, "/ui/clients/"+url.PathEscape(name), "Client created.", nil)
}

func (u *ui) client(w http.ResponseWriter, r *http.Request, s *session) {
	name := r.PathValue("name")
	views, cfg, err := u.clientViews()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var v *clientView
	for _, c := range views {
		if c.Name == name {
			v = c
		}
	}
	if v == nil {
		http.NotFound(w, r)
		return
	}
	toks, _ := u.b.store.ActiveTokens(u.b.now())
	var mine []*TokenRow
	for _, t := range toks {
		if t.Client == name {
			mine = append(mine, t)
		}
	}
	hist, _ := u.b.store.Requests(RequestFilter{Client: name, Limit: 20})
	var apps []string
	for _, a := range cfg.Apps {
		apps = append(apps, a.Name)
	}
	u.render(w, r, s, "client", "clients", "Client "+name, map[string]any{
		"Client": v, "Tokens": mine, "History": hist, "Apps": apps, "NewSecret": u.takeFlash(s, name),
	})
}

func (u *ui) updateClient(w http.ResponseWriter, r *http.Request, s *session) {
	name := r.PathValue("name")
	cidrs := splitList(r.PostFormValue("allowed_cidrs"))
	err := func() error {
		if _, err := parseCIDRs(cidrs); err != nil {
			return err
		}
		c := ClientRow{Name: name, AllowedCIDRs: cidrs, Disabled: r.PostFormValue("disabled") == "on", Note: strings.TrimSpace(r.PostFormValue("note"))}
		if err := u.b.store.UpdateClient(c); err != nil {
			return err
		}
		return u.b.Reload()
	}()
	back(w, r, "/ui/clients/"+url.PathEscape(name), "Saved.", err)
}

func (u *ui) deleteClient(w http.ResponseWriter, r *http.Request, s *session) {
	name := r.PathValue("name")
	err := u.b.store.DeleteClient(name)
	if err == nil {
		err = u.b.Reload() // revokes the client's live tokens
	}
	back(w, r, "/ui/clients", fmt.Sprintf("Client %s deleted and its tokens revoked.", name), err)
}

func (u *ui) newSecret(w http.ResponseWriter, r *http.Request, s *session) {
	name := r.PathValue("name")
	label := strings.TrimSpace(r.PostFormValue("label"))
	if label == "" {
		label = "added " + time.Now().Format("2006-01-02")
	}
	secret, sha := newSecretPair()
	err := u.b.store.AddSecret(name, sha, label)
	if err == nil {
		err = u.b.Reload()
	}
	if err == nil {
		u.setFlash(s, flash{client: name, secret: secret})
	}
	back(w, r, "/ui/clients/"+url.PathEscape(name), "", err)
}

func (u *ui) deleteSecret(w http.ResponseWriter, r *http.Request, s *session) {
	name := r.PathValue("name")
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	err := u.b.store.DeleteSecret(name, id)
	if err == nil {
		err = u.b.Reload()
	}
	back(w, r, "/ui/clients/"+url.PathEscape(name), "Secret removed.", err)
}

func parseGrantForm(r *http.Request) (string, []string, map[string]string, error) {
	app := r.PostFormValue("app")
	repos := splitList(r.PostFormValue("repos"))
	if len(repos) == 0 {
		return "", nil, nil, errors.New("add at least one repo pattern")
	}
	for _, p := range repos {
		if err := validatePattern(p); err != nil {
			return "", nil, nil, err
		}
	}
	perms := map[string]string{}
	for _, k := range commonPerms {
		if v := r.PostFormValue("perm_" + k); v != "" {
			perms[k] = v
		}
	}
	for _, kv := range splitList(r.PostFormValue("perm_other")) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return "", nil, nil, fmt.Errorf("other permissions: %q should be name=level", kv)
		}
		perms[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if err := validatePerms(perms); err != nil {
		return "", nil, nil, err
	}
	return app, repos, perms, nil
}

func (u *ui) saveGrant(w http.ResponseWriter, r *http.Request, s *session) {
	name := r.PathValue("name")
	err := func() error {
		app, repos, perms, err := parseGrantForm(r)
		if err != nil {
			return err
		}
		if u.b.st.Load().apps[app] == nil {
			return fmt.Errorf("unknown app %q", app)
		}
		g := GrantRow{Client: name, App: app, Repos: repos, Permissions: perms}
		if idStr := r.PathValue("id"); idStr != "" {
			g.ID, _ = strconv.ParseInt(idStr, 10, 64)
			err = u.b.store.UpdateGrant(g)
		} else {
			err = u.b.store.AddGrant(g)
		}
		if err != nil {
			return err
		}
		return u.b.Reload()
	}()
	back(w, r, "/ui/clients/"+url.PathEscape(name), "Grant saved.", err)
}

func (u *ui) deleteGrant(w http.ResponseWriter, r *http.Request, s *session) {
	name := r.PathValue("name")
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	err := u.b.store.DeleteGrant(name, id)
	if err == nil {
		err = u.b.Reload()
	}
	back(w, r, "/ui/clients/"+url.PathEscape(name), "Grant removed.", err)
}

func (u *ui) moveGrant(w http.ResponseWriter, r *http.Request, s *session) {
	name := r.PathValue("name")
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	dir := 1
	if r.PostFormValue("dir") == "up" {
		dir = -1
	}
	err := u.b.store.MoveGrant(name, id, dir)
	if err == nil {
		err = u.b.Reload()
	}
	back(w, r, "/ui/clients/"+url.PathEscape(name), "", err)
}

// ---- settings ----

func (u *ui) settings(w http.ResponseWriter, r *http.Request, s *session) {
	u.render(w, r, s, "settings", "settings", "Settings", nil)
}

func (u *ui) changePassword(w http.ResponseWriter, r *http.Request, s *session) {
	err := func() error {
		stored, _ := u.b.store.GetSetting("admin_password")
		if !checkPassword(stored, r.PostFormValue("current")) {
			return errors.New("current password is wrong")
		}
		np := r.PostFormValue("new")
		if len(np) < 10 {
			return errors.New("new password must be at least 10 characters")
		}
		if np != r.PostFormValue("confirm") {
			return errors.New("new passwords do not match")
		}
		h, err := hashPassword(np)
		if err != nil {
			return err
		}
		if err := u.b.store.SetSetting("admin_password", h); err != nil {
			return err
		}
		u.b.store.DeleteAllSessions()
		return nil
	}()
	if err != nil {
		back(w, r, "/ui/settings", "", err)
		return
	}
	back(w, r, "/ui/login", "Password changed; sign in again.", nil)
}

func (u *ui) reload(w http.ResponseWriter, r *http.Request, s *session) {
	err := u.b.Reload()
	back(w, r, "/ui/settings", "Configuration reloaded from the database.", err)
}
