package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tbshfr/gh-appauth/internal/api"
	"github.com/tbshfr/gh-appauth/internal/buildinfo"
	"github.com/tbshfr/gh-appauth/internal/repo"
)

const (
	maxBody       = 64 << 10
	minCachedLife = 10 * time.Minute
	instCacheTTL  = time.Hour
	// githubBudget bounds all GitHub calls of one token request. It has to
	// stay below the server's write timeout, or the client never sees the
	// answer to a request that did mint a token.
	githubBudget  = 45 * time.Second
	identityRetry = 5 * time.Minute
)

type Options struct {
	GitHubAPI       string
	TrustedProxies  []netip.Prefix
	TokensPerMinute int
	FailsPerMinute  int
	HTTPClient      *http.Client
	Now             func() time.Time
	Log             io.Writer
	HistoryDays     int
	// SecureCookies marks UI session cookies Secure (set when serving TLS).
	// Behind a trusted proxy, X-Forwarded-Proto: https has the same effect.
	SecureCookies bool
	// Info is shown read-only on the UI settings page.
	Info ServerInfo
}

type ServerInfo struct {
	Version        string
	DBPath         string
	Listen         string
	UIListen       string
	TLSMode        string
	TLSFingerprint string
	TLSHosts       []string
	TrustedProxies []string
	SetupURL       string // suggested --broker URL for client setup
}

func (i ServerInfo) ReleaseURL() string { return buildinfo.ReleaseURL(i.Version) }

type instEntry struct {
	id      int64
	fetched time.Time
}

type identity struct {
	slug    string
	botID   int64
	lastTry time.Time
	done    bool
}

type Broker struct {
	store *Store
	gh    *ghClient
	opts  Options
	st    atomic.Pointer[state]

	// reloadMu serialises Reload so that the snapshot loaded last is also the
	// one stored last.
	reloadMu sync.Mutex

	tokenLim *limiter
	failLim  *limiter
	// loginLim is separate from failLim so that failed API requests can't
	// lock the admin out of the UI, or the other way round.
	loginLim *limiter

	mu        sync.Mutex
	inst      map[string]instEntry
	ids       map[string]*identity
	keyLocks  map[string]*keyLock
	lastTouch map[int64]time.Time

	ui *ui
}

type keyLock struct {
	mu   sync.Mutex
	refs int
}

func NewBroker(store *Store, opts Options) (*Broker, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = os.Stdout
	}
	if opts.TokensPerMinute == 0 {
		opts.TokensPerMinute = 60
	}
	if opts.FailsPerMinute == 0 {
		opts.FailsPerMinute = 20
	}
	if opts.GitHubAPI == "" {
		opts.GitHubAPI = "https://api.github.com"
	}
	if opts.HistoryDays == 0 {
		opts.HistoryDays = 30
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	if opts.HTTPClient != nil {
		c := *opts.HTTPClient
		hc = &c
	}
	// GitHub redirects requests for renamed or transferred repositories.
	// Following one would answer for a different repository, possibly under
	// another owner, than the one the grant was checked against.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	b := &Broker{
		store:     store,
		gh:        &ghClient{api: opts.GitHubAPI, http: hc, now: opts.Now},
		opts:      opts,
		tokenLim:  newLimiter(opts.TokensPerMinute),
		failLim:   newLimiter(opts.FailsPerMinute),
		loginLim:  newLimiter(opts.FailsPerMinute),
		inst:      map[string]instEntry{},
		ids:       map[string]*identity{},
		keyLocks:  map[string]*keyLock{},
		lastTouch: map[int64]time.Time{},
	}
	if err := b.Reload(); err != nil {
		return nil, err
	}
	b.ui = newUI(b)
	return b, nil
}

func (b *Broker) now() time.Time { return b.opts.Now() }

// Reload rebuilds the config snapshot from the database. On error the current
// snapshot stays in place. Live tokens the new configuration would no longer
// issue are revoked.
func (b *Broker) Reload() error {
	b.reloadMu.Lock()
	defer b.reloadMu.Unlock()
	rows, err := b.store.LoadConfig()
	if err != nil {
		return err
	}
	st, err := buildState(rows)
	if err != nil {
		return err
	}
	b.st.Store(st)
	b.mu.Lock()
	b.inst = map[string]instEntry{}
	b.ids = map[string]*identity{}
	b.mu.Unlock()

	now := b.now()
	toks, err := b.store.ActiveTokens(now)
	if err != nil {
		return err
	}
	for _, t := range toks {
		reason := staleReason(st, t)
		if reason == "" {
			continue
		}
		if err := b.store.MarkRevoked(t.ID, reason, now); err != nil {
			return err
		}
		go b.revokeAtGitHub(t.Token, &RequestRow{TS: now, Event: "revoked", Client: t.Client, Repo: t.Repo, App: t.App,
			Perms: permString(t.Permissions), Reason: reason})
	}
	return nil
}

// tokenKey identifies interchangeable tokens: same client, App, repo and
// requested permissions. The App ID is part of it so that replacing an App
// under the same name does not keep serving the old App's tokens.
func tokenKey(client string, app *appState, repoLower, perms string) string {
	return strings.Join([]string{client, fmt.Sprintf("%s#%d", app.Name, app.AppID), repoLower, perms}, "|")
}

// staleReason says why st would no longer issue token t, or "" if it would.
func staleReason(st *state, t *TokenRow) string {
	cl := st.clients[t.Client]
	if cl == nil || cl.Disabled {
		return "client removed or disabled"
	}
	app := st.apps[t.App]
	if app == nil {
		return "app removed"
	}
	g := cl.grantFor(t.Repo)
	if g == nil || g.App != t.App {
		return "grant removed"
	}
	// The last key segment holds the permissions the token was requested
	// with. t.Permissions is what GitHub reported, which can include extras
	// such as metadata=read, so it can't be compared against the grant.
	requested := t.CacheKey[strings.LastIndexByte(t.CacheKey, '|')+1:]
	if t.CacheKey != tokenKey(t.Client, app, t.Repo, requested) {
		return "app replaced"
	}
	if p, err := narrow(g.Perms, parsePermString(requested)); err != nil || permString(p) != requested {
		return "grant permissions changed"
	}
	return ""
}

// revokeAtGitHub revokes token at GitHub and then records ev, noting a
// failed revocation in its reason so it shows up in the history.
func (b *Broker) revokeAtGitHub(token string, ev *RequestRow) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := b.gh.revoke(ctx, token)
	if err != nil {
		ev.Reason += " (GitHub revoke failed: " + err.Error() + ")"
	}
	b.audit(ev)
	return err
}

// RevokeToken revokes one issued token (UI action).
func (b *Broker) RevokeToken(id int64, reason string) error {
	t, err := b.store.TokenByID(id)
	if err != nil {
		return err
	}
	if t == nil {
		return errors.New("no such token")
	}
	if err := b.store.MarkRevoked(id, reason, b.now()); err != nil {
		return err
	}
	return b.revokeAtGitHub(t.Token, &RequestRow{TS: b.now(), Event: "revoked", Client: t.Client, Repo: t.Repo, App: t.App,
		Perms: permString(t.Permissions), Reason: reason})
}

// ---- audit ----

type auditLine struct {
	TS     string `json:"ts"`
	Event  string `json:"event"`
	Status int    `json:"status,omitempty"`
	Client string `json:"client,omitempty"`
	IP     string `json:"ip,omitempty"`
	Repo   string `json:"repo,omitempty"`
	App    string `json:"app,omitempty"`
	Perms  string `json:"perms,omitempty"`
	Cached bool   `json:"cached"`
	Reason string `json:"reason,omitempty"`
}

func (b *Broker) audit(ev *RequestRow) {
	line, _ := json.Marshal(auditLine{
		TS: ev.TS.UTC().Format(time.RFC3339), Event: ev.Event, Status: ev.Status, Client: ev.Client, IP: ev.IP,
		Repo: ev.Repo, App: ev.App, Perms: ev.Perms, Cached: ev.Cached, Reason: ev.Reason,
	})
	b.mu.Lock()
	b.opts.Log.Write(append(line, '\n'))
	b.mu.Unlock()
	if err := b.store.InsertRequest(ev); err != nil {
		fmt.Fprintf(os.Stderr, "gh-appauth-broker: writing request history: %v\n", err)
	}
}

// PruneLoop deletes request history older than HistoryDays, hourly.
func (b *Broker) PruneLoop(ctx context.Context) {
	for {
		if n, err := b.store.PruneRequests(b.now().AddDate(0, 0, -b.opts.HistoryDays)); err != nil {
			fmt.Fprintf(os.Stderr, "gh-appauth-broker: pruning history: %v\n", err)
		} else if n > 0 {
			fmt.Fprintf(os.Stderr, "gh-appauth-broker: pruned %d history rows\n", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// ---- HTTP ----

// APIHandler serves /healthz and /v1/*. If withUI is set, the admin UI is
// mounted under /ui/ as well.
func (b *Broker) APIHandler(withUI bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("POST /v1/token", b.handleToken)
	mux.HandleFunc("POST /v1/invalidate", b.handleInvalidate)
	mux.HandleFunc("GET /v1/whoami", b.handleWhoami)
	mux.HandleFunc("GET /v1/repos", b.handleRepos)
	if withUI {
		b.ui.mount(mux)
	}
	return mux
}

// UIHandler serves only the admin UI (for a separate -ui-listen address).
func (b *Broker) UIHandler() http.Handler {
	mux := http.NewServeMux()
	b.ui.mount(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (b *Broker) fail(w http.ResponseWriter, ev *RequestRow, code int, event, reason string) {
	ev.Event, ev.Status, ev.Reason = event, code, reason
	b.audit(ev)
	writeJSON(w, code, api.Error{Error: reason})
}

func (b *Broker) isTrusted(ip netip.Addr) bool {
	for _, p := range b.opts.TrustedProxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// peerIP is the address of the directly connected peer.
func peerIP(r *http.Request) netip.Addr {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	if r.RemoteAddr == "" || r.RemoteAddr == "@" || strings.HasPrefix(r.RemoteAddr, "/") {
		return netip.MustParseAddr("127.0.0.1") // unix socket peer
	}
	return netip.IPv4Unspecified()
}

// viaHTTPS reports whether the browser reached the broker over HTTPS: either
// the broker serves TLS itself, or a trusted proxy says it terminated TLS.
func (b *Broker) viaHTTPS(r *http.Request) bool {
	return b.opts.SecureCookies || (b.isTrusted(peerIP(r)) && r.Header.Get("X-Forwarded-Proto") == "https")
}

// clientIP returns the address used for allowed_cidrs and the audit log.
// X-Forwarded-For is only honoured when the direct peer is a trusted proxy;
// we then take the right-most address that is not itself a trusted proxy.
func (b *Broker) clientIP(r *http.Request) netip.Addr {
	ip := peerIP(r)
	if !b.isTrusted(ip) {
		return ip
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return ip
		}
		a = a.Unmap()
		if !b.isTrusted(a) {
			return a
		}
		ip = a
	}
	return ip
}

func (b *Broker) authenticate(w http.ResponseWriter, r *http.Request, ev *RequestRow) *clientState {
	now := b.now()
	ip := b.clientIP(r)
	ev.IP = ip.String()
	limKey := limitKey(ip)
	if !b.failLim.allow(limKey, now) {
		// Not audited: nothing here is authenticated, so a flood would
		// otherwise grow the history and the log without bound.
		writeJSON(w, http.StatusTooManyRequests, api.Error{Error: "too many failed authentication attempts"})
		return nil
	}
	secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	secret = strings.TrimSpace(secret)
	if !ok || secret == "" {
		b.fail(w, ev, http.StatusUnauthorized, "denied", "missing bearer secret")
		return nil
	}
	sum := sha256.Sum256([]byte(secret))
	st := b.st.Load()
	var match *secretEntry
	// Compare against every hash without stopping early so timing does not
	// reveal which (or whether a) hash matched.
	for i := range st.secrets {
		if subtle.ConstantTimeCompare(sum[:], st.secrets[i].sum[:]) == 1 {
			match = &st.secrets[i]
		}
	}
	if match == nil || match.client.Disabled {
		b.fail(w, ev, http.StatusUnauthorized, "denied", "unknown client secret")
		return nil
	}
	b.failLim.refund(limKey, now)
	cl := match.client
	ev.Client = cl.Name
	if !cl.ipAllowed(ip) {
		b.fail(w, ev, http.StatusForbidden, "denied", fmt.Sprintf("client %q is not allowed from %s", cl.Name, ip))
		return nil
	}
	b.mu.Lock()
	touch := now.Sub(b.lastTouch[match.id]) > time.Minute
	if touch {
		b.lastTouch[match.id] = now
	}
	b.mu.Unlock()
	if touch {
		b.store.TouchSecret(match.id, now)
	}
	return cl
}

func (b *Broker) handleWhoami(w http.ResponseWriter, r *http.Request) {
	ev := &RequestRow{TS: b.now()}
	cl := b.authenticate(w, r, ev)
	if cl == nil {
		return
	}
	out := api.WhoAmI{Client: cl.Name, IP: ev.IP, Grants: []api.Grant{}}
	for _, g := range cl.Grants {
		out.Grants = append(out.Grants, api.Grant{App: g.App, Repos: g.Repos, Permissions: g.Perms})
	}
	writeJSON(w, 200, out)
}

func (b *Broker) handleInvalidate(w http.ResponseWriter, r *http.Request) {
	ev := &RequestRow{TS: b.now()}
	cl := b.authenticate(w, r, ev)
	if cl == nil {
		return
	}
	var req api.InvalidateRequest
	if err := decodeBody(w, r, &req); err != nil || req.Token == "" {
		b.fail(w, ev, 400, "denied", "bad request body")
		return
	}
	t, err := b.store.TokenBySHA(cl.Name, sha256Hex(req.Token))
	if err != nil {
		b.fail(w, ev, 500, "error", "database error")
		return
	}
	if t != nil {
		_ = b.store.MarkRevoked(t.ID, "rejected by GitHub (reported by client)", b.now())
		ev.Event, ev.Repo, ev.App, ev.Perms = "invalidated", t.Repo, t.App, permString(t.Permissions)
		ev.Reason = "client reported token rejected"
		// The client's word is not proof that GitHub rejected the token, and
		// a token dropped from the table can no longer be revoked from the UI.
		go b.revokeAtGitHub(t.Token, ev)
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (b *Broker) lockKey(key string) func() {
	b.mu.Lock()
	kl := b.keyLocks[key]
	if kl == nil {
		kl = &keyLock{}
		b.keyLocks[key] = kl
	}
	kl.refs++
	b.mu.Unlock()
	kl.mu.Lock()
	return func() {
		kl.mu.Unlock()
		b.mu.Lock()
		kl.refs--
		if kl.refs == 0 {
			delete(b.keyLocks, key)
		}
		b.mu.Unlock()
	}
}

func (b *Broker) handleToken(w http.ResponseWriter, r *http.Request) {
	now := b.now()
	ev := &RequestRow{TS: now}
	cl := b.authenticate(w, r, ev)
	if cl == nil {
		return
	}
	if !b.tokenLim.allow(cl.Name, now) {
		b.fail(w, ev, http.StatusTooManyRequests, "denied", "rate limit exceeded")
		return
	}
	var req api.TokenRequest
	if err := decodeBody(w, r, &req); err != nil {
		b.fail(w, ev, 400, "denied", "bad request body: "+err.Error())
		return
	}
	ev.Repo = req.Repository
	if !repo.Valid(req.Repository) {
		b.fail(w, ev, 400, "denied", fmt.Sprintf("invalid repository %q", req.Repository))
		return
	}
	full := strings.ToLower(req.Repository)
	ev.Repo = full
	g := cl.grantFor(full)
	if g == nil {
		b.fail(w, ev, 403, "denied", fmt.Sprintf("client %q has no grant for %s", cl.Name, full))
		return
	}
	st := b.st.Load()
	app := st.apps[g.App]
	if app == nil { // config was reloaded between authentication and here
		b.fail(w, ev, 503, "error", "configuration changed, retry")
		return
	}
	ev.App = app.Name
	perms, err := narrow(g.Perms, req.Permissions)
	if err != nil {
		ev.Perms = permString(req.Permissions)
		b.fail(w, ev, 403, "denied", err.Error())
		return
	}
	ev.Perms = permString(perms)

	key := tokenKey(cl.Name, app, full, ev.Perms)
	unlock := b.lockKey(key)
	defer unlock()

	if t, err := b.store.CachedToken(key, now.Add(minCachedLife)); err != nil {
		b.fail(w, ev, 500, "error", "database error: "+err.Error())
		return
	} else if t != nil {
		b.store.HitToken(t.ID)
		ev.Event, ev.Status, ev.Cached = "issued", 200, true
		// Log what the token actually carries: with no permissions requested it
		// gets the installation's full set, which only GitHub's response tells us.
		ev.Perms = permString(t.Permissions)
		b.audit(ev)
		writeJSON(w, 200, api.TokenResponse{
			Token: t.Token, ExpiresAt: t.ExpiresAt.UTC(), Repository: full, App: app.Name, Permissions: t.Permissions,
			BotName: t.BotName, BotEmail: t.BotEmail, Cached: true,
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), githubBudget)
	defer cancel()
	owner, name, _ := strings.Cut(full, "/")
	instID, err := b.installation(ctx, app, owner, func() (int64, error) { return b.gh.installationID(ctx, app, full) })
	if err != nil {
		code, msg := ghFailure(err, app.Name, full)
		b.fail(w, ev, code, eventFor(code), msg)
		return
	}
	res, err := b.gh.mint(ctx, app, instID, name, perms)
	if err != nil {
		var ge *ghError
		if errors.As(err, &ge) && ge.Status == 404 {
			b.dropInstallation(app, owner) // installation was probably removed
		}
		code, msg := ghFailure(err, app.Name, full)
		b.fail(w, ev, code, eventFor(code), msg)
		return
	}
	botName, botEmail := b.identity(ctx, app, res.Token)
	row := &TokenRow{
		CacheKey: key, Client: cl.Name, App: app.Name, Repo: full, Permissions: res.Permissions,
		Token: res.Token, TokenSHA256: sha256Hex(res.Token), BotName: botName, BotEmail: botEmail,
		IssuedAt: now, ExpiresAt: res.ExpiresAt,
	}
	if err := b.store.InsertToken(row, now); err != nil {
		// An unrecorded token could never be revoked, so don't hand it out.
		msg := "database error: " + err.Error()
		ev.Event, ev.Status, ev.Reason = "error", 500, msg
		go b.revokeAtGitHub(res.Token, ev)
		writeJSON(w, 500, api.Error{Error: msg})
		return
	}
	ev.Event, ev.Status = "issued", 200
	ev.Perms = permString(res.Permissions)
	b.audit(ev)
	writeJSON(w, 200, api.TokenResponse{
		Token: res.Token, ExpiresAt: res.ExpiresAt.UTC(), Repository: full, App: app.Name, Permissions: res.Permissions,
		BotName: botName, BotEmail: botEmail,
	})
}

// handleRepos lists the repositories of one owner that the client can get a
// token for: those its first matching grant names an App for, and that this
// App's installation can access.
func (b *Broker) handleRepos(w http.ResponseWriter, r *http.Request) {
	now := b.now()
	ev := &RequestRow{TS: now}
	cl := b.authenticate(w, r, ev)
	if cl == nil {
		return
	}
	owner := r.URL.Query().Get("owner")
	ev.Repo = strings.ToLower(owner) + "/*"
	if !repo.ValidOwner(owner) {
		b.fail(w, ev, 400, "denied", fmt.Sprintf("invalid owner %q", owner))
		return
	}
	owner = strings.ToLower(owner)
	// Each listing mints a token at GitHub, so it counts like a token request.
	if !b.tokenLim.allow(cl.Name, now) {
		b.fail(w, ev, http.StatusTooManyRequests, "denied", "rate limit exceeded")
		return
	}
	st := b.st.Load()
	var apps []*appState
	for _, g := range cl.Grants {
		app := st.apps[g.App]
		if app == nil {
			b.fail(w, ev, 503, "error", "configuration changed, retry")
			return
		}
		if !slices.Contains(apps, app) && slices.ContainsFunc(g.Repos, func(p string) bool {
			ownerPat, _, _ := strings.Cut(p, "/")
			ok, _ := path.Match(ownerPat, owner)
			return ok
		}) {
			apps = append(apps, app)
		}
	}
	if len(apps) == 0 {
		b.fail(w, ev, 403, "denied", fmt.Sprintf("client %q has no grant for repos of %s", cl.Name, owner))
		return
	}
	var names []string
	for _, a := range apps {
		names = append(names, a.Name)
	}
	ev.App = strings.Join(names, ",")

	ctx, cancel := context.WithTimeout(r.Context(), githubBudget)
	defer cancel()
	out := api.RepoList{Repos: []api.Repo{}}
	for _, app := range apps {
		repos, err := b.installationRepos(ctx, app, owner)
		var ge *ghError
		if errors.As(err, &ge) && ge.Status == 404 {
			continue // this App isn't installed on owner
		}
		if err != nil {
			code, msg := ghFailure(err, app.Name, owner)
			b.fail(w, ev, code, eventFor(code), msg)
			return
		}
		for _, gr := range repos {
			full := strings.ToLower(gr.FullName)
			if o, _, _ := strings.Cut(full, "/"); o != owner || !repo.Valid(gr.FullName) {
				continue
			}
			if g := cl.grantFor(full); g != nil && g.App == app.Name {
				out.Repos = append(out.Repos, api.Repo{FullName: gr.FullName, DefaultBranch: gr.DefaultBranch,
					Private: gr.Private, Archived: gr.Archived, App: app.Name})
			}
		}
	}
	slices.SortFunc(out.Repos, func(a, b api.Repo) int {
		return strings.Compare(strings.ToLower(a.FullName), strings.ToLower(b.FullName))
	})
	ev.Event, ev.Status, ev.Reason = "listed", 200, fmt.Sprintf("%d repos", len(out.Repos))
	b.audit(ev)
	writeJSON(w, 200, out)
}

// installationRepos lists every repository app's installation on owner can
// access, using a short-lived metadata token that is revoked right after.
// That token never leaves the broker, so it isn't recorded with the issued
// tokens.
func (b *Broker) installationRepos(ctx context.Context, app *appState, owner string) ([]ghRepo, error) {
	instID, err := b.installation(ctx, app, owner, func() (int64, error) { return b.gh.ownerInstallationID(ctx, app, owner) })
	if err != nil {
		return nil, err
	}
	res, err := b.gh.mintListing(ctx, app, instID)
	if err != nil {
		var ge *ghError
		if errors.As(err, &ge) && ge.Status == 404 {
			b.dropInstallation(app, owner)
		}
		return nil, err
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := b.gh.revoke(rctx, res.Token); err != nil {
			fmt.Fprintf(os.Stderr, "gh-appauth-broker: revoking listing token of app %s: %v\n", app.Name, err)
		}
	}()
	return b.gh.installationRepos(ctx, res.Token)
}

func eventFor(code int) string {
	if code == 403 {
		return "denied"
	}
	return "error"
}

// ghFailure maps GitHub errors to broker responses. 404/422 mean the App is
// not installed on the owner, or the repo is not among the installation's
// selected repositories (or the permissions exceed the installation's).
func ghFailure(err error, app, full string) (int, string) {
	var ge *ghError
	if errors.As(err, &ge) {
		if ge.Status/100 == 3 {
			return 403, fmt.Sprintf("%s was renamed or transferred; request it under its current name", full)
		}
		if ge.Status == 404 || ge.Status == 422 {
			return 403, fmt.Sprintf("app %s is not installed on %s or lacks the requested access (GitHub: %s)", app, full, ge.Message)
		}
		return 502, fmt.Sprintf("GitHub error for %s: %s", full, ge.Error())
	}
	return 502, fmt.Sprintf("GitHub unreachable: %v", err)
}

func instKey(app *appState, owner string) string {
	return fmt.Sprintf("%s#%d|%s", app.Name, app.AppID, owner)
}

// installation returns the cached installation ID of app on owner, calling
// lookup when there is none.
func (b *Broker) installation(ctx context.Context, app *appState, owner string, lookup func() (int64, error)) (int64, error) {
	k := instKey(app, owner)
	b.mu.Lock()
	e, ok := b.inst[k]
	b.mu.Unlock()
	if ok && b.now().Sub(e.fetched) < instCacheTTL {
		return e.id, nil
	}
	id, err := lookup()
	if err != nil {
		return 0, err
	}
	b.mu.Lock()
	b.inst[k] = instEntry{id: id, fetched: b.now()}
	b.mu.Unlock()
	return id, nil
}

func (b *Broker) dropInstallation(app *appState, owner string) {
	b.mu.Lock()
	delete(b.inst, instKey(app, owner))
	b.mu.Unlock()
}

// identity returns the bot's git name and noreply email. Failures never fail
// the token request; lookups are retried at most every identityRetry.
func (b *Broker) identity(ctx context.Context, app *appState, token string) (string, string) {
	k := fmt.Sprintf("%s#%d", app.Name, app.AppID)
	b.mu.Lock()
	id := b.ids[k]
	if id == nil {
		id = &identity{}
		b.ids[k] = id
	}
	if id.done || (!id.lastTry.IsZero() && b.now().Sub(id.lastTry) < identityRetry) {
		slug, botID := id.slug, id.botID
		b.mu.Unlock()
		return botIdentity(slug, botID)
	}
	id.lastTry = b.now()
	slug := id.slug
	b.mu.Unlock()

	var botID int64
	var err error
	if slug == "" {
		slug, err = b.gh.appSlug(ctx, app)
	}
	if err == nil {
		botID, err = b.gh.botUserID(ctx, slug, token)
	}
	b.mu.Lock()
	id.slug = slug
	if err == nil {
		id.botID, id.done = botID, true
	} else {
		fmt.Fprintf(os.Stderr, "gh-appauth-broker: bot identity for app %s: %v\n", app.Name, err)
	}
	b.mu.Unlock()
	return botIdentity(slug, botID)
}

func botIdentity(slug string, id int64) (string, string) {
	if slug == "" {
		return "", ""
	}
	name := slug + "[bot]"
	if id == 0 {
		return name, ""
	}
	return name, fmt.Sprintf("%d+%s@users.noreply.github.com", id, name)
}
