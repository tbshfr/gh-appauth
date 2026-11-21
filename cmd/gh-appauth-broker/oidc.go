package main

import (
	"cmp"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcCookie       = "gaa_oidc"
	oidcCallbackPath = "/ui/oidc/callback"
	oidcTimeout      = 10 * time.Second
	oidcRetry        = 10 * time.Second
	userLabelMax     = 100
)

const defaultOIDCScopes = "profile,email,groups"

var errSSOUnreachable = errors.New("SSO provider unreachable; see the broker log")

// OIDCConfig configures single sign-on to the admin UI.
type OIDCConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string // empty for a public client
	RedirectURL   string
	AllowedGroups []string
	GroupsClaim   string
	Scopes        []string
	Name          string
}

// oidcConfig checks the -oidc-* flags and reads the client secret file. It
// returns nil when SSO is not configured.
func oidcConfig(c serveConfig) (*OIDCConfig, error) {
	if c.OIDCIssuer == "" {
		var set []string
		for _, f := range []struct{ name, v string }{
			{"-oidc-client-id", c.OIDCClientID},
			{"-oidc-client-secret-file", c.OIDCClientSecretFile},
			{"-oidc-redirect-url", c.OIDCRedirectURL},
			{"-oidc-allowed-groups", c.OIDCAllowedGroups},
			{"-oidc-groups-claim", c.OIDCGroupsClaim},
			{"-oidc-scopes", c.OIDCScopes},
			{"-oidc-name", c.OIDCName},
		} {
			if f.v != "" {
				set = append(set, f.name)
			}
		}
		if len(set) > 0 {
			return nil, fmt.Errorf("%s set without -oidc-issuer", strings.Join(set, ", "))
		}
		return nil, nil
	}
	if c.UIListen == "off" {
		return nil, errors.New("-oidc-issuer is set but the admin UI is off (-ui-listen off)")
	}
	cfg := &OIDCConfig{
		Issuer: c.OIDCIssuer, ClientID: c.OIDCClientID, RedirectURL: c.OIDCRedirectURL,
		AllowedGroups: splitList(c.OIDCAllowedGroups), GroupsClaim: cmp.Or(c.OIDCGroupsClaim, "groups"),
		Name: cmp.Or(c.OIDCName, "SSO"), Scopes: []string{oidc.ScopeOpenID},
	}
	for _, s := range splitList(cmp.Or(c.OIDCScopes, defaultOIDCScopes)) {
		if !slices.Contains(cfg.Scopes, s) {
			cfg.Scopes = append(cfg.Scopes, s)
		}
	}
	if _, err := checkOIDCURL("-oidc-issuer", cfg.Issuer); err != nil {
		return nil, err
	}
	switch {
	case cfg.ClientID == "":
		return nil, errors.New("-oidc-client-id is required with -oidc-issuer")
	case cfg.RedirectURL == "":
		return nil, fmt.Errorf("-oidc-redirect-url is required with -oidc-issuer (the broker's public URL plus %s)", oidcCallbackPath)
	case len(cfg.AllowedGroups) == 0:
		return nil, errors.New("-oidc-allowed-groups is required with -oidc-issuer; without it anyone the provider knows could sign in")
	}
	u, err := checkOIDCURL("-oidc-redirect-url", cfg.RedirectURL)
	if err != nil {
		return nil, err
	}
	if u.Path != oidcCallbackPath || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("-oidc-redirect-url must end in %s (got %q)", oidcCallbackPath, cfg.RedirectURL)
	}
	if f := c.OIDCClientSecretFile; f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("-oidc-client-secret-file: %w", err)
		}
		if cfg.ClientSecret = strings.TrimRight(string(b), "\r\n"); cfg.ClientSecret == "" {
			return nil, fmt.Errorf("-oidc-client-secret-file: %s is empty", f)
		}
	}
	return cfg, nil
}

func checkOIDCURL(flag, s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("%s: %q is not an absolute http(s) URL", flag, s)
	}
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("%s: %q must use https:// (plain http:// only on loopback)", flag, s)
	}
	return u, nil
}

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsLoopback()
}

// sso holds what discovery found. Discovery runs in the background at
// startup and, while it keeps failing, again on a login at most every
// oidcRetry, so an unreachable provider never holds up the token API.
type sso struct {
	cfg OIDCConfig
	hc  *http.Client
	now func() time.Time

	ready   atomic.Pointer[ssoReady]
	lastErr atomic.Pointer[string]

	mu      sync.Mutex // serialises discovery
	lastTry time.Time
}

type ssoReady struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

func newSSO(cfg OIDCConfig, now func() time.Time) *sso {
	return &sso{cfg: cfg, hc: &http.Client{Timeout: oidcTimeout}, now: now}
}

func (s *sso) ctx(parent context.Context) context.Context { return oidc.ClientContext(parent, s.hc) }

func (s *sso) get() (*ssoReady, error) {
	if r := s.ready.Load(); r != nil {
		return r, nil
	}
	// With the provider down, an attempt takes the whole client timeout;
	// requests that arrive meanwhile shouldn't queue up behind it.
	if !s.mu.TryLock() {
		return nil, errSSOUnreachable
	}
	defer s.mu.Unlock()
	if r := s.ready.Load(); r != nil {
		return r, nil
	}
	if !s.lastTry.IsZero() && s.now().Sub(s.lastTry) < oidcRetry {
		return nil, errSSOUnreachable
	}
	p, err := oidc.NewProvider(s.ctx(context.Background()), s.cfg.Issuer)
	if err != nil {
		s.lastTry = s.now()
		msg := err.Error()
		if len(msg) > 300 {
			msg = strings.ToValidUTF8(msg[:300], "") + "…"
		}
		s.lastErr.Store(&msg)
		fmt.Fprintf(os.Stderr, "gh-appauth-broker: OIDC discovery for %s failed: %v\n", s.cfg.Issuer, err)
		return nil, errSSOUnreachable
	}
	oc := &oauth2.Config{ClientID: s.cfg.ClientID, ClientSecret: s.cfg.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: s.cfg.RedirectURL, Scopes: s.cfg.Scopes}
	if s.cfg.ClientSecret == "" {
		// Auto-detection would first try HTTP Basic auth with an empty secret.
		oc.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	r := &ssoReady{provider: p, oauth: oc, verifier: p.Verifier(&oidc.Config{ClientID: s.cfg.ClientID, Now: s.now})}
	s.ready.Store(r)
	s.lastErr.Store(nil)
	fmt.Fprintf(os.Stderr, "gh-appauth-broker: OIDC provider %s discovered\n", s.cfg.Issuer)
	return r, nil
}

func (s *sso) status() (ok bool, text string) {
	if s.ready.Load() != nil {
		return true, "discovered"
	}
	if e := s.lastErr.Load(); e != nil {
		return false, *e
	}
	return false, "not contacted yet"
}

type oidcFlow struct{ state, nonce, verifier string }

func (f oidcFlow) encode() string { return f.state + "." + f.nonce + "." + f.verifier }

func decodeOIDCFlow(s string) (oidcFlow, bool) {
	p := strings.Split(s, ".")
	if len(p) != 3 || p[0] == "" || p[1] == "" || p[2] == "" {
		return oidcFlow{}, false
	}
	return oidcFlow{p[0], p[1], p[2]}, true
}

func (u *ui) setOIDCCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	// Lax, not Strict: the provider's redirect back to the callback is a
	// cross-site navigation, and the cookie has to come along with it.
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: value, Path: "/ui/oidc/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: u.b.viaHTTPS(r)})
}

func (u *ui) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if u.session(r) != nil {
		http.Redirect(w, r, "/ui/", http.StatusFound)
		return
	}
	rd, err := u.b.sso.get()
	if err != nil {
		back(w, r, "/ui/login", "", err)
		return
	}
	f := oidcFlow{state: randToken(32), nonce: randToken(32), verifier: oauth2.GenerateVerifier()}
	u.setOIDCCookie(w, r, f.encode(), 600)
	http.Redirect(w, r, rd.oauth.AuthCodeURL(f.state, oidc.Nonce(f.nonce), oauth2.S256ChallengeOption(f.verifier)), http.StatusFound)
}

// ssoFailure.msg is shown on the page; detail only goes to stderr.
type ssoFailure struct {
	code   int
	msg    string
	detail string
}

func (u *ui) oidcCallback(w http.ResponseWriter, r *http.Request) {
	now := u.b.now()
	addr := u.b.clientIP(r)
	ip, limKey := addr.String(), limitKey(addr)
	if !u.b.loginLim.allow(limKey, now) {
		u.loginFailed(w, r, http.StatusTooManyRequests, "Too many failed attempts; wait a minute.")
		return
	}
	c, _ := r.Cookie(oidcCookie)
	u.setOIDCCookie(w, r, "", -1)
	user, sub, f := u.oidcExchange(r, c)
	if f != nil {
		fmt.Fprintf(os.Stderr, "gh-appauth-broker: SSO sign-in from %s failed: %s\n", ip, f.detail)
		reason := "SSO login failed"
		if f.code == http.StatusForbidden {
			reason = fmt.Sprintf("SSO login refused: %s (sub %s) is not in an allowed group", user, sub)
		}
		u.b.audit(&RequestRow{TS: now, Event: "denied", Status: f.code, IP: ip, Reason: reason})
		u.loginFailed(w, r, f.code, f.msg)
		return
	}
	u.b.loginLim.refund(limKey, now)
	if err := u.startSession(w, r, user, "SSO", now, ip); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// A 302 to /ui/ would continue the redirect chain that started at the
	// provider, so the browser would treat it as cross-site and leave out the
	// SameSite=Strict session cookie. A page that moves on by itself makes
	// the next request same-site.
	u.render(w, r, nil, "oidc_continue", "", "Signed in", nil)
}

// oidcExchange checks the callback and returns the user's label and subject.
// The provider's error text is never shown: a crafted link could put any
// words there.
func (u *ui) oidcExchange(r *http.Request, c *http.Cookie) (user, sub string, _ *ssoFailure) {
	fail := func(msg, format string, a ...any) (string, string, *ssoFailure) {
		return "", "", &ssoFailure{http.StatusBadRequest, msg, fmt.Sprintf(format, a...)}
	}
	const retry = "Sign-in failed; try again."
	if c == nil {
		return fail("Sign-in expired or was already used; start again.", "no %s cookie", oidcCookie)
	}
	flow, ok := decodeOIDCFlow(c.Value)
	if !ok {
		return fail("Sign-in expired or was already used; start again.", "malformed %s cookie", oidcCookie)
	}
	q := r.URL.Query()
	// state is checked before error= so that only a response to our own
	// request can show an error at all.
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(flow.state)) != 1 {
		return fail(retry, "state mismatch")
	}
	if e := q.Get("error"); e != "" {
		msg := "The provider could not complete the sign-in; see the broker log."
		if e == "access_denied" {
			msg = "Sign-in was cancelled or refused by the provider."
		}
		return fail(msg, "provider returned error %q: %q", e, q.Get("error_description"))
	}
	rd, err := u.b.sso.get()
	if err != nil {
		return fail(errSSOUnreachable.Error(), "discovery: %v", err)
	}
	ctx, cancel := context.WithTimeout(u.b.sso.ctx(r.Context()), 2*oidcTimeout)
	defer cancel()
	tok, err := rd.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(flow.verifier))
	if err != nil {
		return fail(retry, "code exchange: %q", err.Error())
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return fail(retry, "token response has no id_token")
	}
	idt, err := rd.verifier.Verify(ctx, raw)
	if err != nil {
		return fail(retry, "ID token: %v", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(flow.nonce)) != 1 {
		return fail(retry, "ID token nonce mismatch")
	}
	var claims map[string]json.RawMessage
	if err := idt.Claims(&claims); err != nil {
		return fail(retry, "ID token claims: %v", err)
	}
	cfg := u.b.sso.cfg
	var azp string
	json.Unmarshal(claims["azp"], &azp)
	if (len(idt.Audience) > 1 || azp != "") && azp != cfg.ClientID {
		return fail(retry, "ID token azp %q is not the client ID", azp)
	}
	groupsRaw, ok := claims[cfg.GroupsClaim]
	if !ok {
		info, err := rd.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return fail(retry, "userinfo: %q", err.Error())
		}
		if info.Subject != idt.Subject {
			return fail(retry, "userinfo sub %q does not match ID token sub %q", info.Subject, idt.Subject)
		}
		var uc map[string]json.RawMessage
		if err := info.Claims(&uc); err != nil {
			return fail(retry, "userinfo claims: %v", err)
		}
		groupsRaw = uc[cfg.GroupsClaim]
		for k, v := range uc {
			if _, ok := claims[k]; !ok {
				claims[k] = v
			}
		}
	}
	user = userLabel(claims, idt.Subject)
	groups := parseGroups(groupsRaw)
	if !slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(cfg.AllowedGroups, g) }) {
		return user, printable(idt.Subject), &ssoFailure{http.StatusForbidden, "Your account is not allowed to use this broker.",
			fmt.Sprintf("%q (sub %q) has groups %q, none of them allowed", user, idt.Subject, groups)}
	}
	return user, printable(idt.Subject), nil
}

// parseGroups accepts a list of strings, a single string, or an object whose
// keys are the names (Zitadel's role claims).
func parseGroups(raw json.RawMessage) []string {
	var list []any
	if json.Unmarshal(raw, &list) == nil {
		var out []string
		for _, v := range list {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil && obj != nil {
		var out []string
		for k := range obj {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	return nil
}

// printable drops control and format characters: users can often edit their
// own name at the provider, and it ends up in log lines.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

func userLabel(claims map[string]json.RawMessage, sub string) string {
	label := printable(sub)
	for _, k := range []string{"preferred_username", "email", "name"} {
		var s string
		if json.Unmarshal(claims[k], &s) == nil {
			if s = strings.TrimSpace(printable(s)); s != "" {
				label = s
				break
			}
		}
	}
	if r := []rune(label); len(r) > userLabelMax {
		label = string(r[:userLabelMax]) + "…"
	}
	return label
}
