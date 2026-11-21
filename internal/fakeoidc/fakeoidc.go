// Package fakeoidc is an OpenID Connect provider for tests. /authorize
// approves every request at once; /token checks client authentication, the
// single-use code and the PKCE verifier.
package fakeoidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

const KeyID = "k1"

// Login shapes the next sign-ins.
type Login struct {
	Claims    map[string]any // added to the ID token; sub defaults to "user-1"
	UserInfo  map[string]any // served at /userinfo; sub defaults to the ID token's
	Edit      func(claims map[string]any)
	Sign      func(claims []byte) string // replaces the provider's signature, for forgeries
	NoIDToken bool
	Error     string // /authorize redirects back with error=Error
}

// TokenRequest records how a client called /token.
type TokenRequest struct {
	BasicAuth bool
	Form      url.Values
}

type Server struct {
	URL          string // http://localhost:PORT
	ClientID     string
	ClientSecret string // empty for a public client
	Key          *rsa.PrivateKey

	srv  *httptest.Server
	keys *oidctest.Server

	mu       sync.Mutex
	login    Login
	issuer   string
	down     bool
	codes    map[string]*grant
	access   map[string]map[string]any
	requests []TokenRequest
	errs     []string
}

type grant struct {
	clientID, redirect, challenge, nonce string
	login                                Login
}

// Start runs a provider on localhost, so that its cookies stay apart from a
// broker on 127.0.0.1.
func Start(clientID, clientSecret string) *Server {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	s := &Server{ClientID: clientID, ClientSecret: clientSecret, Key: key,
		codes: map[string]*grant{}, access: map[string]map[string]any{}}
	s.keys = &oidctest.Server{PublicKeys: []oidctest.PublicKey{{PublicKey: key.Public(), KeyID: KeyID, Algorithm: oidc.RS256}}}
	s.srv = httptest.NewServer(s)
	_, port, _ := net.SplitHostPort(s.srv.Listener.Addr().String())
	s.URL = "http://localhost:" + port
	return s
}

func (s *Server) Close() { s.srv.Close() }

// Next sets what the following sign-ins return.
func (s *Server) Next(l Login) {
	s.mu.Lock()
	s.login = l
	s.mu.Unlock()
}

// SetIssuer makes discovery report another issuer ("" = URL).
func (s *Server) SetIssuer(iss string) {
	s.mu.Lock()
	s.issuer = iss
	s.mu.Unlock()
}

// SetDown makes every endpoint answer 503.
func (s *Server) SetDown(down bool) {
	s.mu.Lock()
	s.down = down
	s.mu.Unlock()
}

func (s *Server) TokenRequests() []TokenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]TokenRequest(nil), s.requests...)
}

// Errors lists the requests the provider refused, and why.
func (s *Server) Errors() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.errs...)
}

// SignWith signs claims with key under the provider's key ID.
func SignWith(key crypto.PrivateKey, claims []byte) string {
	return oidctest.SignIDToken(key, KeyID, oidc.RS256, string(claims))
}

func (s *Server) refuse(w http.ResponseWriter, code int, format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	s.mu.Lock()
	s.errs = append(s.errs, msg)
	s.mu.Unlock()
	http.Error(w, msg, code)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	down, iss := s.down, s.issuer
	s.mu.Unlock()
	if down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		if iss == "" {
			iss = s.URL
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss, "authorization_endpoint": s.URL + "/authorize", "token_endpoint": s.URL + "/token",
			"userinfo_endpoint": s.URL + "/userinfo", "jwks_uri": s.URL + "/keys",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case "/keys":
		s.keys.ServeHTTP(w, r)
	case "/authorize":
		s.authorize(w, r)
	case "/token":
		s.token(w, r)
	case "/userinfo":
		s.userinfo(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch {
	case q.Get("client_id") != s.ClientID:
		s.refuse(w, 400, "authorize: unknown client_id %q", q.Get("client_id"))
		return
	case q.Get("response_type") != "code":
		s.refuse(w, 400, "authorize: response_type %q", q.Get("response_type"))
		return
	case !strings.Contains(" "+q.Get("scope")+" ", " openid "):
		s.refuse(w, 400, "authorize: scope %q lacks openid", q.Get("scope"))
		return
	case q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
		s.refuse(w, 400, "authorize: no S256 code challenge")
		return
	case q.Get("state") == "" || q.Get("nonce") == "":
		s.refuse(w, 400, "authorize: state and nonce are required")
		return
	}
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || back.Host == "" {
		s.refuse(w, 400, "authorize: bad redirect_uri")
		return
	}
	s.mu.Lock()
	l := s.login
	v := url.Values{"state": {q.Get("state")}}
	if l.Error != "" {
		v.Set("error", l.Error)
		v.Set("error_description", "<b>call 555-0100</b>")
	} else {
		code := rand.Text()
		s.codes[code] = &grant{clientID: s.ClientID, redirect: back.String(), challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), login: l}
		v.Set("code", code)
	}
	s.mu.Unlock()
	back.RawQuery = v.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.refuse(w, 405, "token: method %s", r.Method)
		return
	}
	r.ParseForm()
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	s.mu.Lock()
	s.requests = append(s.requests, TokenRequest{BasicAuth: basic, Form: r.PostForm})
	g := s.codes[r.PostForm.Get("code")]
	delete(s.codes, r.PostForm.Get("code"))
	s.mu.Unlock()
	switch {
	case id != s.ClientID || secret != s.ClientSecret:
		s.refuse(w, 401, "token: bad client authentication (id %q)", id)
		return
	case g == nil:
		s.refuse(w, 400, "token: unknown or used code")
		return
	case r.PostForm.Get("redirect_uri") != g.redirect:
		s.refuse(w, 400, "token: redirect_uri mismatch")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		s.refuse(w, 400, "token: PKCE verifier does not match")
		return
	}
	now := time.Now()
	claims := map[string]any{"iss": s.URL, "aud": s.ClientID, "sub": "user-1", "nonce": g.nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	maps.Copy(claims, g.login.Claims)
	if g.login.Edit != nil {
		g.login.Edit(claims)
	}
	raw, _ := json.Marshal(claims)
	idToken := SignWith(s.Key, raw)
	if g.login.Sign != nil {
		idToken = g.login.Sign(raw)
	}
	info := map[string]any{"sub": claims["sub"]}
	maps.Copy(info, g.login.UserInfo)
	access := rand.Text()
	s.mu.Lock()
	s.access[access] = info
	s.mu.Unlock()
	resp := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300}
	if !g.login.NoIDToken {
		resp["id_token"] = idToken
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	info, ok := s.access[tok]
	s.mu.Unlock()
	if !ok {
		s.refuse(w, 401, "userinfo: unknown access token")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}
