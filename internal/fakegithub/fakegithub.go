// Package fakegithub is an in-process stand-in for the parts of the GitHub
// REST API the broker uses. It verifies App JWTs like GitHub does, so tests
// catch signing mistakes.
package fakegithub

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Installation struct {
	ID          int64
	Owner       string
	Repos       []string // repo names (without owner); nil = all repositories
	Permissions map[string]string
}

type App struct {
	ID            int64
	Slug          string
	BotID         int64
	PublicKey     *rsa.PublicKey
	Installations []*Installation
}

type Call struct {
	Method string
	Path   string
	Body   string
}

type issued struct {
	installation int64
	expires      time.Time
}

type Server struct {
	mu           sync.Mutex
	apps         map[int64]*App
	calls        []Call
	tokens       map[string]issued
	jwtErrors    []string
	n            int
	FailIdentity bool
	// Redirects maps a lowercase request path to the path it 301s to, the
	// way GitHub answers for renamed or transferred repositories.
	Redirects     map[string]string
	TokenLifetime time.Duration
}

func New(apps ...*App) *Server {
	s := &Server{apps: map[int64]*App{}, tokens: map[string]issued{}, TokenLifetime: time.Hour}
	for _, a := range apps {
		s.apps[a.ID] = a
	}
	return s
}

func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// CallCount counts recorded calls whose "METHOD path" starts with prefix.
func (s *Server) CallCount(prefix string) int {
	n := 0
	for _, c := range s.Calls() {
		if strings.HasPrefix(c.Method+" "+c.Path, prefix) {
			n++
		}
	}
	return n
}

func (s *Server) JWTErrors() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.jwtErrors...)
}

func (s *Server) TokenValid(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tok]
	return ok && time.Now().Before(t.expires)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func msg(w http.ResponseWriter, code int, m string) {
	writeJSON(w, code, map[string]string{"message": m})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	path := strings.ToLower(r.URL.Path)
	s.mu.Lock()
	s.calls = append(s.calls, Call{Method: r.Method, Path: path, Body: string(body)})
	s.mu.Unlock()

	if to, ok := s.Redirects[path]; ok {
		http.Redirect(w, r, to, http.StatusMovedPermanently)
		return
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case r.Method == "GET" && path == "/app":
		app := s.authApp(w, r)
		if app == nil {
			return
		}
		writeJSON(w, 200, map[string]any{"id": app.ID, "slug": app.Slug, "name": app.Slug})

	case r.Method == "GET" && len(parts) == 4 && parts[0] == "repos" && parts[3] == "installation":
		app := s.authApp(w, r)
		if app == nil {
			return
		}
		inst := app.find(parts[1])
		if inst == nil || !inst.has(parts[2]) {
			msg(w, 404, "Not Found")
			return
		}
		writeJSON(w, 200, map[string]any{"id": inst.ID, "account": map[string]any{"login": inst.Owner}})

	case r.Method == "POST" && len(parts) == 4 && parts[0] == "app" && parts[1] == "installations" && parts[3] == "access_tokens":
		app := s.authApp(w, r)
		if app == nil {
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			msg(w, 415, "Unsupported Media Type")
			return
		}
		id, _ := strconv.ParseInt(parts[2], 10, 64)
		var inst *Installation
		for _, in := range app.Installations {
			if in.ID == id {
				inst = in
			}
		}
		if inst == nil {
			msg(w, 404, "Not Found")
			return
		}
		var req struct {
			Repositories []string          `json:"repositories"`
			Permissions  map[string]string `json:"permissions"`
		}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				msg(w, 400, "Problems parsing JSON")
				return
			}
		}
		for _, rn := range req.Repositories {
			if !inst.has(strings.ToLower(rn)) {
				msg(w, 422, "There is at least one repository that does not exist or is not accessible to the parent installation.")
				return
			}
		}
		perms := inst.Permissions
		if req.Permissions != nil {
			for k, v := range req.Permissions {
				if level(inst.Permissions[k]) < level(v) {
					msg(w, 422, fmt.Sprintf("The permissions requested are not granted to this installation: %s", k))
					return
				}
			}
			perms = req.Permissions
		}
		s.mu.Lock()
		s.n++
		tok := fmt.Sprintf("ghs_fake%d_%d", s.n, time.Now().UnixNano())
		exp := time.Now().Add(s.TokenLifetime).UTC().Truncate(time.Second)
		s.tokens[tok] = issued{installation: inst.ID, expires: exp}
		s.mu.Unlock()
		writeJSON(w, 201, map[string]any{"token": tok, "expires_at": exp.Format(time.RFC3339), "permissions": perms, "repository_selection": "selected"})

	case r.Method == "GET" && len(parts) == 2 && parts[0] == "users":
		if s.FailIdentity {
			msg(w, 500, "boom")
			return
		}
		for _, a := range s.apps {
			if parts[1] == strings.ToLower(a.Slug)+"[bot]" {
				writeJSON(w, 200, map[string]any{"login": a.Slug + "[bot]", "id": a.BotID, "type": "Bot"})
				return
			}
		}
		msg(w, 404, "Not Found")

	case r.Method == "DELETE" && path == "/installation/token":
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tok = strings.TrimPrefix(tok, "token ")
		s.mu.Lock()
		_, ok := s.tokens[tok]
		delete(s.tokens, tok)
		s.mu.Unlock()
		if !ok {
			msg(w, 401, "Bad credentials")
			return
		}
		w.WriteHeader(204)

	default:
		msg(w, 404, "Not Found")
	}
}

func level(s string) int {
	switch s {
	case "read":
		return 1
	case "write":
		return 2
	case "admin":
		return 3
	}
	return 0
}

func (a *App) find(owner string) *Installation {
	for _, in := range a.Installations {
		if strings.EqualFold(in.Owner, owner) {
			return in
		}
	}
	return nil
}

func (in *Installation) has(name string) bool {
	if in.Repos == nil {
		return true
	}
	for _, r := range in.Repos {
		if strings.EqualFold(r, name) {
			return true
		}
	}
	return false
}

func (s *Server) jwtFail(w http.ResponseWriter, why string) {
	s.mu.Lock()
	s.jwtErrors = append(s.jwtErrors, why)
	s.mu.Unlock()
	msg(w, 401, "A JSON web token could not be decoded: "+why)
}

// authApp verifies the RS256 App JWT the way GitHub does: valid signature,
// numeric iss naming a known app, and a lifetime of at most 10 minutes.
func (s *Server) authApp(w http.ResponseWriter, r *http.Request) *App {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		s.jwtFail(w, "missing bearer")
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(h, "Bearer "), ".")
	if len(parts) != 3 {
		s.jwtFail(w, "not a JWT")
		return nil
	}
	hdrRaw, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payRaw, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		s.jwtFail(w, "bad base64")
		return nil
	}
	var hdr struct{ Alg, Typ string }
	if json.Unmarshal(hdrRaw, &hdr) != nil || hdr.Alg != "RS256" {
		s.jwtFail(w, "alg must be RS256")
		return nil
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payRaw, &claims) != nil {
		s.jwtFail(w, "bad claims")
		return nil
	}
	var iss, iat, exp int64
	if json.Unmarshal(claims["iss"], &iss) != nil {
		s.jwtFail(w, "iss must be a number")
		return nil
	}
	if json.Unmarshal(claims["iat"], &iat) != nil || json.Unmarshal(claims["exp"], &exp) != nil {
		s.jwtFail(w, "iat/exp missing")
		return nil
	}
	app := s.apps[iss]
	if app == nil {
		s.jwtFail(w, "unknown app")
		return nil
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(app.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		s.jwtFail(w, "bad signature")
		return nil
	}
	now := time.Now().Unix()
	if exp-iat > 600 {
		s.jwtFail(w, "exp too far in the future")
		return nil
	}
	if iat > now+60 || exp <= now {
		s.jwtFail(w, "'Issued at' claim or expiration time is invalid")
		return nil
	}
	return app
}
