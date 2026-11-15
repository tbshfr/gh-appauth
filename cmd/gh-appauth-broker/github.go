package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ghClient struct {
	api  string
	http *http.Client
	now  func() time.Time
}

type ghError struct {
	Status  int
	Message string
}

func (e *ghError) Error() string {
	return fmt.Sprintf("GitHub API %d: %s", e.Status, e.Message)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// appJWT signs a GitHub App JWT. iat is backdated 60s to absorb clock skew;
// exp stays under GitHub's 10 minute maximum.
func (g *ghClient) appJWT(app *appState) (string, error) {
	now := g.now()
	hdr := b64([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]int64{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": app.AppID,
	})
	signing := hdr + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, app.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

func (g *ghClient) do(ctx context.Context, method, p, auth string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.api, "/")+p, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "gh-appauth-broker")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var m struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &m)
		if m.Message == "" {
			m.Message = http.StatusText(resp.StatusCode)
		}
		return &ghError{Status: resp.StatusCode, Message: m.Message}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode GitHub response: %w", err)
		}
	}
	return nil
}

// installationID looks up the installation of app that covers owner/name.
// repoFull must already be validated (it is spliced into the path).
func (g *ghClient) installationID(ctx context.Context, app *appState, repoFull string) (int64, error) {
	jwt, err := g.appJWT(app)
	if err != nil {
		return 0, err
	}
	var out struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	if err := g.do(ctx, "GET", "/repos/"+repoFull+"/installation", jwt, nil, &out); err != nil {
		return 0, err
	}
	// The ID is cached per owner and used for every repo of that owner, so
	// it must really be that owner's installation.
	if owner, _, _ := strings.Cut(repoFull, "/"); !strings.EqualFold(out.Account.Login, owner) {
		return 0, &ghError{Status: 404, Message: fmt.Sprintf("installation %d belongs to %q, not %q", out.ID, out.Account.Login, owner)}
	}
	return out.ID, nil
}

type mintResult struct {
	Token       string            `json:"token"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Permissions map[string]string `json:"permissions"`
}

func (g *ghClient) mint(ctx context.Context, app *appState, instID int64, repoName string, perms map[string]string) (*mintResult, error) {
	jwt, err := g.appJWT(app)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"repositories": []string{repoName}}
	if len(perms) > 0 {
		body["permissions"] = perms
	}
	var out mintResult
	if err := g.do(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", instID), jwt, body, &out); err != nil {
		return nil, err
	}
	if out.Token == "" {
		return nil, fmt.Errorf("GitHub returned no token")
	}
	return &out, nil
}

func (g *ghClient) appSlug(ctx context.Context, app *appState) (string, error) {
	jwt, err := g.appJWT(app)
	if err != nil {
		return "", err
	}
	var out struct {
		Slug string `json:"slug"`
	}
	if err := g.do(ctx, "GET", "/app", jwt, nil, &out); err != nil {
		return "", err
	}
	return out.Slug, nil
}

func (g *ghClient) botUserID(ctx context.Context, slug, token string) (int64, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	if err := g.do(ctx, "GET", "/users/"+url.PathEscape(slug+"[bot]"), token, nil, &out); err != nil {
		return 0, err
	}
	return out.ID, nil
}

// revoke invalidates an installation token at GitHub (DELETE /installation/token
// authenticates with the token itself).
func (g *ghClient) revoke(ctx context.Context, token string) error {
	err := g.do(ctx, "DELETE", "/installation/token", token, nil, nil)
	if e, ok := err.(*ghError); ok && e.Status == 401 {
		return nil // already expired or revoked
	}
	return err
}
