package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tbshfr/gh-appauth/internal/api"
)

const (
	minCachedLife   = 10 * time.Minute
	minFallbackLife = time.Minute
)

type brokerClient struct {
	cfg  *Config
	http *http.Client
}

// brokerError is a definitive answer from the broker (4xx); no retry and no
// fallback to cached tokens, so revocation takes effect.
type brokerError struct {
	Status int
	Msg    string
}

func (e *brokerError) Error() string { return e.Msg }

func tlsConfig(cfg *Config) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s: no certificates found", cfg.CAFile)
		}
		tc.RootCAs = pool
	}
	if cfg.Fingerprint != "" {
		want := cfg.Fingerprint
		// Pinning replaces chain and hostname checks with an exact match on
		// the broker's certificate, which is stricter than CA validation.
		// This is how self-signed brokers are trusted.
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("broker presented no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(got[:]) != want {
				return fmt.Errorf("broker certificate fingerprint %s does not match the pinned %s", colonHex(got[:]), colonHex(mustHex(want)))
			}
			return nil
		}
	}
	return tc, nil
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func newBrokerClient(cfg *Config) (*brokerClient, error) {
	tc, err := tlsConfig(cfg)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     tc,
	}
	return &brokerClient{cfg: cfg, http: &http.Client{Transport: tr, Timeout: 15 * time.Second}}, nil
}

// do performs one broker request, retrying once on connection errors or 5xx.
func (bc *brokerClient) do(method, path string, body, out any) (*http.Response, error) {
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	url := strings.TrimRight(bc.cfg.Broker, "/") + path
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+bc.cfg.Secret)
		req.Header.Set("User-Agent", "gh-appauth")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := bc.http.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("broker %s unreachable: %v", bc.cfg.Broker, scrub(err, bc.cfg.Secret))
			var cv *tls.CertificateVerificationError
			if errors.As(err, &cv) || strings.Contains(err.Error(), "fingerprint") {
				return nil, lastErr // retrying a TLS failure won't help
			}
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("broker %s error %d: %s", bc.cfg.Broker, resp.StatusCode, errMsg(b))
			continue
		}
		if resp.StatusCode >= 400 {
			return resp, &brokerError{Status: resp.StatusCode, Msg: errMsg(b)}
		}
		if out != nil && len(b) > 0 {
			if err := json.Unmarshal(b, out); err != nil {
				return resp, fmt.Errorf("broker returned invalid JSON: %v", err)
			}
		}
		return resp, nil
	}
	return nil, lastErr
}

func errMsg(b []byte) string {
	var e api.Error
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		return e.Error
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func scrub(err error, secret string) string {
	s := err.Error()
	if secret != "" {
		s = strings.ReplaceAll(s, secret, "<secret>")
	}
	return s
}

func (bc *brokerClient) whoami() (*api.WhoAmI, *http.Response, error) {
	var w api.WhoAmI
	resp, err := bc.do("GET", "/v1/whoami", nil, &w)
	return &w, resp, err
}

func (bc *brokerClient) fetchToken(repoName string, perms map[string]string) (*api.TokenResponse, error) {
	var t api.TokenResponse
	_, err := bc.do("POST", "/v1/token", api.TokenRequest{Repository: repoName, Permissions: perms}, &t)
	if err != nil {
		return nil, err
	}
	if t.Token == "" {
		return nil, errors.New("broker returned no token")
	}
	return &t, nil
}

func (bc *brokerClient) invalidate(token string) error {
	_, err := bc.do("POST", "/v1/invalidate", api.InvalidateRequest{Token: token}, nil)
	return err
}

// ---- local token cache ----

func cacheDir() (string, error) {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "gh-appauth"), nil
	}
	if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
		return filepath.Join(d, "gh-appauth"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".cache", "gh-appauth"), nil
}

func permString(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+p[k])
	}
	return strings.Join(parts, ",")
}

func cacheFile(cfg *Config, repoName string, perms map[string]string) (string, error) {
	d, err := cacheDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(strings.TrimRight(cfg.Broker, "/") + "|" + strings.ToLower(repoName) + "|" + permString(perms)))
	return filepath.Join(d, hex.EncodeToString(sum[:])+".json"), nil
}

func readCached(path string) *api.TokenResponse {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var t api.TokenResponse
	if json.Unmarshal(b, &t) != nil || t.Token == "" {
		return nil
	}
	return &t
}

func writeCached(path string, t *api.TokenResponse) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Dir(path), 0o700)
	b, _ := json.Marshal(t)
	return writeFileAtomic(path, b)
}

// eraseCached removes every cached token for repoName (any permission set),
// and returns the tokens that were removed.
func eraseCached(repoName string) []string {
	d, err := cacheDir()
	if err != nil {
		return nil
	}
	entries, _ := os.ReadDir(d)
	var out []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(d, e.Name())
		if t := readCached(p); t != nil && strings.EqualFold(t.Repository, repoName) {
			os.Remove(p)
			out = append(out, t.Token)
		}
	}
	return out
}

func clearCache() (int, error) {
	d, err := cacheDir()
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(d)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".tmp-") {
			if os.Remove(filepath.Join(d, e.Name())) == nil {
				n++
			}
		}
	}
	return n, nil
}

type tokenSource string

const (
	fromCache    tokenSource = "local cache"
	fromBroker   tokenSource = "broker"
	fromFallback tokenSource = "local cache (broker unreachable)"
)

var now = time.Now

// getToken returns a token for repoName, using the local cache when the
// cached token has more than 10 minutes left. If the broker is unreachable
// (not if it refuses), a cached token with at least a minute left is used
// with a warning.
func getToken(cfg *Config, repoName string, perms map[string]string) (*api.TokenResponse, tokenSource, error) {
	path, err := cacheFile(cfg, repoName, perms)
	if err != nil {
		return nil, "", err
	}
	cached := readCached(path)
	if cached != nil && cached.ExpiresAt.After(now().Add(minCachedLife)) {
		return cached, fromCache, nil
	}
	bc, err := newBrokerClient(cfg)
	if err != nil {
		return nil, "", err
	}
	t, err := bc.fetchToken(repoName, perms)
	if err != nil {
		var be *brokerError
		if errors.As(err, &be) {
			os.Remove(path)
			return nil, "", fmt.Errorf("denied for %s: %s", repoName, be.Msg)
		}
		if cached != nil && cached.ExpiresAt.After(now().Add(minFallbackLife)) {
			fmt.Fprintf(os.Stderr, "gh-appauth: warning: %v; using cached token for %s (expires %s)\n",
				err, repoName, cached.ExpiresAt.Local().Format(time.Kitchen))
			return cached, fromFallback, nil
		}
		return nil, "", err
	}
	if err := writeCached(path, t); err != nil {
		fmt.Fprintf(os.Stderr, "gh-appauth: warning: caching token: %v\n", err)
	}
	return t, fromBroker, nil
}
