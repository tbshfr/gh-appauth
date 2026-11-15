package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Config is the client configuration, stored at
// $XDG_CONFIG_HOME/gh-appauth/config.json (mode 0600).
type Config struct {
	Broker       string `json:"broker"`
	Secret       string `json:"secret"`
	CAFile       string `json:"ca_file,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	InsecureHTTP bool   `json:"insecure_http,omitempty"`
	RealGH       string `json:"real_gh,omitempty"`
	Host         string `json:"host,omitempty"`
}

func (c *Config) GitHubHost() string {
	if c.Host == "" {
		return "github.com"
	}
	return strings.ToLower(c.Host)
}

func configDir() (string, error) {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "gh-appauth"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".config", "gh-appauth"), nil
}

func configPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.json"), nil
}

// loadFileConfig reads the config file without env overrides. A missing file
// yields an empty config.
func loadFileConfig() (*Config, error) {
	p, err := configPath()
	if err != nil {
		return nil, err
	}
	c := &Config{}
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users (mode %v); run: chmod 600 %s", p, fi.Mode().Perm(), p)
	}
	if err := json.NewDecoder(f).Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return c, nil
}

// loadConfig returns the effective config: the file plus GH_APPAUTH_*
// environment overrides (handy in containers).
func loadConfig() (*Config, error) {
	c, err := loadFileConfig()
	if err != nil {
		return nil, err
	}
	if v := os.Getenv("GH_APPAUTH_BROKER"); v != "" {
		c.Broker = v
	}
	if v := os.Getenv("GH_APPAUTH_SECRET"); v != "" {
		c.Secret = v
	}
	if v := os.Getenv("GH_APPAUTH_CA_FILE"); v != "" {
		c.CAFile = v
	}
	if v := os.Getenv("GH_APPAUTH_FINGERPRINT"); v != "" {
		c.Fingerprint = v
	}
	if v := os.Getenv("GH_APPAUTH_INSECURE_HTTP"); v == "1" || strings.EqualFold(v, "true") {
		c.InsecureHTTP = true
	}
	if c.Broker == "" || c.Secret == "" {
		return nil, errors.New("not configured; run: gh appauth setup --broker URL")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	u, err := url.Parse(c.Broker)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid broker URL %q", c.Broker)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) && !c.InsecureHTTP {
			return fmt.Errorf("refusing plain http:// to %s: the client secret would cross the network unencrypted (use https, or pass --insecure-http if you accept that)", u.Host)
		}
	default:
		return fmt.Errorf("broker URL must be https:// (got %q)", c.Broker)
	}
	if c.Fingerprint != "" {
		fp, err := normalizeFingerprint(c.Fingerprint)
		if err != nil {
			return err
		}
		c.Fingerprint = fp
	}
	return nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsLoopback()
}

// normalizeFingerprint accepts "AB:CD:..." or plain hex, optionally prefixed
// with "sha256:", and returns lowercase hex.
func normalizeFingerprint(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.NewReplacer(":", "", " ", "").Replace(s)
	if len(s) != 64 {
		return "", fmt.Errorf("fingerprint must be a SHA-256 (64 hex digits), got %d digits", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", errors.New("fingerprint must be hex")
	}
	return s, nil
}

func saveConfig(c *Config) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is readable by other users (mode %v); fix with chmod 600 first", p, fi.Mode().Perm())
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeFileAtomic(p, append(b, '\n'))
}

// writeFileAtomic writes a 0600 file via a temp file and rename.
func writeFileAtomic(p string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
