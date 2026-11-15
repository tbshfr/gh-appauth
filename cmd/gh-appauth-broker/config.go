package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func validateName(kind, s string) error {
	if !nameRE.MatchString(s) {
		return fmt.Errorf("%s name %q: use 1-64 letters, digits, '.', '_' or '-'", kind, s)
	}
	return nil
}

func parsePrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a PKCS#1 or PKCS#8 private key: %v", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not RSA")
	}
	return rk, nil
}

func validatePattern(p string) error {
	if strings.Count(p, "/") != 1 {
		return fmt.Errorf("repo pattern %q must look like owner/repo", p)
	}
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return fmt.Errorf("repo pattern %q must look like owner/repo", p)
	}
	if _, err := path.Match(p, "x/y"); err != nil {
		return fmt.Errorf("repo pattern %q: %v", p, err)
	}
	return nil
}

var levels = map[string]int{"read": 1, "write": 2, "admin": 3}

var permKeyRE = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)

func validatePerms(p map[string]string) error {
	for k, v := range p {
		if !permKeyRE.MatchString(k) {
			return fmt.Errorf("permission name %q is invalid", k)
		}
		if levels[v] == 0 {
			return fmt.Errorf("permission %s=%q: level must be read, write or admin", k, v)
		}
	}
	return nil
}

func parseCIDRs(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", s)
			}
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func validHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

// ---- runtime snapshot ----

type appState struct {
	Name  string
	AppID int64
	Key   *rsa.PrivateKey
}

type grantState struct {
	App   string
	Repos []string // lowercased glob patterns
	Perms map[string]string
}

type clientState struct {
	Name     string
	CIDRs    []netip.Prefix
	Disabled bool
	Grants   []grantState
}

type secretEntry struct {
	sum    [32]byte
	id     int64
	client *clientState
}

// state is an immutable snapshot of the config. The server swaps it
// atomically so a request always sees one consistent version.
type state struct {
	apps    map[string]*appState
	clients map[string]*clientState
	secrets []secretEntry
}

func buildState(c *ConfigRows) (*state, error) {
	st := &state{apps: map[string]*appState{}, clients: map[string]*clientState{}}
	var errs []string
	for _, a := range c.Apps {
		if a.AppID <= 0 {
			errs = append(errs, fmt.Sprintf("app %s: app_id must be positive", a.Name))
		}
		k, err := parsePrivateKey(a.PrivateKey)
		if err != nil {
			errs = append(errs, fmt.Sprintf("app %s: private key: %v", a.Name, err))
			continue
		}
		st.apps[a.Name] = &appState{Name: a.Name, AppID: a.AppID, Key: k}
	}
	for _, cl := range c.Clients {
		cidrs, err := parseCIDRs(cl.AllowedCIDRs)
		if err != nil {
			errs = append(errs, fmt.Sprintf("client %s: %v", cl.Name, err))
		}
		st.clients[cl.Name] = &clientState{Name: cl.Name, CIDRs: cidrs, Disabled: cl.Disabled}
	}
	seen := map[string]string{}
	for _, s := range c.Secrets {
		cl := st.clients[s.Client]
		if cl == nil {
			continue
		}
		h := strings.ToLower(s.SHA256)
		if !validHash(h) {
			errs = append(errs, fmt.Sprintf("client %s: secret hash is not 64 hex characters", s.Client))
			continue
		}
		if other, dup := seen[h]; dup {
			errs = append(errs, fmt.Sprintf("clients %s and %s share a secret hash", other, s.Client))
			continue
		}
		seen[h] = s.Client
		var e secretEntry
		hex.Decode(e.sum[:], []byte(h))
		e.id, e.client = s.ID, cl
		st.secrets = append(st.secrets, e)
	}
	for _, g := range c.Grants {
		cl := st.clients[g.Client]
		if cl == nil {
			continue
		}
		if st.apps[g.App] == nil {
			errs = append(errs, fmt.Sprintf("client %s: grant uses unknown app %q", g.Client, g.App))
		}
		if len(g.Repos) == 0 {
			errs = append(errs, fmt.Sprintf("client %s: grant for %s has no repos", g.Client, g.App))
		}
		gs := grantState{App: g.App, Perms: g.Permissions}
		for _, p := range g.Repos {
			if err := validatePattern(p); err != nil {
				errs = append(errs, fmt.Sprintf("client %s: %v", g.Client, err))
			}
			gs.Repos = append(gs.Repos, strings.ToLower(p))
		}
		if err := validatePerms(g.Permissions); err != nil {
			errs = append(errs, fmt.Sprintf("client %s: %v", g.Client, err))
		}
		cl.Grants = append(cl.Grants, gs)
	}
	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return st, nil
}

func (cl *clientState) grantFor(repoLower string) *grantState {
	for i := range cl.Grants {
		for _, p := range cl.Grants[i].Repos {
			if ok, _ := path.Match(p, repoLower); ok {
				return &cl.Grants[i]
			}
		}
	}
	return nil
}

func (cl *clientState) ipAllowed(ip netip.Addr) bool {
	if len(cl.CIDRs) == 0 {
		return true
	}
	ip = ip.Unmap()
	for _, p := range cl.CIDRs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// narrow returns the permissions to request from GitHub. A nil result means
// "everything the installation has".
func narrow(grant, req map[string]string) (map[string]string, error) {
	if err := validatePerms(req); err != nil {
		return nil, err
	}
	if len(req) == 0 {
		if len(grant) == 0 {
			return nil, nil
		}
		return grant, nil
	}
	if len(grant) == 0 {
		return req, nil
	}
	for k, v := range req {
		g, ok := grant[k]
		if !ok {
			return nil, fmt.Errorf("permission %q is not in the grant", k)
		}
		if levels[v] > levels[g] {
			return nil, fmt.Errorf("permission %s=%s exceeds the granted %s", k, v, g)
		}
	}
	return req, nil
}

func permString(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k + "=" + p[k])
	}
	return b.String()
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
