// Package repo parses GitHub repository references shared by the broker and
// the gh extension.
package repo

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const DefaultHost = "github.com"

// nameRE is the strict form the broker accepts. It keeps the value safe to
// splice into API URL paths (no "..", no extra slashes, no escapes).
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)

// Valid reports whether s is a strict "owner/repo" name.
func Valid(s string) bool {
	if !nameRE.MatchString(s) {
		return false
	}
	name := s[strings.IndexByte(s, '/')+1:]
	return name != "." && name != ".."
}

// Parse accepts owner/repo, github.com/owner/repo, https URLs, ssh:// URLs and
// scp-style git@github.com:owner/repo, all for github.com.
func Parse(s string) (string, error) { return ParseHost(s, DefaultHost) }

// ParseHost is Parse for a specific GitHub host.
func ParseHost(s, host string) (string, error) {
	orig := s
	s = strings.TrimSpace(s)
	host = strings.ToLower(host)
	var p string
	switch {
	case strings.Contains(s, "://"):
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("invalid repository %q: %v", orig, err)
		}
		if u.Scheme != "https" && u.Scheme != "ssh" && u.Scheme != "http" && u.Scheme != "git" {
			return "", fmt.Errorf("invalid repository %q: unsupported scheme %q", orig, u.Scheme)
		}
		if !strings.EqualFold(u.Hostname(), host) {
			return "", fmt.Errorf("repository %q is not on %s", orig, host)
		}
		p = u.Path
	case strings.HasPrefix(s, "git@") && strings.Contains(s, ":"):
		hp := strings.TrimPrefix(s, "git@")
		i := strings.IndexByte(hp, ':')
		if !strings.EqualFold(hp[:i], host) {
			return "", fmt.Errorf("repository %q is not on %s", orig, host)
		}
		p = hp[i+1:]
	default:
		s = strings.Trim(s, "/")
		parts := strings.Split(s, "/")
		if len(parts) == 3 {
			if !strings.EqualFold(parts[0], host) {
				return "", fmt.Errorf("repository %q is not on %s", orig, host)
			}
			p = parts[1] + "/" + parts[2]
		} else {
			p = s
		}
	}
	p = strings.Trim(p, "/")
	p = strings.TrimSuffix(p, ".git")
	if strings.Count(p, "/") != 1 || !Valid(p) {
		return "", fmt.Errorf("invalid repository %q: want owner/repo", orig)
	}
	return p, nil
}
