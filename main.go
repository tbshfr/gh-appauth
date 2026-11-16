// Command gh-appauth is a gh CLI extension that gets GitHub App installation
// tokens from a gh-appauth broker and wires them into git and gh.
package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tbshfr/gh-appauth/internal/api"
	"github.com/tbshfr/gh-appauth/internal/buildinfo"
	"github.com/tbshfr/gh-appauth/internal/repo"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

const usage = `gh appauth: GitHub App tokens for git and gh, from a gh-appauth broker

Usage:
  gh appauth setup --broker URL [--fingerprint SHA256] [--ca-file F] [--insecure-http]
                                    save broker settings (secret read from stdin)
  gh appauth status                 show broker, client, grants and current repo
  gh appauth token [OWNER/REPO] [--perm k=v]... [--json]
                                    print a token (default repo: origin of cwd)
  gh appauth repos OWNER [--no-archived] [--json]
                                    list OWNER's repos this client can get tokens for
  gh appauth git-setup              configure git to use this credential helper
  gh appauth identity               set user.name/email in this repo to the App bot
                                    (automatic in repos without their own identity)
  gh appauth shim DIR               install a gh wrapper in DIR (put DIR first in PATH)
  gh appauth exec [--repo R] -- CMD...
                                    run CMD with GH_TOKEN/GITHUB_TOKEN for R
  gh appauth cache clear            delete locally cached tokens
  gh appauth version                print the extension version

Internal:
  gh appauth git-credential get|erase|store
  gh appauth git-hook post-checkout OLD NEW FLAG
  gh appauth gh-shim ARGS...

Environment: GH_APPAUTH_BROKER, GH_APPAUTH_SECRET, GH_APPAUTH_CA_FILE,
GH_APPAUTH_FINGERPRINT and GH_APPAUTH_INSECURE_HTTP=1 override the config file;
GH_APPAUTH_REPO sets the repo for the gh shim and exec when the command doesn't
name one and GH_REPO isn't set.
`

// exitCode is returned by commands that run a child process.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func main() {
	err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	var ec exitCode
	switch {
	case err == nil:
	case errors.As(err, &ec):
		os.Exit(int(ec))
	default:
		fmt.Fprintf(os.Stderr, "gh-appauth: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitCode(2)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "setup":
		return cmdSetup(rest, stdin, stdout, stderr)
	case "status":
		return cmdStatus(stdout)
	case "token":
		return cmdToken(rest, stdout)
	case "repos":
		return cmdRepos(rest, stdout)
	case "git-credential":
		return cmdGitCredential(rest, stdin, stdout, stderr)
	case "git-setup":
		return cmdGitSetup(stdout, stderr)
	case "identity":
		return cmdIdentity(stdout)
	case "git-hook":
		return cmdGitHook(rest, stderr)
	case "shim":
		return cmdShim(rest, stdout)
	case "gh-shim":
		return cmdGHShim(rest, stdin, stdout, stderr)
	case "exec":
		return cmdExec(rest, stdin, stdout, stderr)
	case "cache":
		if len(rest) == 1 && rest[0] == "clear" {
			n, err := clearCache()
			if err == nil {
				fmt.Fprintf(stdout, "removed %d cached token(s)\n", n)
			}
			return err
		}
		return errors.New("usage: gh appauth cache clear")
	case "version", "--version":
		fmt.Fprintln(stdout, "gh-appauth", buildinfo.Resolve(version))
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return exitCode(2)
	}
}

// ---- setup ----

func cmdSetup(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	broker := fs.String("broker", "", "broker URL, e.g. https://broker.lan:8443")
	fp := fs.String("fingerprint", "", "pin the broker's TLS certificate SHA-256 fingerprint (self-signed brokers)")
	caFile := fs.String("ca-file", "", "extra CA certificate PEM to trust for the broker")
	insecure := fs.Bool("insecure-http", false, "allow plain http:// to a non-loopback broker (secret travels unencrypted)")
	host := fs.String("host", "", "GitHub host (default github.com)")
	if err := fs.Parse(args); err != nil {
		return exitCode(2)
	}
	old, err := loadFileConfig()
	if err != nil {
		return err
	}
	cfg := &Config{Broker: strings.TrimRight(*broker, "/"), CAFile: *caFile, Fingerprint: *fp, InsecureHTTP: *insecure, Host: *host, RealGH: old.RealGH}
	if cfg.Broker == "" {
		return errors.New("--broker is required")
	}
	if cfg.CAFile != "" {
		if abs, err := filepath.Abs(cfg.CAFile); err == nil {
			cfg.CAFile = abs
		}
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	secret, err := readSecret(stdin, stderr)
	if err != nil {
		return err
	}
	cfg.Secret = secret

	bc, err := newBrokerClient(cfg)
	if err != nil {
		return err
	}
	who, _, err := bc.whoami()
	if err != nil {
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) || strings.Contains(err.Error(), "certificate") {
			if got, ferr := peerFingerprint(cfg.Broker); ferr == nil {
				return fmt.Errorf("%v\n\nThe broker's certificate isn't trusted. Its SHA-256 fingerprint is:\n  %s\nIf this matches the fingerprint the broker printed at startup (also shown on the admin UI's Settings page and by `gh-appauth-broker fingerprint`), run setup again with:\n  --fingerprint %s", err, got, got)
			}
		}
		return fmt.Errorf("checking secret with broker: %v", err)
	}
	if err := saveConfig(cfg); err != nil {
		return err
	}
	p, _ := configPath()
	fmt.Fprintf(stdout, "Authenticated as client %q (from %s). Saved %s\n", who.Client, who.IP, p)
	for _, g := range who.Grants {
		fmt.Fprintf(stdout, "  %s → %s %s\n", g.App, strings.Join(g.Repos, ", "), permOrAll(g.Permissions))
	}
	fmt.Fprintln(stdout, "Next: gh appauth git-setup")
	return nil
}

func permOrAll(p map[string]string) string {
	if len(p) == 0 {
		return "(all installation permissions)"
	}
	return "(" + permString(p) + ")"
}

func readSecret(stdin io.Reader, stderr io.Writer) (string, error) {
	f, isFile := stdin.(*os.File)
	tty := isFile && isTerminal(f)
	if tty {
		fmt.Fprint(stderr, "Client secret: ")
		if err := sttyCmd(f, "-echo"); err == nil {
			defer func() { sttyCmd(f, "echo"); fmt.Fprintln(stderr) }()
		}
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", errors.New("reading secret from stdin: no input")
	}
	s := strings.TrimSpace(line)
	if s == "" {
		return "", errors.New("empty secret")
	}
	return s, nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func sttyCmd(f *os.File, arg string) error {
	c := exec.Command("stty", arg)
	c.Stdin = f
	return c.Run()
}

// peerFingerprint connects without verification only to read and show the
// certificate's fingerprint; nothing is sent over this connection.
func peerFingerprint(broker string) (string, error) {
	u, err := url.Parse(broker)
	if err != nil {
		return "", err
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no certificate")
	}
	sum := sha256.Sum256(certs[0].Raw)
	return colonHex(sum[:]), nil
}

// ---- status ----

func cmdStatus(stdout io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	p, _ := configPath()
	fmt.Fprintf(stdout, "Config:  %s\n", p)
	fmt.Fprintf(stdout, "Broker:  %s\n", cfg.Broker)
	switch {
	case cfg.Fingerprint != "":
		fmt.Fprintf(stdout, "Trust:   pinned certificate %s\n", colonHex(mustHex(cfg.Fingerprint)))
	case cfg.CAFile != "":
		fmt.Fprintf(stdout, "Trust:   system CAs + %s\n", cfg.CAFile)
	case strings.HasPrefix(cfg.Broker, "http://"):
		fmt.Fprintf(stdout, "Trust:   NONE (plain HTTP)\n")
	default:
		fmt.Fprintf(stdout, "Trust:   system CAs\n")
	}
	bc, err := newBrokerClient(cfg)
	if err != nil {
		return err
	}
	start := time.Now()
	who, resp, err := bc.whoami()
	if err != nil {
		fmt.Fprintf(stdout, "Status:  UNREACHABLE or refused: %v\n", err)
	} else {
		fmt.Fprintf(stdout, "Status:  reachable (%d ms)\n", time.Since(start).Milliseconds())
		if resp != nil && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			c := resp.TLS.PeerCertificates[0]
			fmt.Fprintf(stdout, "TLS:     %s, subject %q, expires %s\n", tls.VersionName(resp.TLS.Version), c.Subject.String(), c.NotAfter.Format("2006-01-02"))
		}
		fmt.Fprintf(stdout, "Client:  %s (seen from %s)\n", who.Client, who.IP)
		fmt.Fprintln(stdout, "Grants:")
		for _, g := range who.Grants {
			fmt.Fprintf(stdout, "  %s → %s %s\n", g.App, strings.Join(g.Repos, ", "), permOrAll(g.Permissions))
		}
		if len(who.Grants) == 0 {
			fmt.Fprintln(stdout, "  (none)")
		}
	}
	r, rerr := currentRepo(cfg)
	if rerr != nil {
		fmt.Fprintf(stdout, "Repo:    (none: %v)\n", rerr)
		return nil
	}
	fmt.Fprintf(stdout, "Repo:    %s\n", r)
	t, src, err := getToken(cfg, r, nil)
	if err != nil {
		fmt.Fprintf(stdout, "  token: %v\n", err)
		return nil
	}
	fmt.Fprintf(stdout, "  app:         %s\n", t.App)
	if t.BotName != "" {
		fmt.Fprintf(stdout, "  bot:         %s <%s>\n", t.BotName, t.BotEmail)
	}
	fmt.Fprintf(stdout, "  expires:     %s (%s)\n", t.ExpiresAt.Local().Format("15:04:05"), time.Until(t.ExpiresAt).Round(time.Minute))
	fmt.Fprintf(stdout, "  permissions: %s\n", permString(t.Permissions))
	fmt.Fprintf(stdout, "  source:      %s\n", src)
	return nil
}

// ---- token ----

type permFlags map[string]string

func (p permFlags) String() string { return permString(p) }
func (p permFlags) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" {
		return fmt.Errorf("--perm wants name=level, got %q", s)
	}
	switch v {
	case "read", "write", "admin":
	default:
		return fmt.Errorf("--perm %s: level must be read, write or admin", k)
	}
	p[k] = v
	return nil
}

func cmdToken(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	perms := permFlags{}
	fs.Var(perms, "perm", "narrow permissions, e.g. --perm contents=read (repeatable)")
	asJSON := fs.Bool("json", false, "print the full JSON response")
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	var r string
	switch len(positional) {
	case 0:
		if r, err = currentRepo(cfg); err != nil {
			return err
		}
	case 1:
		if r, err = repo.ParseHost(positional[0], cfg.GitHubHost()); err != nil {
			return err
		}
	default:
		return errors.New("usage: gh appauth token [OWNER/REPO] [--perm k=v]... [--json]")
	}
	t, _, err := getToken(cfg, r, perms)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(t)
	}
	fmt.Fprintln(stdout, t.Token)
	return nil
}

// parseInterspersed parses fs from args and returns the positional arguments,
// which may come before, between or after the flags.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, exitCode(2)
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return positional, nil
}

// ---- repos ----

func cmdRepos(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("repos", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the full JSON response")
	noArchived := fs.Bool("no-archived", false, "omit archived repositories")
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: gh appauth repos OWNER [--no-archived] [--json]")
	}
	owner := positional[0]
	if !repo.ValidOwner(owner) {
		return fmt.Errorf("invalid owner %q", owner)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	bc, err := newBrokerClient(cfg)
	if err != nil {
		return err
	}
	list, err := bc.repos(owner)
	if err != nil {
		return err
	}
	if *noArchived {
		list.Repos = slices.DeleteFunc(list.Repos, func(r api.Repo) bool { return r.Archived })
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(list)
	}
	for _, r := range list.Repos {
		info := "public"
		if r.Private {
			info = "private"
		}
		if r.Archived {
			info += ", archived"
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", r.FullName, r.DefaultBranch, info, r.App)
	}
	return nil
}
