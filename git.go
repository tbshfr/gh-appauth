package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tbshfr/gh-appauth/internal/api"
	"github.com/tbshfr/gh-appauth/internal/repo"
)

func gitOut(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// currentRepo returns owner/repo for the current folder's origin remote.
func currentRepo(cfg *Config) (string, error) {
	u, err := gitOut("remote", "get-url", "origin")
	if err != nil {
		return "", errors.New("no origin remote here (not in a git repo?); pass OWNER/REPO")
	}
	return repo.ParseHost(u, cfg.GitHubHost())
}

// ghBaseRepo returns the repo gh itself works on in the current folder, which
// isn't always origin: in a fork cloned by `gh repo clone`, gh targets the
// parent in the upstream remote.
func ghBaseRepo(cfg *Config) (string, error) {
	remotes, err := gitOut("remote", "-v")
	if err != nil {
		return "", errors.New("no git remotes here (not in a git repo?); pass OWNER/REPO")
	}
	resolved, _ := gitOut("config", "--get-regexp", `^remote\..*\.gh-resolved$`)
	return pickBaseRepo(remotes, resolved, cfg.GitHubHost())
}

// pickBaseRepo mirrors gh's choice when it can't prompt (checked against gh
// 2.103). Among the remotes on host, sorted upstream, github, origin, then the
// rest in git's order, the first one marked by `gh repo set-default`
// (remote.NAME.gh-resolved) wins, else the first one. remotesV is the output of
// `git remote -v`, resolvedCfg that of `git config --get-regexp`.
func pickBaseRepo(remotesV, resolvedCfg, host string) (string, error) {
	type remote struct{ name, repo string }
	var remotes []remote
	for line := range strings.Lines(remotesV) {
		f := strings.Fields(line)
		// Partial clones add a fourth field, such as "[blob:none]".
		if len(f) < 3 || f[2] != "(fetch)" {
			continue
		}
		if r, err := repo.ParseHost(f[1], host); err == nil {
			remotes = append(remotes, remote{f[0], r})
		}
	}
	if len(remotes) == 0 {
		return "", fmt.Errorf("no %s remote here; pass OWNER/REPO", host)
	}
	score := map[string]int{"upstream": 3, "github": 2, "origin": 1}
	slices.SortStableFunc(remotes, func(a, b remote) int { return score[b.name] - score[a.name] })

	resolved := map[string]string{}
	for line := range strings.Lines(resolvedCfg) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok {
			resolved[strings.TrimSuffix(strings.TrimPrefix(k, "remote."), ".gh-resolved")] = v
		}
	}
	for _, r := range remotes {
		switch v := resolved[r.name]; v {
		case "":
		case "base":
			return r.repo, nil
		default:
			return repo.ParseHost(v, host)
		}
	}
	return remotes[0].repo, nil
}

// selfPath is the absolute path of this binary. git and the gh shim call it
// directly so they don't go through `gh` (which may itself be the shim).
func selfPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ---- credential helper ----

func readCredential(r io.Reader) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m
}

func cmdGitCredential(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: gh appauth git-credential get|store|erase")
	}
	op := args[0]
	in := readCredential(stdin)
	if op == "store" {
		return nil
	}
	if op != "get" && op != "erase" {
		return nil // unknown operations must be ignored per the protocol
	}
	cfg, err := loadConfig()
	if err != nil {
		if op == "erase" {
			return nil
		}
		fmt.Fprintf(stderr, "gh-appauth: %v\n", err)
		fmt.Fprintln(stdout, "quit=1")
		return exitCode(1)
	}
	if in["protocol"] != "https" || !strings.EqualFold(in["host"], cfg.GitHubHost()) {
		return nil // not ours; let other helpers answer
	}
	if in["path"] == "" {
		if op == "erase" {
			return nil
		}
		fmt.Fprintln(stderr, "gh-appauth: git did not send the repository path; run: gh appauth git-setup (needs credential.useHttpPath)")
		return exitCode(1)
	}
	r, err := repo.ParseHost(in["path"], cfg.GitHubHost())
	if err != nil {
		fmt.Fprintf(stderr, "gh-appauth: %v\n", err)
		return exitCode(1)
	}

	if op == "erase" {
		// git erases a credential after GitHub rejected it: drop it locally
		// and tell the broker so it won't serve it from its cache either.
		removed := eraseCached(r)
		if pw := in["password"]; pw != "" {
			removed = append(removed, pw)
		}
		if len(removed) > 0 {
			if bc, err := newBrokerClient(cfg); err == nil {
				seen := map[string]bool{}
				for _, t := range removed {
					if !seen[t] {
						seen[t] = true
						_ = bc.invalidate(t)
					}
				}
			}
		}
		return nil
	}

	t, _, err := getToken(cfg, r, nil)
	if err != nil {
		fmt.Fprintf(stderr, "gh-appauth: %v\n", err)
		// quit=1 stops git from falling back to an interactive prompt,
		// which would hang an agent.
		fmt.Fprintln(stdout, "quit=1")
		return exitCode(1)
	}
	fmt.Fprintf(stdout, "username=x-access-token\npassword=%s\npassword_expiry_utc=%d\n", t.Token, t.ExpiresAt.Unix())
	maybeSetIdentity(cfg, r, t, stderr)
	return nil
}

// ---- git-setup ----

func cmdGitSetup(stdout, stderr io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	self, err := selfPath()
	if err != nil {
		return err
	}
	section := "credential.https://" + cfg.GitHubHost()
	// --unset-all fails with status 5 when nothing is set; that's fine.
	_ = exec.Command("git", "config", "--global", "--unset-all", section+".helper").Run()
	steps := [][]string{
		// The empty helper clears helpers inherited from system config
		// (gh auth git-credential, osxkeychain, ...).
		{"config", "--global", "--add", section + ".helper", ""},
		{"config", "--global", "--add", section + ".helper", "!" + shellQuote(self) + " git-credential"},
		{"config", "--global", section + ".useHttpPath", "true"},
		{"config", "--global", "--replace-all", "hook." + hookName + ".command", hookCommand(self)},
		{"config", "--global", "--replace-all", "hook." + hookName + ".event", "post-checkout"},
	}
	for _, s := range steps {
		if _, err := gitOut(s...); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "git now asks gh-appauth for https://%s credentials (helper: %s)\n", cfg.GitHubHost(), self)
	fmt.Fprintln(stdout, "repos without their own user.name/user.email get the App's bot identity on clone, fetch or push (turn off with: git config --global gh-appauth.autoIdentity false)")
	if remotes, err := gitOut("remote", "-v"); err == nil {
		for _, line := range strings.Split(remotes, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && (strings.HasPrefix(f[1], "git@") || strings.HasPrefix(f[1], "ssh://")) {
				r, perr := repo.ParseHost(f[1], cfg.GitHubHost())
				fix := ""
				if perr == nil {
					fix = fmt.Sprintf("; switch with: git remote set-url %s https://%s/%s.git", f[0], cfg.GitHubHost(), r)
				}
				fmt.Fprintf(stderr, "warning: remote %q uses SSH (%s), which never uses the credential helper%s\n", f[0], f[1], fix)
				break
			}
		}
	}
	return nil
}

// ---- identity ----

func cmdIdentity(stdout io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	r, err := currentRepo(cfg)
	if err != nil {
		return err
	}
	t, _, err := getToken(cfg, r, nil)
	if err != nil {
		return err
	}
	if err := setIdentity(t); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "commits in this repo will be authored as %s <%s>\n", t.BotName, t.BotEmail)
	return nil
}

func setIdentity(t *api.TokenResponse) error {
	if t.BotName == "" || t.BotEmail == "" {
		return errors.New("the broker couldn't determine the App's bot identity (check the broker log)")
	}
	// Repo-local config lives in the common git dir, so it also applies to
	// every worktree of this repository.
	if _, err := gitOut("config", "--local", "user.name", t.BotName); err != nil {
		return err
	}
	_, err := gitOut("config", "--local", "user.email", t.BotEmail)
	return err
}

// Only the repo's own config counts as an identity: a global one on an agent
// machine is usually the human's.
func autoIdentityRepo(cfg *Config) string {
	r, err := currentRepo(cfg)
	if err != nil {
		return ""
	}
	// An unparsable value makes git fail, which counts as off: a typo in an
	// opt-out must not leave the feature on.
	if v, _ := gitOut("config", "--type=bool", "--default=true", "--get", "gh-appauth.autoIdentity"); v != "true" {
		return ""
	}
	if v, _ := gitOut("config", "--local", "--get-regexp", `^user\.(name|email)$`); v != "" {
		return ""
	}
	return r
}

// Errors are only reported: this runs inside git and gh commands that must not
// fail because of it.
func maybeSetIdentity(cfg *Config, r string, t *api.TokenResponse, stderr io.Writer) {
	if t.BotName == "" || t.BotEmail == "" || !strings.EqualFold(autoIdentityRepo(cfg), r) {
		return
	}
	if err := setIdentity(t); err != nil {
		// A name without an email would pass for the repo's own identity
		// and block every later attempt.
		_ = exec.Command("git", "config", "--local", "--unset-all", "user.name").Run()
		_ = exec.Command("git", "config", "--local", "--unset-all", "user.email").Run()
		fmt.Fprintf(stderr, "gh-appauth: warning: setting the bot identity: %v\n", err)
		return
	}
	fmt.Fprintf(stderr, "gh-appauth: commits in this repo will be authored as %s <%s>\n", t.BotName, t.BotEmail)
}

// Config-defined hooks need git 2.54; older versions ignore the setting.
const hookName = "gh-appauth"

// The hook lives in the global config, so it runs in every repo. If the binary
// is gone (uninstalled, or the config is shared into a container), it has to
// do nothing: a failing post-checkout makes clone, checkout and worktree add
// exit non-zero. The function wrapper is needed because git appends the hook's
// arguments to the command string.
func hookCommand(self string) string {
	q := shellQuote(self)
	return "f() { test -x " + q + " || return 0; " + q + ` git-hook post-checkout "$@"; }; f`
}

// post-checkout with an all-zero old ref means a fresh clone or worktree. This
// covers public repos: their clone never asks the credential helper, so
// nothing else would set the identity before the first commit.
func cmdGitHook(args []string, stderr io.Writer) error {
	if len(args) != 4 || args[0] != "post-checkout" || strings.Trim(args[1], "0") != "" {
		return nil
	}
	cfg, err := loadConfig()
	if err != nil {
		return nil
	}
	r := autoIdentityRepo(cfg)
	if r == "" {
		return nil
	}
	// A denial is normal here (a public repo the client has no grant for),
	// so it stays quiet.
	if t, _, err := getToken(cfg, r, nil); err == nil {
		maybeSetIdentity(cfg, r, t, stderr)
	}
	return nil
}
