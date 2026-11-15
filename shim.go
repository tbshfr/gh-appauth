package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/tbshfr/gh-appauth/internal/repo"
)

// passthrough lists gh commands that never get an App token.
var passthrough = map[string]bool{
	"--version": true, "version": true, "help": true, "--help": true, "-h": true,
	"auth": true, "extension": true, "ext": true, "extensions": true, "config": true,
	"alias": true, "completion": true, "appauth": true,
}

func isShimScript(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 512)
	n, _ := f.Read(b)
	return strings.Contains(string(b[:n]), " gh-shim ")
}

// findRealGH locates the real gh binary, skipping our wrapper scripts and
// anything in exclude.
func findRealGH(exclude string) (string, error) {
	if p := os.Getenv("GH_PATH"); p != "" && !isShimScript(p) {
		return p, nil
	}
	if exclude != "" {
		if abs, err := filepath.Abs(exclude); err == nil {
			exclude = abs
		}
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		if abs, err := filepath.Abs(dir); err == nil && abs == exclude {
			continue
		}
		p := filepath.Join(dir, "gh")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 && !isShimScript(p) {
			return p, nil
		}
	}
	return "", errors.New("can't find the real gh binary in PATH")
}

func cmdShim(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: gh appauth shim DIR")
	}
	if runtime.GOOS == "windows" {
		return errors.New("the gh shim is a shell script and doesn't work on Windows; use: gh appauth exec -- gh ...")
	}
	dir, err := filepath.Abs(args[0])
	if err != nil {
		return err
	}
	cfg, err := loadFileConfig()
	if err != nil {
		return err
	}
	real, err := findRealGH(dir)
	if err != nil {
		return err
	}
	self, err := selfPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %s gh-shim \"$@\"\n", shellQuote(self))
	target := filepath.Join(dir, "gh")
	if err := os.WriteFile(target+".tmp", []byte(script), 0o755); err != nil {
		return err
	}
	if err := os.Rename(target+".tmp", target); err != nil {
		return err
	}
	cfg.RealGH = real
	if err := saveConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "installed %s (real gh: %s)\nput %s first in PATH for the agent by adding this to its shell profile (e.g. ~/.bashrc):\n  export PATH=%s:\"$PATH\"\nthen open a new shell; `type -a gh` should list %s first.\n", target, real, dir, shellQuote(dir), target)
	fmt.Fprintln(stdout, "Make sure the agent's user has no `gh auth login` session, so commands without a repo fail instead of using your account.")
	return nil
}

// repoFlag extracts the -R/--repo value from gh arguments.
func repoFlag(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return "", false
		case a == "-R" || a == "--repo":
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case strings.HasPrefix(a, "--repo="):
			return strings.TrimPrefix(a, "--repo="), true
		case strings.HasPrefix(a, "-R") && len(a) > 2:
			return strings.TrimPrefix(strings.TrimPrefix(a, "-R"), "="), true
		}
	}
	return "", false
}

// positionalCmds lists the gh commands whose first positional argument can name
// the repository, each with its flags that take a value, so that a value such
// as a --body containing a PR link isn't mistaken for that argument. For
// `repo` commands the argument is the repository; for `pr` and `issue` it only
// names one when it's a URL. The flag lists come from gh 2.103 --help.
var positionalCmds = map[string]string{
	"repo clone":       "-u --upstream-remote-name",
	"repo fork":        "--fork-name --org --remote-name",
	"repo set-default": "",
	"repo view":        "-b --branch -q --jq --json -t --template",

	"pr checkout":      "-b --branch --worktree",
	"pr checks":        "-i --interval -q --jq --json -t --template",
	"pr close":         "-c --comment",
	"pr comment":       "--attach -b --body -F --body-file",
	"pr diff":          "--color -e --exclude",
	"pr edit":          "--add-assignee --add-label --add-project --add-reviewer --attach -B --base -b --body -F --body-file -m --milestone --remove-assignee --remove-label --remove-project --remove-reviewer -t --title",
	"pr lock":          "-r --reason",
	"pr merge":         "-A --author-email -b --body -F --body-file --match-head-commit -t --subject",
	"pr ready":         "",
	"pr reopen":        "-c --comment",
	"pr revert":        "-b --body -F --body-file -t --title",
	"pr review":        "-b --body -F --body-file",
	"pr unlock":        "",
	"pr update-branch": "",
	"pr view":          "-q --jq --json -t --template",

	"issue close":    "-c --comment --duplicate-of -r --reason",
	"issue comment":  "--attach -b --body -F --body-file",
	"issue delete":   "",
	"issue develop":  "-b --base --branch-repo -n --name --worktree",
	"issue edit":     "--add-assignee --add-blocked-by --add-blocking --add-label --add-project --add-sub-issue --attach -b --body -F --body-file -m --milestone --parent --remove-assignee --remove-blocked-by --remove-blocking --remove-label --remove-project --remove-sub-issue -t --title --type",
	"issue lock":     "-r --reason",
	"issue pin":      "",
	"issue reopen":   "-c --comment",
	"issue transfer": "",
	"issue unlock":   "",
	"issue unpin":    "",
	"issue view":     "-q --jq --json -t --template",
}

// positionalArg returns the command ("pr view") and its first positional
// argument, if the command is in positionalCmds and has one.
func positionalArg(args []string) (cmd, arg string, ok bool) {
	if len(args) > 0 && args[0] == "co" {
		// gh ships `co` as a default alias for `pr checkout`.
		args = append([]string{"pr", "checkout"}, args[1:]...)
	}
	if len(args) < 2 {
		return "", "", false
	}
	cmd = args[0] + " " + args[1]
	spec, known := positionalCmds[cmd]
	if !known {
		return "", "", false
	}
	valueFlags := append(strings.Fields(spec), "-R", "--repo")
	for i := 2; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			// For repo clone and fork, everything after this goes to git.
			return "", "", false
		case slices.Contains(valueFlags, a):
			i++
		case strings.HasPrefix(a, "-"):
		default:
			return cmd, a, true
		}
	}
	return "", "", false
}

// repoFromURL returns owner/repo from a GitHub web URL such as
// https://github.com/acme/web/pull/1/files.
func repoFromURL(s, host string) (string, error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %v", s, err)
	}
	seg := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(seg) < 2 {
		return "", fmt.Errorf("can't find OWNER/REPO in %q", s)
	}
	return repo.ParseHost((&url.URL{Scheme: u.Scheme, Host: u.Host, Path: seg[0] + "/" + seg[1]}).String(), host)
}

func needsToken(args []string) bool {
	return len(args) > 0 && !passthrough[args[0]]
}

func filteredEnv(drop ...string) []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		keep := true
		for _, d := range drop {
			if k == d {
				keep = false
			}
		}
		if keep {
			out = append(out, kv)
		}
	}
	return out
}

func runChild(path string, args []string, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
	c := exec.Command(path, args...)
	c.Env = env
	c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stderr
	err := c.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return exitCode(ee.ExitCode())
	}
	return err
}

// shimRepo works out which repo a gh command targets, in the order gh itself
// uses (checked against gh 2.103): a repo or PR/issue URL argument, -R,
// GH_REPO, then the current folder's remotes.
func shimRepo(cfg *Config, args []string) (string, error) {
	host := cfg.GitHubHost()
	if cmd, v, ok := positionalArg(args); ok {
		if strings.HasPrefix(cmd, "repo ") {
			r, err := repo.ParseHost(v, host)
			if err != nil {
				return "", fmt.Errorf("%v; gh resolves a bare name against the logged-in user, and an App token has none", err)
			}
			return r, nil
		}
		if strings.Contains(v, "://") {
			return repoFromURL(v, host)
		}
	}
	if v, ok := repoFlag(args); ok {
		return repo.ParseHost(v, host)
	}
	if v := os.Getenv("GH_REPO"); v != "" {
		return repo.ParseHost(v, host)
	}
	if v := os.Getenv("GH_APPAUTH_REPO"); v != "" {
		return repo.ParseHost(v, host)
	}
	r, err := ghBaseRepo(cfg)
	if err != nil {
		return "", nil // no repo: run without a token
	}
	return r, nil
}

func cmdGHShim(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fileCfg, _ := loadFileConfig()
	real := ""
	if fileCfg != nil {
		real = fileCfg.RealGH
	}
	if real == "" || isShimScript(real) {
		var err error
		if real, err = findRealGH(""); err != nil {
			return err
		}
	}
	env := filteredEnv("GH_TOKEN", "GITHUB_TOKEN")
	if !needsToken(args) {
		return runChild(real, args, env, stdin, stdout, stderr)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	r, err := shimRepo(cfg, args)
	if err != nil {
		return err
	}
	if r == "" {
		return runChild(real, args, env, stdin, stdout, stderr)
	}
	t, _, err := getToken(cfg, r, nil)
	if err != nil {
		return err
	}
	env = append(env, "GH_TOKEN="+t.Token)
	return runChild(real, args, env, stdin, stdout, stderr)
}

func cmdExec(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repoArg := fs.String("repo", "", "OWNER/REPO (default: the repo gh would use in the current folder)")
	if err := fs.Parse(args); err != nil {
		return exitCode(2)
	}
	cmd := fs.Args()
	if len(cmd) == 0 {
		return errors.New("usage: gh appauth exec [--repo R] -- CMD...")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	var r string
	if *repoArg != "" {
		r, err = repo.ParseHost(*repoArg, cfg.GitHubHost())
	} else if v := cmp.Or(os.Getenv("GH_REPO"), os.Getenv("GH_APPAUTH_REPO")); v != "" {
		r, err = repo.ParseHost(v, cfg.GitHubHost())
	} else {
		r, err = ghBaseRepo(cfg)
	}
	if err != nil {
		return err
	}
	t, _, err := getToken(cfg, r, nil)
	if err != nil {
		return err
	}
	path, err := exec.LookPath(cmd[0])
	if err != nil {
		return err
	}
	env := append(filteredEnv("GH_TOKEN", "GITHUB_TOKEN"), "GH_TOKEN="+t.Token, "GITHUB_TOKEN="+t.Token)
	return runChild(path, cmd[1:], env, stdin, stdout, stderr)
}
