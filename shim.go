package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	fmt.Fprintf(stdout, "installed %s (real gh: %s)\nput %s first in PATH for the agent, e.g.\n  export PATH=%s:$PATH\n", target, real, dir, shellQuote(dir))
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

// shimRepo works out which repo a gh command targets.
func shimRepo(cfg *Config, args []string) (string, error) {
	if v, ok := repoFlag(args); ok {
		return repo.ParseHost(v, cfg.GitHubHost())
	}
	if v := os.Getenv("GH_APPAUTH_REPO"); v != "" {
		return repo.ParseHost(v, cfg.GitHubHost())
	}
	r, err := currentRepo(cfg)
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
	repoArg := fs.String("repo", "", "OWNER/REPO (default: origin of the current folder)")
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
	} else {
		r, err = currentRepo(cfg)
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
