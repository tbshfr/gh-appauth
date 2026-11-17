package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tbshfr/gh-appauth/internal/api"
)

// Set on Unix only.
var killSelf func(pipe bool)

// fakeGH answers like gh does when GitHub refuses a token in FAKEGH_REJECT
// ("*" for any).
func fakeGH() int {
	tok := os.Getenv("GH_TOKEN")
	args := os.Args[1:]
	in := ""
	for _, a := range args {
		switch a {
		case "-":
			b, _ := io.ReadAll(os.Stdin)
			in = string(b)
		case "--kill-self":
			killSelf(false)
		case "--kill-pipe":
			killSelf(true)
		case "--interleave":
			for i := range 200 {
				fmt.Printf("out %d\n", i)
				fmt.Fprintf(os.Stderr, "err %d\n", i)
			}
			return 0
		case "--checks-pending":
			return 8
		case "--quote-401":
			// e.g. an issue body that quotes the error, then a failure
			fmt.Println(`{"body":"saw HTTP 401: Bad credentials (https://api.github.com/graphql)"}`)
			return 1
		case "--count-sigint":
			// Many programs take a second Ctrl-C as "quit now".
			c := make(chan os.Signal, 4)
			signal.Notify(c, os.Interrupt)
			os.WriteFile(os.Getenv("FAKEGH_MARKER")+".ready", nil, 0o600)
			<-c
			time.Sleep(500 * time.Millisecond)
			os.WriteFile(os.Getenv("FAKEGH_MARKER"), []byte(strconv.Itoa(1+len(c))), 0o600)
			return 0
		case "--side-effect":
			time.Sleep(1500 * time.Millisecond)
			os.WriteFile(os.Getenv("FAKEGH_MARKER"), []byte("done"), 0o600)
			return 0
		}
	}
	fmt.Fprintln(os.Stderr, "working…")
	for _, a := range args {
		if a == "--not-found" {
			fmt.Fprintln(os.Stderr, "HTTP 404: Not Found (https://api.github.com/repos/acme/web)")
			return 1
		}
	}
	for _, r := range strings.Split(os.Getenv("FAKEGH_REJECT"), ",") {
		if r != "" && (r == "*" || r == tok) {
			fmt.Println(`{"message":"Bad credentials","status":"401"}`)
			fmt.Fprintln(os.Stderr, "HTTP 401: Bad credentials (https://api.github.com/graphql)")
			return 1
		}
	}
	fmt.Printf("TOKEN=%s STDIN=%q\n", tok, in)
	return 0
}

var githubCalls atomic.Int32

// The fake GitHub API refuses the same tokens as fake gh.
func shimEnv(t *testing.T) (*fakeBroker, string) {
	t.Helper()
	isolate(t)
	t.Chdir(t.TempDir())
	fb := newFakeBroker(t, true)
	useBroker(t, fb)
	githubCalls.Store(0)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		githubCalls.Add(1)
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		for _, rej := range strings.Split(os.Getenv("FAKEGH_REJECT"), ",") {
			if rej != "" && (rej == "*" || rej == tok) || r.URL.Path != "/installation/repositories" {
				w.WriteHeader(401)
				return
			}
		}
	}))
	t.Cleanup(api.Close)
	t.Setenv("GH_APPAUTH_GITHUB_API", api.URL)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_PATH", self)
	t.Setenv("GH_APPAUTH_TEST_FAKEGH", "1")
	t.Setenv("GH_REPO", "acme/web")
	p := cacheToken(t, nil, "ghs_dead")
	t.Setenv("FAKEGH_REJECT", "ghs_dead")
	return fb, p
}

func cacheToken(t *testing.T, perms map[string]string, tok string) string {
	t.Helper()
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	p, _ := cacheFile(cfg, "acme/web", perms)
	if err := writeCached(p, &api.TokenResponse{Token: tok, ExpiresAt: time.Now().Add(30 * time.Minute), Repository: "acme/web"}); err != nil {
		t.Fatal(err)
	}
	return p
}

func shim(stdin io.Reader, args ...string) (string, string, error) {
	var out, errb bytes.Buffer
	err := cmdGHShim(args, stdin, &out, &errb)
	return out.String(), errb.String(), err
}

func (fb *fakeBroker) invalidations() []string {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return append([]string(nil), fb.invalidated...)
}

func pretendTerminal(t *testing.T) {
	old := isTTY
	isTTY = func(any) bool { return true }
	t.Cleanup(func() { isTTY = old })
}

func TestShimRetriesRejectedToken(t *testing.T) {
	fb, p := shimEnv(t)
	other := cacheToken(t, map[string]string{"contents": "read"}, "ghs_other")
	out, errb, err := shim(strings.NewReader("the body"), "pr", "create", "--body-file", "-")
	if err != nil {
		t.Fatalf("err %v\nstderr %s", err, errb)
	}
	if !strings.Contains(out, `TOKEN=ghs_tok1_acme_web STDIN="the body"`) {
		t.Fatalf("retry didn't get the new token and all of stdin: %q", out)
	}
	if strings.Contains(out, "Bad credentials") || strings.Contains(errb, "Bad credentials") || strings.Count(errb, "working…") != 1 {
		t.Fatalf("first run's output leaked:\nstdout %q\nstderr %q", out, errb)
	}
	if !strings.Contains(errb, "gh-appauth: GitHub rejected the token for acme/web (revoked?); got a new one and ran the command again") {
		t.Fatalf("stderr %q", errb)
	}
	// Only the rejected token goes; another command may be using the other.
	if inv := fb.invalidations(); len(inv) != 1 || inv[0] != "ghs_dead" {
		t.Fatalf("broker invalidations = %v", inv)
	}
	if c := readCached(p); c == nil || c.Token != "ghs_tok1_acme_web" {
		t.Fatalf("cache holds %+v", c)
	}
	if c := readCached(other); c == nil || c.Token != "ghs_other" {
		t.Fatal("token for other permissions dropped")
	}
}

func TestShimRetriesOnce(t *testing.T) {
	fb, _ := shimEnv(t)
	t.Setenv("FAKEGH_REJECT", "*")
	out, errb, err := shim(nil, "api", "user")
	if err != exitCode(1) {
		t.Fatalf("err %v", err)
	}
	if strings.Count(out, "Bad credentials") != 1 || strings.Count(errb, "HTTP 401") != 1 || strings.Count(errb, "ran the command again") != 1 {
		t.Fatalf("stdout %q\nstderr %q", out, errb)
	}
	if fb.calls() != 1 {
		t.Fatalf("token requests = %d", fb.calls())
	}
}

func TestShimOtherFailureNoRetry(t *testing.T) {
	fb, p := shimEnv(t)
	t.Setenv("FAKEGH_REJECT", "")
	out, errb, err := shim(nil, "pr", "view", "--not-found")
	if err != exitCode(1) || out != "" || errb != "working…\nHTTP 404: Not Found (https://api.github.com/repos/acme/web)\n" {
		t.Fatalf("err %v stdout %q stderr %q", err, out, errb)
	}
	if fb.calls() != 0 || len(fb.invalidations()) != 0 || readCached(p) == nil {
		t.Fatal("a failure other than a rejected token touched the token")
	}
}

func TestShimRejectedAfterWindow(t *testing.T) {
	fb, p := shimEnv(t)
	old := retryWindow
	retryWindow = 0
	t.Cleanup(func() { retryWindow = old })
	out, errb, err := shim(nil, "pr", "list")
	if err != exitCode(1) {
		t.Fatalf("err %v", err)
	}
	if !strings.Contains(out, "Bad credentials") || !strings.Contains(errb, "HTTP 401") ||
		!strings.HasSuffix(errb, "gh-appauth: GitHub rejected the token for acme/web (revoked?); dropped it, so the next command gets a new one\n") {
		t.Fatalf("stdout %q\nstderr %q", out, errb)
	}
	if fb.calls() != 0 || len(fb.invalidations()) != 1 || readCached(p) != nil {
		t.Fatalf("calls %d invalidations %v", fb.calls(), fb.invalidations())
	}
	if out, _, err := shim(nil, "pr", "list"); err != nil || !strings.Contains(out, "TOKEN=ghs_tok1_acme_web") {
		t.Fatalf("next command: %q %v", out, err)
	}
}

func TestShimRetryNewTokenFails(t *testing.T) {
	fb, _ := shimEnv(t)
	fb.tokenStatus = 403
	out, errb, err := shim(nil, "pr", "list")
	if err != exitCode(1) || !strings.Contains(out, "Bad credentials") ||
		!strings.Contains(errb, "HTTP 401") || !strings.Contains(errb, "getting a new one failed: denied for acme/web: refused") {
		t.Fatalf("err %v\nstdout %q\nstderr %q", err, out, errb)
	}
}

func TestShimBrokerHandsOutSameToken(t *testing.T) {
	fb, _ := shimEnv(t)
	fb.token = "ghs_dead"
	out, errb, err := shim(nil, "pr", "list")
	if err != exitCode(1) || strings.Count(out, "Bad credentials") != 1 || strings.Count(errb, "HTTP 401") != 1 ||
		!strings.HasSuffix(errb, "gh-appauth: GitHub rejected the token for acme/web (revoked?); the broker handed it out again; run the command again later\n") {
		t.Fatalf("err %v\nstdout %q\nstderr %q", err, out, errb)
	}
}

func TestShimRetryRereadsStdinFile(t *testing.T) {
	shimEnv(t)
	p := filepath.Join(t.TempDir(), "in")
	if err := os.WriteFile(p, []byte("skip|the body"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Seek(5, io.SeekStart)
	out, errb, err := shim(f, "pr", "create", "--body-file", "-")
	if err != nil || !strings.Contains(out, `STDIN="the body"`) {
		t.Fatalf("err %v\nstdout %q\nstderr %q", err, out, errb)
	}
}

func TestShimRetryReplaysPipe(t *testing.T) {
	shimEnv(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	go func() {
		pw.WriteString("piped body")
		pw.Close()
	}()
	out, errb, err := shim(pr, "api", "-X", "POST", "repos/{owner}/{repo}/issues", "--input", "-")
	if err != nil || !strings.Contains(out, `STDIN="piped body"`) {
		t.Fatalf("err %v\nstdout %q\nstderr %q", err, out, errb)
	}
}

// A pipe gh isn't told to read belongs to whoever reads it next, as in
// `... | while read n; do gh pr view $n; done`: the shim must leave it alone.
func TestShimLeavesUnreadPipe(t *testing.T) {
	fb, _ := shimEnv(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	pw.WriteString("two\nthree\n")
	pw.Close()
	out, errb, err := shim(pr, "pr", "view", "1")
	if err != exitCode(1) || !strings.Contains(out, "Bad credentials") ||
		!strings.HasSuffix(errb, "gh-appauth: GitHub rejected the token for acme/web (revoked?); dropped it; run the command again (stdin can't be read twice)\n") {
		t.Fatalf("err %v\nstdout %q\nstderr %q", err, out, errb)
	}
	if len(fb.invalidations()) != 1 {
		t.Fatal("rejected token not dropped")
	}
	if rest, _ := io.ReadAll(pr); string(rest) != "two\nthree\n" {
		t.Fatalf("shim consumed stdin; left %q", rest)
	}
	t.Setenv("FAKEGH_REJECT", "")
	pr2, pw2, _ := os.Pipe()
	defer pr2.Close()
	pw2.WriteString("x\n")
	pw2.Close()
	if _, _, err := shim(pr2, "pr", "view", "1"); err != nil {
		t.Fatal(err)
	}
	if rest, _ := io.ReadAll(pr2); string(rest) != "x\n" {
		t.Fatalf("shim consumed stdin; left %q", rest)
	}
}

func TestShimTerminalAsksGitHub(t *testing.T) {
	fb, p := shimEnv(t)
	pretendTerminal(t)
	out, errb, err := shim(nil, "pr", "list")
	if err != nil {
		t.Fatalf("err %v\nstderr %s", err, errb)
	}
	if !strings.Contains(out, "Bad credentials") || !strings.Contains(out, "TOKEN=ghs_tok1_acme_web") ||
		!strings.Contains(errb, "HTTP 401") ||
		!strings.Contains(errb, "gh-appauth: GitHub rejected the token for acme/web (revoked?); got a new one and ran the command again") {
		t.Fatalf("stdout %q\nstderr %q", out, errb)
	}
	if c := readCached(p); c == nil || c.Token != "ghs_tok1_acme_web" {
		t.Fatalf("cache holds %+v", c)
	}
	if inv := fb.invalidations(); len(inv) != 1 || inv[0] != "ghs_dead" {
		t.Fatalf("broker invalidations = %v", inv)
	}
}

func TestShimTerminalTokenAlive(t *testing.T) {
	fb, _ := shimEnv(t)
	pretendTerminal(t)
	cacheToken(t, nil, "ghs_alive")
	_, errb, err := shim(nil, "pr", "view", "--not-found")
	if err != exitCode(1) || strings.Contains(errb, "gh-appauth:") || fb.calls() != 0 || githubCalls.Load() != 1 {
		t.Fatalf("err %v calls %d github %d stderr %q", err, fb.calls(), githubCalls.Load(), errb)
	}
	cacheToken(t, nil, "ghs_dead")
	if _, _, err := shim(nil, "pr", "checks", "--checks-pending"); err != exitCode(8) || githubCalls.Load() != 1 || fb.calls() != 0 {
		t.Fatalf("err %v github %d", err, githubCalls.Load())
	}
}

// The message may be quoted output; revoking would break a working token.
func TestShimUnrelated401(t *testing.T) {
	for _, status := range []int{200, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			fb, p := shimEnv(t)
			cacheToken(t, nil, "ghs_alive")
			t.Setenv("FAKEGH_REJECT", "")
			if status != 200 {
				gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					githubCalls.Add(1)
					w.WriteHeader(status)
				}))
				t.Cleanup(gh.Close)
				t.Setenv("GH_APPAUTH_GITHUB_API", gh.URL)
			}
			f, err := os.Create(filepath.Join(t.TempDir(), "out"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := cmdGHShim([]string{"api", "graphql", "--quote-401"}, nil, f, f); err != exitCode(1) {
				t.Fatalf("err %v", err)
			}
			b, _ := os.ReadFile(f.Name())
			if strings.Contains(string(b), "gh-appauth:") || len(fb.invalidations()) != 0 || fb.calls() != 0 || githubCalls.Load() != 1 {
				t.Fatalf("output %q invalidations %v", b, fb.invalidations())
			}
			if c := readCached(p); c == nil || c.Token != "ghs_alive" {
				t.Fatal("working token dropped")
			}
		})
	}
}

func TestCheckToken(t *testing.T) {
	for status, want := range map[int]tokenState{200: tokenAlive, 401: tokenDead, 403: tokenAlive, 404: tokenAlive, 429: tokenAlive, 503: tokenAlive} {
		gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer ghs_x" || r.URL.Path != "/installation/repositories" {
				t.Errorf("request %s %s", r.Header.Get("Authorization"), r.URL.Path)
			}
			w.WriteHeader(status)
		}))
		t.Setenv("GH_APPAUTH_GITHUB_API", gh.URL+"/")
		if got := checkToken(&Config{}, "ghs_x"); got != want {
			t.Errorf("GitHub answers %d: got %v, want %v", status, got, want)
		}
		gh.Close()
	}
	t.Setenv("GH_APPAUTH_GITHUB_API", "http://127.0.0.1:1")
	if got := checkToken(&Config{}, "ghs_x"); got != tokenUnknown {
		t.Errorf("GitHub unreachable: got %v", got)
	}
}

func TestGitHubAPI(t *testing.T) {
	t.Setenv("GH_APPAUTH_GITHUB_API", "")
	for host, want := range map[string]string{
		"":                "https://api.github.com",
		"GitHub.com":      "https://api.github.com",
		"acme.ghe.com":    "https://api.acme.ghe.com",
		"git.example.com": "https://git.example.com/api/v3",
	} {
		if got := githubAPI(&Config{Host: host}); got != want {
			t.Errorf("host %q: %s, want %s", host, got, want)
		}
	}
	t.Setenv("GH_APPAUTH_GITHUB_API", "https://proxy.example.com/github/")
	if got := githubAPI(&Config{}); got != "https://proxy.example.com/github" {
		t.Errorf("override: %s", got)
	}
}

// If GitHub can't be asked, gh's own message decides.
func TestShimGitHubUnreachable(t *testing.T) {
	shimEnv(t)
	t.Setenv("GH_APPAUTH_GITHUB_API", "http://127.0.0.1:1")
	out, errb, err := shim(nil, "pr", "list")
	if err != nil || !strings.Contains(out, "TOKEN=ghs_tok1_acme_web") || !strings.Contains(errb, "ran the command again") {
		t.Fatalf("err %v\nstdout %q\nstderr %q", err, out, errb)
	}
}

func TestShimKeepsCombinedOutputInOrder(t *testing.T) {
	shimEnv(t)
	t.Setenv("FAKEGH_REJECT", "")
	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := cmdGHShim([]string{"pr", "list", "--interleave"}, nil, f, f); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.Name())
	var want strings.Builder
	for i := range 200 {
		fmt.Fprintf(&want, "out %d\nerr %d\n", i, i)
	}
	if string(b) != want.String() {
		t.Fatalf("out of order:\n%.300s", b)
	}
}

func TestFirstOutputReleasesLargeOutput(t *testing.T) {
	var out, errb bytes.Buffer
	o := newFirstOutput(&out, &errb)
	stdout, stderr := o.start()
	stderr.Write([]byte("a"))
	stdout.Write([]byte("b"))
	if out.Len()+errb.Len() != 0 {
		t.Fatal("output not held")
	}
	stdout.Write(make([]byte, maxHeld))
	if errb.String() != "a" || out.Len() != maxHeld+1 {
		t.Fatalf("held output not released in order: %d %d", errb.Len(), out.Len())
	}
	if o.stop() {
		t.Fatal("window still open after release")
	}
}

func TestDevNullIsNotATerminal(t *testing.T) {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTTY(f) {
		t.Fatal("/dev/null counted as a terminal")
	}
}

func TestReadsStdin(t *testing.T) {
	for args, want := range map[string]bool{
		"pr create --body-file -":            true,
		"pr create --body-file=-":            true,
		"api repos/a/b/issues -F body=@-":    true,
		"api repos/a/b/issues --field=b=@-":  true,
		"api repos/a/b/issues -f body=@-":    false,
		"pr create --title a=-":              false,
		"api graphql --input -":              true,
		"pr list":                            false,
		"pr create --body a-b --title x=y-z": false,
	} {
		if got := readsStdin(strings.Fields(args)); got != want {
			t.Errorf("%s: %v", args, got)
		}
	}
}

func TestReplayStdinCap(t *testing.T) {
	s := newReplayStdin(bytes.NewReader(make([]byte, maxReplay+100)))
	r, done, err := s.open()
	if err != nil {
		t.Fatal(err)
	}
	n, _ := io.Copy(io.Discard, r)
	done()
	if n != maxReplay+100 {
		t.Fatalf("gh got %d bytes", n)
	}
	if s.canReplay() {
		t.Fatal("kept more than maxReplay")
	}
	if _, _, err := s.open(); err == nil {
		t.Fatal("replayed after dropping the start")
	}
}
