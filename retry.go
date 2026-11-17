package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// A token can be revoked before it expires and the cache can't know, so the
// shim runs gh as a child and, when GitHub rejects the token, drops it and
// runs the command once more. At a terminal gh keeps the terminal (prompts,
// git progress), so there the shim asks GitHub instead of reading the output.

// A dead token fails gh's first API call; a later failure may come after the
// command already changed something.
var retryWindow = 10 * time.Second

const (
	maxHeld   = 1 << 20
	maxReplay = 32 << 20
)

// A variable so tests can pretend.
var isTTY = func(w any) bool {
	f, ok := w.(*os.File)
	if !ok || !isTerminal(f) {
		return false
	}
	// isTerminal is true for any character device, /dev/null included.
	fi, err1 := f.Stat()
	null, err2 := os.Stat(os.DevNull)
	return err1 != nil || err2 != nil || !os.SameFile(fi, null)
}

func githubAPI(cfg *Config) string {
	if u := os.Getenv("GH_APPAUTH_GITHUB_API"); u != "" {
		return strings.TrimRight(u, "/")
	}
	switch h := cfg.GitHubHost(); {
	case h == "github.com":
		return "https://api.github.com"
	case strings.HasSuffix(h, ".ghe.com"): // GHE.com data residency
		return "https://api." + h
	default: // GitHub Enterprise Server
		return "https://" + h + "/api/v3"
	}
}

// gh api words it differently from the other commands.
func rejectedToken(stderr []byte) bool {
	return bytes.Contains(stderr, []byte("HTTP 401: Bad credentials")) || bytes.Contains(stderr, []byte("Bad credentials (HTTP 401)"))
}

type tokenState int

const (
	tokenUnknown tokenState = iota
	tokenDead
	tokenAlive
)

// Only a 401 means the token is dead: acting on a 403, 429 or 5xx would
// revoke a working token.
func checkToken(cfg *Config, token string) tokenState {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", githubAPI(cfg)+"/installation/repositories?per_page=1", nil)
	if err != nil {
		return tokenUnknown
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tokenUnknown
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return tokenDead
	}
	return tokenAlive
}

func runWithRetry(cfg *Config, repoName, token, gh string, args, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
	in := newStdinFeeder(stdin, args)
	out := newFirstOutput(stdout, stderr)
	ghIn, inDone, err := in.next()
	if err != nil {
		return err
	}
	ghOut, ghErr := out.start()
	runErr := runGH(gh, args, withToken(env, token), ghIn, ghOut, ghErr)
	inDone()
	early := out.stop()

	dead := false
	if ec := exitCode(0); errors.As(runErr, &ec) {
		if out.agent {
			// The message may be about another credential, or quoted.
			dead = out.rejected() && checkToken(cfg, token) != tokenAlive
		} else {
			// Not on other codes: gh pr checks exits 8 for pending checks.
			dead = early && ec == 1 && checkToken(cfg, token) == tokenDead
		}
	}
	if !dead {
		out.flush()
		return finish(runErr)
	}

	dropTokens(cfg, token)
	note := func(msg string) {
		fmt.Fprintf(stderr, "gh-appauth: GitHub rejected the token for %s (revoked?); %s\n", repoName, msg)
	}
	var newToken, why string
	switch {
	case !early:
		why = "dropped it, so the next command gets a new one"
	case !in.canRepeat():
		why = "dropped it; run the command again (stdin can't be read twice)"
	default:
		t, _, err := getToken(cfg, repoName, nil)
		switch {
		case err != nil:
			why = fmt.Sprintf("getting a new one failed: %v", err)
		case t.Token == token:
			why = "the broker handed it out again; run the command again later"
		default:
			newToken = t.Token
			if ghIn, inDone, err = in.next(); err != nil {
				why = fmt.Sprintf("dropped it; run the command again (rereading stdin: %v)", err)
			}
		}
	}
	if why != "" {
		out.flush()
		note(why)
		return finish(runErr)
	}
	out.discard()
	note("got a new one and ran the command again")
	runErr = runGH(gh, args, withToken(env, newToken), ghIn, stdout, stderr)
	inDone()
	return finish(runErr)
}

func withToken(env []string, token string) []string {
	return append(slices.Clip(env), "GH_TOKEN="+token)
}

type childSignal struct{ sig syscall.Signal }

func (c childSignal) Error() string { return "gh: " + c.sig.String() }

var passedSignals = []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}

// signal.Ignored can't tell anymore once Notify was called.
var ignoredAtStart = sync.OnceValue(func() map[syscall.Signal]bool {
	m := map[syscall.Signal]bool{}
	for _, s := range passedSignals {
		m[s] = signal.Ignored(s)
	}
	return m
})

func runGH(path string, args, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
	c := exec.Command(path, args...)
	c.Env = env
	c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stderr
	// A browser gh starts can keep the output pipes open.
	c.WaitDelay = 2 * time.Second
	// Pdeathsig fires when the starting thread ends, not the process.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c.SysProcAttr = childSysProcAttr()

	// The terminal already sends Ctrl-C and hangups to gh, and a second one
	// often means "quit now". Still catch them, to outlive gh.
	fromTTY := inForegroundGroup()
	ignored := ignoredAtStart()
	sigs := make(chan os.Signal, 4)
	for _, s := range passedSignals {
		if !ignored[s] {
			signal.Notify(sigs, s)
		}
	}
	if err := c.Start(); err != nil {
		signal.Stop(sigs)
		return err
	}
	var got syscall.Signal
	pass := func(s os.Signal) {
		sig := s.(syscall.Signal)
		if fromTTY && sig != syscall.SIGTERM {
			return
		}
		got = sig
		_ = c.Process.Signal(sig)
	}
	waited := make(chan error, 1)
	go func() { waited <- c.Wait() }()
	var err error
	for running := true; running; {
		select {
		case s := <-sigs:
			pass(s)
		case err = <-waited:
			running = false
		}
	}
	signal.Stop(sigs)
	select {
	case s := <-sigs: // came as gh exited
		pass(s)
	default:
	}

	var ee *exec.ExitError
	switch {
	case got != 0:
		return childSignal{got}
	case err == nil, errors.Is(err, exec.ErrWaitDelay):
		return nil
	case errors.As(err, &ee):
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return childSignal{ws.Signal()}
		}
		return exitCode(ee.ExitCode())
	}
	return err
}

// Dying of the signal stops a shell loop around the shim, as it would for gh.
func finish(err error) error {
	var cs childSignal
	if !errors.As(err, &cs) {
		return err
	}
	if !ignoredAtStart()[cs.sig] {
		raise(cs.sig)
	}
	return exitCode(128 + int(cs.sig))
}

// firstOutput holds an agent's output back during the retry window, so that
// a retry replaces the failed run's output instead of following it.
type firstOutput struct {
	mu             sync.Mutex
	stdout, stderr io.Writer
	agent          bool
	holding        bool
	open           bool
	stopped        bool
	held           []heldChunk
	size           int
	errHead        []byte
	timer          *time.Timer
}

func sameFile(a, b io.Writer) bool {
	fa, ok1 := a.(*os.File)
	fb, ok2 := b.(*os.File)
	if !ok1 || !ok2 {
		return false
	}
	sa, err1 := fa.Stat()
	sb, err2 := fb.Stat()
	return fa == fb || err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

type heldChunk struct {
	w io.Writer
	b []byte
}

func newFirstOutput(stdout, stderr io.Writer) *firstOutput {
	agent := !isTTY(stdout) && !isTTY(stderr)
	return &firstOutput{stdout: stdout, stderr: stderr, agent: agent, holding: agent, open: true}
}

func (o *firstOutput) start() (stdout, stderr io.Writer) {
	stdout, stderr = o.stdout, o.stderr
	switch {
	case o.agent && sameFile(o.stdout, o.stderr):
		// One writer, so exec gives gh one pipe and 2>&1 keeps its order.
		s := outputStream{o, o.stderr, true}
		stdout, stderr = s, s
	case o.agent:
		stdout, stderr = outputStream{o, o.stdout, false}, outputStream{o, o.stderr, true}
	}
	o.timer = time.AfterFunc(retryWindow, func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		if !o.stopped {
			o.closeLocked()
		}
	})
	return stdout, stderr
}

func (o *firstOutput) closeLocked() {
	o.open, o.holding = false, false
	for _, c := range o.held {
		_, _ = c.w.Write(c.b)
	}
	o.held = nil
}

func (o *firstOutput) stop() (early bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stopped = true
	o.timer.Stop()
	return o.open
}

func (o *firstOutput) rejected() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return rejectedToken(o.errHead)
}

func (o *firstOutput) flush() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closeLocked()
}

func (o *firstOutput) discard() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.held = nil
	o.closeLocked()
}

type outputStream struct {
	o     *firstOutput
	w     io.Writer
	isErr bool
}

func (s outputStream) Write(p []byte) (int, error) {
	o := s.o
	o.mu.Lock()
	defer o.mu.Unlock()
	if s.isErr && len(o.errHead) < maxHeld {
		o.errHead = append(o.errHead, p[:min(len(p), maxHeld-len(o.errHead))]...)
	}
	if !o.holding {
		return s.w.Write(p)
	}
	o.held = append(o.held, heldChunk{s.w, bytes.Clone(p)})
	if o.size += len(p); o.size > maxHeld {
		o.closeLocked()
	}
	return len(p), nil
}

// gh may have read stdin before the token was found dead, and a second run
// must not get only what's left.
type stdinFeeder struct {
	r      io.Reader
	once   bool // r can't be given to gh a second time
	seek   bool
	offset int64
	replay *replayStdin
}

// Values that merely end in "-", such as --title "a=-", don't count.
func readsStdin(args []string) bool {
	for i, a := range args {
		_, val, isLong := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		switch {
		case a == "-":
			return true
		case strings.HasPrefix(a, "--") && isLong && val == "-":
			return true
		case strings.HasSuffix(a, "=@-") && i > 0 && (args[i-1] == "-F" || args[i-1] == "--field"):
			return true
		case strings.HasSuffix(a, "=@-") && (strings.HasPrefix(a, "-F") || strings.HasPrefix(a, "--field=")):
			return true
		}
	}
	return false
}

func newStdinFeeder(stdin io.Reader, args []string) *stdinFeeder {
	if stdin == nil {
		return &stdinFeeder{}
	}
	if f, ok := stdin.(*os.File); ok {
		if fi, err := f.Stat(); err == nil {
			switch {
			case fi.Mode()&os.ModeCharDevice != 0:
				// At a terminal gh must see the terminal to prompt.
				return &stdinFeeder{r: f}
			case fi.Mode().IsRegular():
				if off, err := f.Seek(0, io.SeekCurrent); err == nil {
					return &stdinFeeder{r: f, seek: true, offset: off}
				}
			}
		}
	}
	if readsStdin(args) {
		return &stdinFeeder{replay: newReplayStdin(stdin)}
	}
	// What gh leaves belongs to whoever reads next: `... | while read n; do gh ...`.
	return &stdinFeeder{r: stdin, once: true}
}

func (s *stdinFeeder) canRepeat() bool {
	if s.replay != nil {
		return s.replay.canReplay()
	}
	return !s.once
}

func (s *stdinFeeder) next() (io.Reader, func(), error) {
	switch {
	case s.replay != nil:
		return s.replay.open()
	case s.seek:
		_, err := s.r.(*os.File).Seek(s.offset, io.SeekStart)
		return s.r, func() {}, err
	}
	return s.r, func() {}, nil
}

// replayStdin keeps what gh read, so a second run gets it from the start.
// Reading only as gh takes it leaves the rest of a pipe to whoever reads next.
type replayStdin struct {
	src     io.Reader
	mu      sync.Mutex
	cond    *sync.Cond
	buf     []byte // read from src, starting at offset base
	base    int    // > 0 once the start was dropped
	reading bool
	done    bool
}

func newReplayStdin(src io.Reader) *replayStdin {
	s := &replayStdin{src: src}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *replayStdin) canReplay() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.base == 0
}

func (s *replayStdin) open() (io.Reader, func(), error) {
	if !s.canReplay() {
		return nil, nil, errors.New("stdin too large to keep")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	stopped := false
	go func() {
		defer pw.Close()
		b := make([]byte, 32<<10)
		pos := 0
		for {
			s.mu.Lock()
			var chunk []byte
			for chunk == nil {
				switch {
				case stopped:
					s.mu.Unlock()
					return
				case pos < s.base+len(s.buf):
					// append never changes bytes below len.
					chunk = s.buf[pos-s.base:]
				case s.done:
					s.mu.Unlock()
					return
				case s.reading: // a previous run's reader is still waiting on src
					s.cond.Wait()
				default:
					s.reading = true
					s.mu.Unlock()
					n, err := s.src.Read(b)
					s.mu.Lock()
					s.reading = false
					s.buf = append(s.buf, b[:n]...)
					s.done = err != nil
					s.cond.Broadcast()
				}
			}
			s.mu.Unlock()
			if _, err := pw.Write(chunk); err != nil {
				return
			}
			pos += len(chunk)
			s.mu.Lock()
			if !stopped && s.base+len(s.buf) > maxReplay {
				s.buf = append([]byte(nil), s.buf[pos-s.base:]...)
				s.base = pos
			}
			s.mu.Unlock()
		}
	}()
	return pr, func() {
		pr.Close()
		s.mu.Lock()
		stopped = true
		s.cond.Broadcast()
		s.mu.Unlock()
	}, nil
}
