//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func init() {
	killSelf = func(pipe bool) {
		if pipe {
			// Go ignores a SIGPIPE sent with kill; sh doesn't.
			syscall.Exec("/bin/sh", []string{"sh", "-c", "kill -PIPE $$"}, os.Environ())
		}
		syscall.Kill(os.Getpid(), syscall.SIGTERM)
		time.Sleep(10 * time.Second)
	}
}

func shimProcess(args ...string) *exec.Cmd {
	self, _ := os.Executable()
	return exec.Command(self, append([]string{"gh-shim"}, args...)...)
}

// So a shell loop around the shim stops, as it would for gh.
func TestShimDiesOfGHSignal(t *testing.T) {
	shimEnv(t)
	t.Setenv("GH_APPAUTH_TEST_RUN", "1")
	err := shimProcess("pr", "list", "--kill-self").Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("err %v", err)
	}
	if ws := ee.Sys().(syscall.WaitStatus); !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Fatalf("shim exit: %v", ee)
	}
}

func TestShimForwardsSignal(t *testing.T) {
	shimEnv(t)
	t.Setenv("GH_APPAUTH_TEST_RUN", "1")
	t.Setenv("FAKEGH_REJECT", "")
	pr, pw, _ := os.Pipe()
	defer pr.Close()
	defer pw.Close()
	c := shimProcess("pr", "create", "--body-file", "-")
	c.Stdin = pr // fake gh waits for stdin that never ends
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	c.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if !errors.As(err, &ee) || !ee.Sys().(syscall.WaitStatus).Signaled() {
			t.Fatalf("shim exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		c.Process.Kill()
		t.Fatal("shim didn't stop")
	}
}

// SIGPIPE from `| head` must not cost raise's 1s wait.
func TestShimGHSigpipe(t *testing.T) {
	shimEnv(t)
	t.Setenv("GH_APPAUTH_TEST_RUN", "1")
	t.Setenv("FAKEGH_REJECT", "")
	start := time.Now()
	err := shimProcess("pr", "list", "--kill-pipe").Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 || time.Since(start) > 900*time.Millisecond {
		// TestMain turns any error from run into exit status 1.
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
}
