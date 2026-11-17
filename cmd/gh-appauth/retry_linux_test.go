package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Otherwise a timed-out command could still finish its side effect.
func TestShimKilledTakesGH(t *testing.T) {
	shimEnv(t)
	t.Setenv("GH_APPAUTH_TEST_RUN", "1")
	t.Setenv("FAKEGH_REJECT", "")
	marker := filepath.Join(t.TempDir(), "marker")
	t.Setenv("FAKEGH_MARKER", marker)
	c := shimProcess("pr", "merge", "--side-effect")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	c.Process.Kill()
	c.Wait()
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("gh kept running after the shim was killed")
	}
}

func TestShimCtrlCAtTerminal(t *testing.T) {
	shimEnv(t)
	t.Setenv("GH_APPAUTH_TEST_RUN", "1")
	t.Setenv("FAKEGH_REJECT", "")
	marker := filepath.Join(t.TempDir(), "marker")
	t.Setenv("FAKEGH_MARKER", marker)
	ptm, pts := openPTY(t)
	c := shimProcess("pr", "create", "--count-sigint")
	c.Stdin, c.Stdout, c.Stderr = pts, pts, pts
	// Foreground process group of the pty, as under a shell.
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pts.Close()
	go io.Copy(io.Discard, ptm)
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(marker + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			c.Process.Kill()
			t.Fatal("gh didn't start")
		}
	}
	ptm.Write([]byte{3}) // ^C
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shim exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		c.Process.Kill()
		t.Fatal("shim didn't stop")
	}
	if b, _ := os.ReadFile(marker); string(b) != "1" {
		t.Fatalf("gh got %q SIGINTs", b)
	}
}

func openPTY(t *testing.T) (ptm, pts *os.File) {
	t.Helper()
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() { ptm.Close() })
	fd := int(ptm.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	pts, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	return ptm, pts
}
