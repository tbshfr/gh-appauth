//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const canSignal = true

func inForegroundGroup() bool {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	defer tty.Close()
	pgrp, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP)
	return err == nil && pgrp == unix.Getpgrp()
}

// Only signals that end the shim anyway; SIGPIPE from `| head` just sets the
// exit code.
func raise(sig syscall.Signal) {
	switch sig {
	case syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP:
	default:
		return
	}
	signal.Reset(sig)
	_ = syscall.Kill(os.Getpid(), sig)
	// Another thread may take the signal; don't exit before it does.
	time.Sleep(time.Second)
}
