//go:build windows

package main

import "syscall"

// Windows can't send these to another process, and the console already gives
// gh Ctrl-C, so gh's own result decides. The shim still catches them, to
// outlive gh.
const canSignal = false

func raise(syscall.Signal) {}

func inForegroundGroup() bool { return false }
