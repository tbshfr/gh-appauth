//go:build windows

package main

import "syscall"

func raise(syscall.Signal) {}

func inForegroundGroup() bool { return false }
