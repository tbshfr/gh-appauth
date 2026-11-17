package main

import "syscall"

// So gh doesn't outlive a timed-out shim, even one killed with SIGKILL.
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
