//go:build !linux

package main

import "syscall"

func childSysProcAttr() *syscall.SysProcAttr { return nil }
