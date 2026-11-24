//go:build unix

package service

import "syscall"

const moduleFileNonblocking = syscall.O_NONBLOCK
