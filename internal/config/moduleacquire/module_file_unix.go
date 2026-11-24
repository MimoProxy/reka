//go:build unix

package moduleacquire

import "syscall"

const moduleFileNonblocking = syscall.O_NONBLOCK
