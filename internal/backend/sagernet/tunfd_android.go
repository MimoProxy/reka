//go:build android

package sagernet

import "golang.org/x/sys/unix"

func duplicateTUNFD(fd int) (int, error) { return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0) }
func closeTUNFD(fd int)                  { _ = unix.Close(fd) }
