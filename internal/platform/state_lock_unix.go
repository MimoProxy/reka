//go:build !windows

package platform

import (
	"golang.org/x/sys/unix"
	"os"
)

func lockStateFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
