//go:build darwin

package store

import (
	"os"

	"golang.org/x/sys/unix"
)

// syncFile passes f's data to the drive without flushing the drive cache.
func syncFile(f *os.File) error { return unix.Fsync(int(f.Fd())) }

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return unix.Fsync(int(d.Fd()))
}

// barrier flushes the drive cache (F_FULLFSYNC), which covers every file
// synced before it, not only dir.
func barrier(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	_, err = unix.FcntlInt(d.Fd(), unix.F_FULLFSYNC, 0)
	return err
}
