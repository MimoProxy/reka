//go:build unix

package resource

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Open every component beneath the trusted state root without following links.
// Relative descriptor traversal prevents a concurrent rename from redirecting
// a privileged resource read to a client-chosen filesystem path.
func openNoFollow(dir, hash string) (*os.File, error) {
	parent, err := unix.Open(filepath.Dir(dir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	root, err := unix.Openat(parent, filepath.Base(dir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	fd, err := unix.Openat(root, hash, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), hash), nil
}
