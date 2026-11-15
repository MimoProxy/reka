//go:build !windows

package secret

import (
	"errors"
	"syscall"
)

func isChmodUnsupported(error) bool { return false }

func isSyncDirUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP)
}
