//go:build !windows

package service

import (
	"fmt"
	"os"
	"syscall"
)

func profileDirectoryOwner(info os.FileInfo) error {
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("profile directory has a different owner")
	}
	return nil
}
