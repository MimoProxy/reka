//go:build windows

package service

import "os"

func profileDirectoryOwner(info os.FileInfo) error { return nil }
