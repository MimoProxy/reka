//go:build windows

package service

import "os"

// Keep the existing single-profile Windows service unchanged. Workspaces need
// an explicit per-namespace ACL policy before they can be enabled on Windows.
func profileWorkspaceSupported() bool { return false }
func profileDirectoryOwner(info os.FileInfo) error {
	return errf(CodeBlocked, "Windows profile workspaces are not enabled")
}
