//go:build windows

package service

import (
	"os"
	"testing"
)

func TestWindowsProfileWorkspaceFailsClosedWithoutChangingSingleProfileState(t *testing.T) {
	root := t.TempDir()
	workspace, err := OpenProfileWorkspace(root, "alpha", false, true)
	if workspace != nil {
		workspace.Close()
		t.Fatal("workspace unexpectedly enabled without a namespace ACL policy")
	}
	exportErrorCode(t, err, CodeBlocked)
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 0 {
		t.Fatal("unsupported workspace changed state", files, err)
	}
}
