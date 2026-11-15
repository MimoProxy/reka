package platform

import (
	"os"
	"os/exec"
	"testing"
)

func TestStateRootExclusiveUntilClose(t *testing.T) {
	root := t.TempDir()
	first, e := LockStateRoot(root)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	if second, e := LockStateRoot(root); e == nil {
		second.Close()
		t.Fatal("second kernel admitted before recovery")
	}
	if e = first.Close(); e != nil {
		t.Fatal(e)
	}
	third, e := LockStateRoot(root)
	if e != nil {
		t.Fatal(e)
	}
	third.Close()
}
func TestStateRootLockReleasedByProcessExit(t *testing.T) {
	if root := os.Getenv("REKA_LOCK_CHILD"); root != "" {
		if _, e := LockStateRoot(root); e != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	root := t.TempDir()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestStateRootLockReleasedByProcessExit$")
	cmd.Env = append(os.Environ(), "REKA_LOCK_CHILD="+root)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	l, e := LockStateRoot(root)
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
}
