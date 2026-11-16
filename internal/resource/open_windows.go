//go:build windows

package resource

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func openNoFollow(dir, hash string) (*os.File, error) {
	for _, path := range []string{filepath.Dir(dir), dir} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, ErrCorrupt
		}
	}
	path := filepath.Join(dir, hash)
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrCorrupt
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return nil, ErrCorrupt
	}
	f := os.NewFile(uintptr(handle), path)
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		f.Close()
		return nil, ErrCorrupt
	}
	return f, nil
}
