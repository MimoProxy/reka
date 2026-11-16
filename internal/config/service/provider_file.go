package service

import (
	"errors"
	"io"
	"os"

	"github.com/MimoProxy/reka/internal/resource"
)

// Remote paths are interpreted only inside an explicit local root. os.Root
// rejects parent traversal, absolute paths and symlinks escaping that root.
func readProviderFile(directory, path string) ([]byte, error) {
	if directory == "" {
		return nil, errors.New("provider_directory_required")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("provider_directory_unavailable")
	}
	defer root.Close()
	info, err := root.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("provider_file_unavailable")
	}
	file, err := root.Open(path)
	if err != nil {
		return nil, errors.New("provider_file_unavailable")
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > resource.MaxSize {
		return nil, errors.New("provider_file_invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, resource.MaxSize+1))
	if err != nil || len(data) == 0 || len(data) > resource.MaxSize {
		return nil, errors.New("provider_file_invalid")
	}
	return data, nil
}
