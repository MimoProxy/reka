//go:build windows

package secret

// Windows cannot fsync a directory; renames are made durable by NTFS
// journaling.
func isChmodUnsupported(error) bool   { return true }
func isSyncDirUnsupported(error) bool { return true }
