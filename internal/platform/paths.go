// Package platform holds per-platform conventions. System takeover (TUN,
// routes, system DNS and proxy) will live here too.
package platform

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultStateRoot is where a user-mode kernel keeps its state:
//
//	macOS    ~/Library/Application Support/Reka
//	Windows  %LOCALAPPDATA%\Reka
//	Linux    $XDG_STATE_HOME/reka, else ~/.local/state/reka
//
// Android hosts always pass the app's private directory instead.
func DefaultStateRoot() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "Reka"), nil
	case "windows":
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			return filepath.Join(dir, "Reka"), nil
		}
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "Reka"), nil
	}
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "reka"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "reka"), nil
}
