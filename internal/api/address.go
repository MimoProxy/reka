package api

import (
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strings"
)

// ParseAddress splits a control address into its transport and target:
//
//	unix:///path/to/control.sock   (macOS, Linux, Android)
//	pipe://name                    (Windows: \\.\pipe\name)
//
// A bare absolute path is a Unix socket.
func ParseAddress(addr string) (network, target string, err error) {
	switch {
	case strings.HasPrefix(addr, "unix://"):
		return "unix", strings.TrimPrefix(addr, "unix://"), nil
	case strings.HasPrefix(addr, "pipe://"):
		return "pipe", `\\.\pipe\` + strings.TrimPrefix(addr, "pipe://"), nil
	case strings.HasPrefix(addr, `\\.\pipe\`):
		return "pipe", addr, nil
	case filepath.IsAbs(addr):
		return "unix", addr, nil
	}
	return "", "", fmt.Errorf("control: unsupported address %q (use unix:///path or pipe://name)", addr)
}

// DefaultAddress is where the control API listens for a state root when
// nothing else is configured.
func DefaultAddress(stateRoot string) string {
	if runtime.GOOS == "windows" {
		return "pipe://reka-" + pipeSuffix(stateRoot)
	}
	return "unix://" + filepath.Join(stateRoot, "control.sock")
}

// Dial connects to a control endpoint.
func Dial(addr string) (net.Conn, error) {
	network, target, err := ParseAddress(addr)
	if err != nil {
		return nil, err
	}
	if network == "pipe" {
		return dialPipe(target)
	}
	return net.Dial("unix", target)
}
