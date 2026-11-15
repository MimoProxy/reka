//go:build !windows

package api

import (
	"errors"
	"net"
)

func dialPipe(string) (net.Conn, error) {
	return nil, errors.New("control: named pipes exist only on Windows")
}
func pipeSuffix(string) string { return "" }
