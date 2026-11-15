//go:build !windows

package control

import (
	"errors"
	"net"
)

var errNoPipes = errors.New("control: named pipes exist only on Windows")

func listenPipe(string) (net.Listener, error) { return nil, errNoPipes }
func dialPipe(string) (net.Conn, error)       { return nil, errNoPipes }
func pipeSuffix(string) string                { return "" }
