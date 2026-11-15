//go:build !windows

package control

import (
	"errors"
	"net"
)

var errNoPipes = errors.New("control: named pipes exist only on Windows")

func listenPipe(string) (net.Listener, error) { return nil, errNoPipes }
