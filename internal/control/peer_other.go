//go:build !darwin && !linux && !windows

package control

import "net"

// Other Unix systems rely on the socket's 0600 mode alone.
func checkPeer(net.Conn) error { return nil }
