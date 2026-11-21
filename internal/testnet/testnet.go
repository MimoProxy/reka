// Package testnet gives tests loopback ports without a window in which
// another process can take a port the test released and expects to bind
// again.
//
// Tests that own every socket use ListenTCPUDP and pass the open sockets on.
// Tests that hand a port to code which binds it itself use Retry: the port
// is chosen, the code binds it, and a collision with another process picks
// a new port instead of failing the test.
package testnet

import (
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const attempts = 64

var loopback = netip.MustParseAddr("127.0.0.1")

// InUse reports whether err says a local address could not be bound
// because something else holds it. Errors that only keep the text, such as
// diagnostics, are recognised by their message.
func InUse(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	text := err.Error()
	for _, message := range []string{
		"address already in use",
		// Windows: WSAEADDRINUSE, and WSAEACCES for excluded port ranges.
		"Only one usage of each socket address",
		"forbidden by its access permissions",
	} {
		if strings.Contains(text, message) {
			return true
		}
	}
	return false
}

// ListenTCPUDP binds TCP and UDP on the same loopback port and closes both
// when the test ends.
func ListenTCPUDP(t testing.TB) (net.Listener, net.PacketConn) {
	t.Helper()
	for range attempts {
		listener, packet, err := listenPair()
		if err == nil {
			t.Cleanup(func() { listener.Close(); packet.Close() })
			return listener, packet
		}
	}
	t.Fatal("no loopback port free for both TCP and UDP")
	return nil, nil
}

// Retry calls start with a loopback port until start succeeds, and returns
// that port. A start that fails because the port is taken is retried with
// another port; any other failure ends the test. start must release
// whatever it bound before it reports a failure.
func Retry(t testing.TB, start func(port uint16) error) uint16 {
	t.Helper()
	return RetryPorts(t, 1, func(ports []uint16) error { return start(ports[0]) })[0]
}

// RetryPorts is Retry for a start that binds n distinct ports at once.
func RetryPorts(t testing.TB, n int, start func(ports []uint16) error) []uint16 {
	t.Helper()
	var last error
	for range attempts {
		ports, err := candidates(n)
		if err == nil {
			if err = start(ports); err == nil {
				return ports
			}
			if !InUse(err) {
				t.Fatal(err)
			}
		}
		last = err
	}
	t.Fatal("no loopback ports could be bound:", last)
	return nil
}

// RetryAddr is Retry with the port as a loopback address.
func RetryAddr(t testing.TB, start func(address netip.AddrPort) error) netip.AddrPort {
	t.Helper()
	return netip.AddrPortFrom(loopback, Retry(t, func(port uint16) error {
		return start(netip.AddrPortFrom(loopback, port))
	}))
}

// candidates returns n distinct ports that were free for both TCP and UDP
// a moment ago. Ports are random rather than ephemeral so that a reserved
// range on Windows is not walked one port at a time, and starting from UDP
// finds both of its exclusion tables.
func candidates(n int) ([]uint16, error) {
	ports := make([]uint16, 0, n)
	var held []io.Closer
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for len(ports) < n {
		listener, packet, err := listenPair()
		if err != nil {
			return nil, err
		}
		held = append(held, listener, packet)
		ports = append(ports, uint16(packet.LocalAddr().(*net.UDPAddr).Port))
	}
	return ports, nil
}

func listenPair() (net.Listener, net.PacketConn, error) {
	address := net.JoinHostPort(loopback.String(), strconv.Itoa(1024+rand.IntN(65536-1024)))
	packet, err := net.ListenPacket("udp4", address)
	if err != nil {
		return nil, nil, err
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		packet.Close()
		return nil, nil, err
	}
	return listener, packet, nil
}
