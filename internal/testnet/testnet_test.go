package testnet

import (
	"errors"
	"net"
	"testing"
)

func TestListenTCPUDPSharesOnePort(t *testing.T) {
	listener, packet := ListenTCPUDP(t)
	if listener.Addr().(*net.TCPAddr).Port != packet.LocalAddr().(*net.UDPAddr).Port {
		t.Fatal(listener.Addr(), packet.LocalAddr())
	}
}

func TestRetryMovesPastTakenPort(t *testing.T) {
	busy, _ := ListenTCPUDP(t)
	_, err := net.Listen("tcp4", busy.Addr().String())
	if !InUse(err) {
		t.Fatalf("bind to a held port: %v", err)
	}
	calls := 0
	port := Retry(t, func(port uint16) error {
		calls++
		if calls == 1 {
			return err
		}
		return nil
	})
	if calls != 2 || port == 0 {
		t.Fatal(calls, port)
	}
	if InUse(errors.New("connection refused")) || InUse(nil) {
		t.Fatal("unrelated errors reported as a taken address")
	}
}
