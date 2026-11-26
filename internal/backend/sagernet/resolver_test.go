package sagernet

import (
	"context"
	"net"
	"syscall"
	"testing"
)

func TestNewResolverUsesSystemResolverWhenAsked(t *testing.T) {
	r := newResolver(true, nil)
	if r.PreferGo || r.Dial != nil {
		t.Fatalf("system resolver = %+v, want the zero net.Resolver", r)
	}
}

func TestNewResolverProtectsGoResolverSockets(t *testing.T) {
	protected := make(chan struct{}, 1)
	r := newResolver(false, func(_, _ string, _ syscall.RawConn) error {
		protected <- struct{}{}
		return nil
	})
	if !r.PreferGo || r.Dial == nil {
		t.Fatalf("Go resolver = %+v, want PreferGo with a dialer", r)
	}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := r.Dial(context.Background(), "udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case <-protected:
	default:
		t.Fatal("Go resolver dialed without applying Protect")
	}
}
