package sagernet

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type endpointTestPacketConn struct {
	N.PacketConn
	closed bool
}

func (c *endpointTestPacketConn) Close() error {
	c.closed = true
	return nil
}

type endpointTestDNSWriter struct{ writes int }

func (w *endpointTestDNSWriter) WritePacket(packet *buf.Buffer, _ M.Socksaddr) error {
	packet.Release()
	w.writes++
	return nil
}

func TestEndpointRouterRejectsInbound(t *testing.T) {
	b := New(Options{})
	defer b.Close()
	ctx := b.endpointContext(b.ctx, nil)
	r := service.FromContext[adapter.Router](ctx)
	md := adapter.InboundContext{}
	if got := r.PreMatch(md, nil).Action; got != adapter.PreMatchReject {
		t.Fatal("endpoint allowed inbound flow", got)
	}
	c, other := net.Pipe()
	defer other.Close()
	other.SetReadDeadline(time.Now().Add(time.Second))
	var callbacks int
	checkClose := func(err error) {
		if !errors.Is(err, errEndpointInbound) {
			t.Fatal("missing endpoint rejection", err)
		}
		callbacks++
	}
	r.RouteConnectionEx(ctx, c, md, checkClose)
	var buf [1]byte
	if _, err := other.Read(buf[:]); !errors.Is(err, io.EOF) {
		t.Fatal("peer TCP remained open", err)
	}
	packet := new(endpointTestPacketConn)
	r.RoutePacketConnectionEx(ctx, packet, md, checkClose)
	if !packet.closed || callbacks != 2 {
		t.Fatal("expected both inbound flows to close with a rejection")
	}
	dns := new(endpointTestDNSWriter)
	r.HijackDNSPacket(ctx, []byte{0}, dns, md)
	if dns.writes != 0 {
		t.Fatal("endpoint answered inbound DNS")
	}
}

func TestEndpointBoundDialerKeepsProtect(t *testing.T) {
	var calls atomic.Int32
	b := New(Options{ProtectFD: func(int) error { calls.Add(1); return nil }})
	defer b.Close()
	ctx := b.endpointContext(b.ctx, b.protect)
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		// Match the explicitly bound NewDefault dialer in WireGuard's CreateDialer.
		d, err := dialer.NewDefault(ctx, option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: iface.Name}})
		if err != nil {
			t.Fatal(err)
		}
		if _, usePool := d.UDPListenerControl(); usePool {
			t.Fatal("endpoint enabled the UDP egress pool with no interface monitor")
		}
		c, err := d.ListenPacket(ctx, M.ParseSocksaddr("127.0.0.1:53"))
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if calls.Load() != 1 {
			t.Fatalf("bound UDP socket protected %d times", calls.Load())
		}
		return
	}
	t.Skip("host has no loopback interface")
}
