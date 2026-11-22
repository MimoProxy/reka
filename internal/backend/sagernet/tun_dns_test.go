package sagernet

import (
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/platform"
	D "github.com/miekg/dns"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

func TestTUNUDPDNSOverflow(t *testing.T) {
	backend := New(Options{Logger: slog.New(slog.DiscardHandler)})
	t.Cleanup(func() { _ = backend.Close() })
	inbound := &TUNInbound{
		b: backend, cfg: platform.TUNConfig{DNSHijack: true},
		slots: make(chan struct{}, 1),
	}
	inbound.slots <- struct{}{}
	src := M.SocksaddrFromNetIP(netip.MustParseAddrPort("198.18.0.2:50000"))
	dst := M.SocksaddrFromNetIP(netip.MustParseAddrPort("192.0.2.1:53"))

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		inbound.NewPacketConnectionEx(t.Context(), bufio.NewUnbindPacketConnWithAddr(server, dst), src, dst, nil)
	}()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	query := new(D.Msg).SetQuestion("example.test.", D.TypeAAAA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(wire); err != nil {
		t.Fatal(err)
	}
	n, err := client.Read(wire)
	if err != nil {
		t.Fatal(err)
	}
	var reply D.Msg
	if err := reply.Unpack(wire[:n]); err != nil {
		t.Fatal(err)
	}
	if !reply.Response || reply.Id != query.Id || reply.Rcode != D.RcodeServerFailure || !slices.Equal(reply.Question, query.Question) {
		t.Fatalf("unexpected DNS reply: %v", &reply)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("overflow handler did not close the connection")
	}
	if got := inbound.dnsOverflow.Load(); got != 1 {
		t.Fatalf("DNS overflow count = %d, want 1", got)
	}
}
