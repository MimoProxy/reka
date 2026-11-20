package sagernet

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

func TestDHCPDNSUsesLeaseServerAndRetriesTruncation(t *testing.T) {
	listen, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp4", listen.Addr().String())
	if err != nil {
		listen.Close()
		t.Fatal(err)
	}
	udp := &D.Server{PacketConn: packet, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		answer := new(D.Msg).SetReply(q)
		answer.Truncated = true
		_ = w.WriteMsg(answer)
	})}
	tcp := &D.Server{Listener: listen, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		answer := new(D.Msg).SetReply(q)
		record, _ := D.NewRR("dhcp.test. 600 IN TXT \"from lease resolver\"")
		answer.Answer = []D.RR{record}
		_ = w.WriteMsg(answer)
	})}
	for _, server := range []*D.Server{udp, tcp} {
		started := make(chan struct{})
		server.NotifyStartedFunc = func() { close(started) }
		go server.ActivateAndServe()
		<-started
		defer server.Shutdown()
	}
	_, port, _ := net.SplitHostPort(listen.Addr().String())
	q := new(D.Msg).SetQuestion("dhcp.test.", D.TypeTXT)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var networks []string
	dialer := new(net.Dialer)
	got, err := exchangeDHCPDNS(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, port, q,
		func(ctx context.Context, network, address string) (net.Conn, error) {
			networks = append(networks, network)
			if address != listen.Addr().String() {
				t.Fatalf("unexpected resolver %q", address)
			}
			return dialer.DialContext(ctx, network, address)
		})
	if err != nil || len(got.Answer) != 1 || got.Answer[0].Header().Ttl != 30 ||
		len(networks) != 2 || networks[0] != "udp" || networks[1] != "tcp" {
		t.Fatalf("reply=%+v transports=%v err=%v", got, networks, err)
	}
}
