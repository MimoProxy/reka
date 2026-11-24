package generation

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"testing"

	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/testnet"
	D "github.com/miekg/dns"
	"github.com/sagernet/sing-tun/dnsinfo"
)

func TestSystemDNSServersUsePhysicalScope(t *testing.T) {
	tunnel := netip.MustParseAddrPort("172.27.255.2:53")
	wifi := netip.MustParseAddrPort("192.0.2.53:53")
	wifi6 := netip.MustParseAddrPort("[fe80::1%en0]:53")
	cellular := netip.MustParseAddrPort("198.51.100.53:53")
	config := &dnsinfo.Configuration{
		Resolvers: []dnsinfo.Resolver{{Servers: []netip.AddrPort{tunnel}}},
		ScopedResolvers: []dnsinfo.Resolver{
			{InterfaceIndex: 4, Servers: []netip.AddrPort{wifi, wifi6, wifi, tunnel}},
			{InterfaceIndex: 5, Servers: []netip.AddrPort{cellular}},
		},
	}
	excluded := []netip.Prefix{netip.MustParsePrefix("172.27.255.0/30")}
	if got := systemDNSServers(config, 4, excluded); !slices.Equal(got, []netip.AddrPort{wifi, wifi6}) {
		t.Fatalf("Wi-Fi servers: %v", got)
	}
	if got := systemDNSServers(config, 5, excluded); !slices.Equal(got, []netip.AddrPort{cellular}) {
		t.Fatalf("cellular servers: %v", got)
	}
	if got := systemDNSServers(config, 6, excluded); len(got) != 0 {
		t.Fatalf("selected the VPN DNS as upstream: %v", got)
	}
}

func TestSystemDNSQueriesRetainWireAnswers(t *testing.T) {
	listener, packet := testnet.ListenTCPUDP(t)
	alias := dnsRecordForTest(t, "entry.test. 90 IN CNAME middle.test.")
	secondAlias := dnsRecordForTest(t, "middle.test. 80 IN CNAME endpoint.test.")
	address := dnsRecordForTest(t, "endpoint.test. 75 IN A 192.0.2.21")
	https := dnsRecordForTest(t, "endpoint.test. 65 IN HTTPS 1 . alpn=h2,h3")
	authority := dnsRecordForTest(t, "test. 120 IN NS nameserver.test.")
	udp := &D.Server{PacketConn: packet, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		m := new(D.Msg).SetReply(q)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})}
	tcp := &D.Server{Listener: listener, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		m := new(D.Msg).SetReply(q)
		switch q.Question[0].Qtype {
		case D.TypeA:
			m.Answer = []D.RR{alias, secondAlias, address}
		case D.TypeHTTPS:
			m.Answer = []D.RR{alias, secondAlias, https}
		case D.TypeCNAME:
			m.Answer = []D.RR{alias}
		}
		m.Ns = []D.RR{authority}
		_ = w.WriteMsg(m)
	})}
	for _, server := range []*D.Server{udp, tcp} {
		started := make(chan struct{})
		server.NotifyStartedFunc = func() { close(started) }
		go server.ActivateAndServe()
		<-started
		defer server.Shutdown()
	}

	endpoint := netip.MustParseAddrPort(listener.Addr().String())
	store := history.NewBounded(8, 32<<10, history.DNS)
	dialer := new(net.Dialer)
	resolver, err := RD.New(RD.Config{Nameservers: []string{"system"}}, RD.Options{
		History: store,
		SystemExchange: func(ctx context.Context, q *D.Msg) (*D.Msg, netip.Addr, error) {
			return exchangeSystemDNS(ctx, q, []netip.AddrPort{endpoint}, func(ctx context.Context, network, address, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, address)
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Retire()
	for _, test := range []struct {
		qtype   uint16
		records []D.RR
	}{
		{D.TypeA, []D.RR{alias, secondAlias, address}},
		{D.TypeHTTPS, []D.RR{alias, secondAlias, https}},
		{D.TypeCNAME, []D.RR{alias}},
	} {
		q := new(D.Msg).SetQuestion("entry.test.", test.qtype)
		m, err := resolver.Exchange(t.Context(), q, "normal", false)
		if err != nil || len(m.Answer) != len(test.records) || len(m.Ns) != 1 {
			t.Fatalf("type %d response=%v error=%v", test.qtype, m, err)
		}
		page, err := store.List(history.DNS, "", history.ListOptions{Limit: 1})
		if err != nil || len(page.Rows) != 1 {
			t.Fatalf("history=%+v error=%v", page, err)
		}
		var record struct {
			Source  string   `json:"result_source"`
			Servers []string `json:"system_servers"`
			Answers []struct {
				Name string
				Type string
				TTL  uint32
				Data string
			}
		}
		if err := json.Unmarshal(page.Rows[0].Data, &record); err != nil {
			t.Fatal(err)
		}
		if record.Source != "system" || !slices.Equal(record.Servers, []string{endpoint.Addr().String()}) ||
			len(record.Answers) != len(test.records) {
			t.Fatalf("history record: %+v", record)
		}
		for i, rr := range test.records {
			got, header := record.Answers[i], rr.Header()
			if rr.String() != m.Answer[i].String() || got.Name != header.Name ||
				got.Type != D.TypeToString[header.Rrtype] || got.TTL != header.Ttl {
				t.Fatalf("returned or recorded answer %d changed: %+v", i, got)
			}
			if cname, ok := rr.(*D.CNAME); ok && got.Data != cname.Target {
				t.Fatalf("CNAME target was not retained: %+v", got)
			}
		}
	}
}

func dnsRecordForTest(t *testing.T, text string) D.RR {
	t.Helper()
	rr, err := D.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
