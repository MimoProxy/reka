package acceptance

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/service"
	D "github.com/miekg/dns"
)

func loopbackDNSUpstream(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	queries := new(atomic.Int32)
	up := &D.Server{PacketConn: socket, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		queries.Add(1)
		m := new(D.Msg)
		m.SetReply(q)
		if question := q.Question[0]; question.Qtype == D.TypeA {
			m.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: question.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)}}
		}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	up.NotifyStartedFunc = func() { close(started) }
	go up.ActivateAndServe()
	<-started
	t.Cleanup(func() { _ = up.Shutdown() })
	return "udp://" + socket.LocalAddr().String(), queries
}

func TestFakeIPFlowsGenerationsAndRestart(t *testing.T) {
	upstream, _ := loopbackDNSUpstream(t)
	profile := fmt.Sprintf("schema-version: 1\ndns: {nameserver: [%q], enhanced-mode: fake-ip, fake-ip-range: 198.18.0.0/29, fake-ip-ttl: 1}\nrules: [{id: named, match: {domain: echo.test}, outbound: direct},{id: final, match: {all: true}, outbound: reject}]", upstream)
	h := newHarness(t, profile)
	target := echoServer(t)
	allocate := func() netip.Addr {
		q := new(D.Msg)
		q.SetQuestion("echo.test.", D.TypeA)
		reply, err := h.engine().ExchangeDNS(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		a, ok := netip.AddrFromSlice(reply.Answer[0].(*D.A).A)
		if !ok {
			t.Fatal("invalid fake response")
		}
		return a.Unmap()
	}
	first := allocate()
	conn, err := socks5Connect(h.proxy(), netip.AddrPortFrom(first, target.Port()))
	if err != nil {
		t.Fatal("fake TCP connect", err)
	}
	defer conn.Close()
	echo := func() {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		payload := []byte("pinned-fake-domain")
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(payload, got) {
			t.Fatal("fake TCP echo", err)
		}
	}
	echo()
	profile = strings.ReplaceAll(strings.Replace(profile, "198.18.0.0/29", "198.19.0.0/29", 1), "fake-ip-ttl: 1", "fake-ip-ttl: 60")
	h.mustCommit(service.CommitRequest{ChangeRequest: service.ChangeRequest{Profile: &profile}})
	second := allocate()
	if first == second {
		t.Fatal("range update reused old fake address")
	}
	time.Sleep(1100 * time.Millisecond)
	echo()
	conn.Close()
	waitFor(t, "old fake flow drained", 3*time.Second, func() bool { return len(h.engine().Connections()) == 0 })
	h.svc.Close()
	h.open("")
	restored, err := socks5Connect(h.proxy(), netip.AddrPortFrom(second, target.Port()))
	if err != nil {
		t.Fatal("persisted fake address lost", err)
	}
	restored.SetDeadline(time.Now().Add(2 * time.Second))
	restored.Write([]byte("restored"))
	got := make([]byte, 8)
	if _, err = io.ReadFull(restored, got); err != nil || string(got) != "restored" {
		t.Fatal("restored fake route", err)
	}
	restored.Close()
	udp := udpEcho(t)
	assoc := associate(t, h.proxy())
	destination := netip.AddrPortFrom(second, udp.Port())
	assoc.send(destination, "fake-udp")
	replies := assoc.recv(time.Second)
	if replies[destination.String()] != "fake-udp" {
		t.Fatal("fake UDP destination/reply rewrite", replies)
	}

}

func TestRedirHostProxyAndDirectFlowsAcrossReload(t *testing.T) {
	upstream, queries := loopbackDNSUpstream(t)
	requests := make(chan string, 2)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Method + " " + r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	base := fmt.Sprintf(`schema-version: 1
sniff: {enabled: false}
outbounds: [{id: relay, type: http, server: 127.0.0.1, port: %d}]
`, proxy.Listener.Addr().(*net.TCPAddr).Port)
	h := newHarness(t, base+fmt.Sprintf("dns: {nameserver: [%q]}\n", upstream)+`rules:
  - {match: {domain-suffix: google.com}, outbound: relay}
  - {match: {all: true}, outbound: reject}
`)
	reply, err := h.engine().ExchangeDNS(t.Context(), new(D.Msg).SetQuestion("www.google.com.", D.TypeA))
	if err != nil || len(reply.Answer) != 1 {
		t.Fatalf("client DNS reply = %v, error = %v", reply, err)
	}
	record, ok := reply.Answer[0].(*D.A)
	if !ok {
		t.Fatalf("expected A record, got %v", reply.Answer)
	}
	ip, ok := netip.AddrFromSlice(record.A)
	if !ok || ip.Unmap() != netip.MustParseAddr("127.0.0.1") || queries.Load() != 1 {
		t.Fatalf("client address = %v, upstream queries = %d", ip, queries.Load())
	}
	ip = ip.Unmap()
	checkProxyTarget := func(target netip.AddrPort, want string) {
		t.Helper()
		conn, err := socks5Connect(h.proxy(), target)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		select {
		case got := <-requests:
			if got != "CONNECT "+want {
				t.Fatalf("upstream proxy received %q, want CONNECT %s", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no upstream proxy request for %s", target)
		}
	}
	checkProxyTarget(netip.AddrPortFrom(ip, 443), "www.google.com:443")

	// Change the DNS configuration to discard the lookup cache. Only the
	// engine's reverse mapping can join the domain and the original address.
	profile := base + fmt.Sprintf("dns: {nameserver: [%q], direct-nameserver: [%q]}\n", upstream, upstream) + `rules:
  - {match: {and: [{domain-suffix: google.com}, {ip-cidr: 127.0.0.0/8, no-resolve: true}]}, outbound: direct}
  - {match: {all: true}, outbound: relay}
`
	h.mustCommit(service.CommitRequest{ChangeRequest: service.ChangeRequest{Profile: &profile}})
	target := netip.AddrPortFrom(ip, echoServer(t).Port())
	conn, err := socks5Connect(h.proxy(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	const payload = "direct echo"
	if _, err = io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil || string(got) != payload {
		t.Fatalf("direct TCP echo = %q, error = %v", got, err)
	}
	connections := connsByDest(h, target.String())
	if len(connections) != 1 {
		t.Fatalf("direct TCP connections to %s = %v", target, connections)
	}
	timeline, ok := h.engine().ConnectionTimeline(connections[0].ID)
	if !ok {
		t.Fatal("missing direct connection timeline")
	}
	found := false
	for _, event := range timeline.Trace.Events {
		if event.Kind == "fakeip" {
			t.Fatal("real DNS answer reported as Fake IP")
		}
		if event.Kind == "dns_mapping" && event.Name == "www.google.com" && event.Addr == ip.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing DNS mapping in connection events: %+v", timeline.Trace.Events)
	}
	udp := netip.AddrPortFrom(ip, udpEcho(t).Port())
	assoc := associate(t, h.proxy())
	assoc.send(udp, payload)
	if got := assoc.recv(time.Second); got[udp.String()] != payload {
		t.Fatalf("direct UDP echo = %v", got)
	}
	unmapped := netip.MustParseAddrPort("192.0.2.17:443")
	checkProxyTarget(unmapped, unmapped.String())
	if count := queries.Load(); count != 1 {
		t.Fatalf("upstream received %d queries, want only the original client query", count)
	}
}

func TestRedirHostSharedAnswerUsesSniffedServerName(t *testing.T) {
	upstream, _ := loopbackDNSUpstream(t)
	requests := make(chan string, 2)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Method + " " + r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	// Sniffing keeps its defaults. The upstream answers every name with the
	// same address, as a resolver returning polluted answers often does.
	h := newHarness(t, fmt.Sprintf(`schema-version: 1
outbounds: [{id: relay, type: http, server: 127.0.0.1, port: %d}]
dns: {nameserver: [%q]}
rules:
  - {match: {domain-suffix: example.com}, outbound: relay}
  - {match: {domain-suffix: example.net}, outbound: relay}
  - {match: {all: true}, outbound: reject}
`, proxy.Listener.Addr().(*net.TCPAddr).Port, upstream))
	var ip netip.Addr
	for _, name := range []string{"www.example.com.", "www.example.net."} {
		reply, err := h.engine().ExchangeDNS(t.Context(), new(D.Msg).SetQuestion(name, D.TypeA))
		if err != nil || len(reply.Answer) != 1 {
			t.Fatalf("client DNS reply for %s = %v, error = %v", name, reply, err)
		}
		record, ok := reply.Answer[0].(*D.A)
		if !ok {
			t.Fatalf("expected A record for %s, got %v", name, reply.Answer)
		}
		ip, _ = netip.AddrFromSlice(record.A)
		ip = ip.Unmap()
	}
	// The address now maps to the second name, but the client connects to the
	// first one, as its TLS server name shows.
	conn, err := socks5Connect(h.proxy(), netip.AddrPortFrom(ip, 443))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	go func() {
		_ = tls.Client(conn, &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true}).Handshake()
	}()
	select {
	case got := <-requests:
		if got != "CONNECT www.example.com:443" {
			t.Fatalf("upstream proxy received %q, want CONNECT www.example.com:443", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no upstream proxy request")
	}
}
