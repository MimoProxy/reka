package core

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/testnet"
	D "github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

type socketOwnerHost struct {
	fakeHost
	origin string
	seen   chan string
}

func (h *socketOwnerHost) FindProcess(_, _, destination string) string {
	select {
	case h.seen <- destination:
	default:
	}
	if destination == h.origin {
		return "self.app"
	}
	return ""
}

// The router reverses Fake IP to a domain, but the host's OS ownership API
// still needs the original socket peer. Test both an allowed connection and
// a process-rule rejection through the real embedded API and SOCKS inbound.
func TestProcessOwnerUsesOriginalSocketWithFakeIP(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dns := &D.Server{PacketConn: upstream, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		a := new(D.Msg)
		a.SetReply(q)
		a.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)}}
		_ = w.WriteMsg(a)
	})}
	go func() { _ = dns.ActivateAndServe() }()
	defer dns.Shutdown()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	var proxyAddress, dnsAddress string
	var host *socketOwnerHost
	var in *Instance
	testnet.RetryPorts(t, 2, func(ports []uint16) (err error) {
		proxyAddress, dnsAddress = fmt.Sprintf("127.0.0.1:%d", ports[0]), fmt.Sprintf("127.0.0.1:%d", ports[1])
		host = &socketOwnerHost{origin: proxyAddress, seen: make(chan string, 8)}
		profile := fmt.Sprintf("schema-version: 1\ndns:\n nameserver: [%q]\n default-nameserver: [%q]\n listen: %q\n enhanced-mode: fake-ip\nrules:\n - {id: app, match: {process-name: other.app}, outbound: reject}\n - {id: final, match: {all: true}, outbound: direct}\n", upstream.LocalAddr().String(), upstream.LocalAddr().String(), dnsAddress)
		local := fmt.Sprintf("listeners: [{id: mixed, type: mixed, listen: %q}]\n", proxyAddress)
		in, err = Start(Options{StateRoot: t.TempDir(), InitialProfile: []byte(profile), InitialLocal: []byte(local), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, host)
		return err
	})
	defer in.Stop()
	var hello map[string]any
	if err = json.Unmarshal(in.Call([]byte(`{"id":1,"method":"Hello","params":{"versions":[1]}}`)), &hello); err != nil || hello["error"] != nil {
		t.Fatalf("handshake: %v, %v", hello, err)
	}
	question := new(D.Msg)
	question.SetQuestion("owner.fake.test.", D.TypeA)
	answer, _, err := (&D.Client{Timeout: 2 * time.Second}).Exchange(question, dnsAddress)
	if err != nil || len(answer.Answer) == 0 {
		t.Fatalf("Fake IP query: %v, %v", answer, err)
	}
	fakeIP := answer.Answer[0].(*D.A).A.String()
	if !netip.MustParsePrefix("198.18.0.0/16").Contains(netip.MustParseAddr(fakeIP)) {
		t.Fatalf("not a Fake IP: %s", fakeIP)
	}
	dialer, _ := proxy.SOCKS5("tcp", proxyAddress, nil, &net.Dialer{Timeout: 2 * time.Second})
	target := net.JoinHostPort(fakeIP, fmt.Sprint(echo.Addr().(*net.TCPAddr).Port))
	c, err := dialer.Dial("tcp", target)
	if err != nil {
		t.Fatal("wrong package must leave forwarding intact:", err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(c, "owner")
	buffer := make([]byte, 5)
	_, err = io.ReadFull(c, buffer)
	c.Close()
	if err != nil || string(buffer) != "owner" {
		t.Fatalf("baseline forwarding: %q, %v", buffer, err)
	}
	request := []byte(`{"id":2,"method":"CommitConfiguration","params":{"base_revision":1,"patch":[{"op":"set","path":"/rules/app/match","value":{"process-name":"self.app"}}]}}`)
	var response struct {
		Result struct {
			State string `json:"state"`
		} `json:"result"`
	}
	encoded := in.Call(request)
	if err = json.Unmarshal(encoded, &response); err != nil || response.Result.State != "committed" {
		t.Fatalf("commit: %s, %v", encoded, err)
	}
	c, err = dialer.Dial("tcp", target)
	if err == nil {
		c.Close()
		t.Fatal("process rule did not reject socket")
	}
	for n := 0; n < 2; n++ {
		select {
		case destination := <-host.seen:
			if destination != proxyAddress {
				t.Fatalf("ownership saw rewritten destination %q; expected original socket %q", destination, proxyAddress)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("host lookup not invoked")
		}
	}
}
