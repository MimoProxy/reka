package service

import (
	"context"
	"fmt"
	D "github.com/miekg/dns"
	"net"
	"strings"
	"testing"
)

func TestDNSListenersSourceCacheAndFakeReload(t *testing.T) {
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	up := &D.Server{PacketConn: socket, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		m := new(D.Msg)
		m.SetReply(q)
		m.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}}
		w.WriteMsg(m)
	})}
	go up.ActivateAndServe()
	defer up.Shutdown()
	env := newEnv(t)
	s := env.open(DefaultProfile, "")
	defer s.Close()
	port := freePort(t)
	profile := fmt.Sprintf("schema-version: 1\ndns: {nameserver: ['udp://%s'], listen: '127.0.0.1:%d', enhanced-mode: fake-ip, fake-ip-range: 198.18.0.0/29, fake-ip-ttl: 1}\nrules: [{match: {all: true}, outbound: direct}]\n", socket.LocalAddr(), port)
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Profile: &profile})
	q := new(D.Msg)
	q.SetQuestion("fake.test.", D.TypeA)
	client := &D.Client{Net: "udp"}
	m, _, err := client.Exchange(q, fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil || len(m.Answer) != 1 {
		t.Fatal(m, err)
	}
	old := m.Answer[0].(*D.A).A.String()
	if !strings.HasPrefix(old, "198.18.") {
		t.Fatal(old)
	}
	profile = strings.Replace(profile, "198.18.0.0/29", "198.19.0.0/29", 1)
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Profile: &profile})
	m, _, err = client.Exchange(q, fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil || !strings.HasPrefix(m.Answer[0].(*D.A).A.String(), "198.19.") {
		t.Fatal(m, err)
	}
	// TCP listener uses the same generation and policy; real lookups bypass Fake IP.
	m, err = s.Engine().ExchangeDNS(context.Background(), q)
	if err != nil || len(m.Answer) != 1 {
		t.Fatal(m, err)
	}
	profile = strings.Replace(profile, "enhanced-mode: fake-ip", "enhanced-mode: redir-host", 1)
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Profile: &profile})
	client.Net = "tcp"
	m, _, err = client.Exchange(q, fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil || m.Answer[0].(*D.A).A.String() != "127.0.0.1" {
		t.Fatal("real upstream exchange", m, err)
	}
}
