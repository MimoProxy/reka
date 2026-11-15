package acceptance

import (
	"bytes"
	"context"
	"fmt"
	"github.com/MimoProxy/reka/internal/config/service"
	D "github.com/miekg/dns"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestFakeIPFlowsGenerationsAndRestart(t *testing.T) {
	socket, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	up := &D.Server{PacketConn: socket, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		m := new(D.Msg)
		m.SetReply(q)
		m.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}}
		w.WriteMsg(m)
	})}
	go up.ActivateAndServe()
	defer up.Shutdown()
	profile := fmt.Sprintf("schema-version: 1\ndns: {nameserver: ['udp://%s'], enhanced-mode: fake-ip, fake-ip-range: 198.18.0.0/29, fake-ip-ttl: 1}\nrules: [{id: named, match: {domain: echo.test}, outbound: direct},{id: final, match: {all: true}, outbound: reject}]", socket.LocalAddr())
	h := newHarness(t, profile)
	target := echoServer(t)
	allocate := func() netip.Addr {
		q := new(D.Msg)
		q.SetQuestion("echo.test.", D.TypeA)
		reply, e := h.engine().ExchangeDNS(context.Background(), q)
		if e != nil {
			t.Fatal(e)
		}
		a, ok := netip.AddrFromSlice(reply.Answer[0].(*D.A).A)
		if !ok {
			t.Fatal("invalid fake response")
		}
		return a.Unmap()
	}
	first := allocate()
	conn, e := socks5Connect(h.proxy(), netip.AddrPortFrom(first, target.Port()))
	if e != nil {
		t.Fatal("fake TCP connect", e)
	}
	defer conn.Close()
	echo := func() {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		payload := []byte("pinned-fake-domain")
		if _, e := conn.Write(payload); e != nil {
			t.Fatal(e)
		}
		got := make([]byte, len(payload))
		if _, e := io.ReadFull(conn, got); e != nil || !bytes.Equal(payload, got) {
			t.Fatal("fake TCP echo", e)
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
	restored, e := socks5Connect(h.proxy(), netip.AddrPortFrom(second, target.Port()))
	if e != nil {
		t.Fatal("persisted fake address lost", e)
	}
	restored.SetDeadline(time.Now().Add(2 * time.Second))
	restored.Write([]byte("restored"))
	got := make([]byte, 8)
	if _, e = io.ReadFull(restored, got); e != nil || string(got) != "restored" {
		t.Fatal("restored fake route", e)
	}
	restored.Close()
	if !raceEnabled {
		udp := udpEcho(t)
		assoc := associate(t, h.proxy())
		destination := netip.AddrPortFrom(second, udp.Port())
		assoc.send(destination, "fake-udp")
		replies := assoc.recv(time.Second)
		if replies[destination.String()] != "fake-udp" {
			t.Fatal("fake UDP destination/reply rewrite", replies)
		}
	}
}
