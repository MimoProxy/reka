package service

import (
	"context"
	"fmt"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	D "github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestAutomaticHealthDoesNotWriteConfiguration(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsServer := &D.Server{Listener: listener, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		m := new(D.Msg)
		m.SetReply(q)
		rr, _ := D.NewRR(q.Question[0].Name + " 30 IN A 192.0.2.8")
		m.Answer = []D.RR{rr}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	dnsServer.NotifyStartedFunc = func() { close(started) }
	go dnsServer.ActivateAndServe()
	<-started
	defer dnsServer.Shutdown()
	dnsProxies := make(chan time.Duration, 4)
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer health.Close()
	proxy := func(delay time.Duration) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "CONNECT" {
				w.WriteHeader(405)
				return
			}
			if r.Host == listener.Addr().String() {
				dnsProxies <- delay
			}
			time.Sleep(delay)
			remote, e := net.DialTimeout("tcp", r.Host, time.Second)
			if e != nil {
				w.WriteHeader(502)
				return
			}
			client, _, e := w.(http.Hijacker).Hijack()
			if e != nil {
				remote.Close()
				return
			}
			client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			go func() {
				defer client.Close()
				defer remote.Close()
				go io.Copy(remote, client)
				io.Copy(client, remote)
			}()
		}))
	}
	slow, fast := proxy(70*time.Millisecond), proxy(0)
	defer slow.Close()
	defer fast.Close()
	a, _ := url.Parse(slow.URL)
	b, _ := url.Parse(fast.URL)
	hostA, portA, _ := net.SplitHostPort(a.Host)
	hostB, portB, _ := net.SplitHostPort(b.Host)
	profile := fmt.Sprintf("schema-version: 1\noutbounds: [{id: slow, type: http, server: %s, port: %s},{id: fast, type: http, server: %s, port: %s}]\ngroups: [{id: auto, type: url-test, members: [slow,fast], url: '%s', interval: 1, timeout: 1000, lazy: false},{id: parent, type: select, members: [auto,direct], selected: direct}]\nrules: [{match: {all: true}, outbound: parent}]", hostA, portA, hostB, portB, health.URL)
	profile += fmt.Sprintf("\ndns: {nameserver: ['tcp://%s#auto']}\n", listener.Addr())
	env := newEnv(t)
	s := env.open(profile, "")
	defer s.Close()
	before := s.GetConfiguration(true)
	deadline := time.Now().Add(4 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		for _, state := range s.Engine().GroupStatus() {
			ready = state.ID == "auto" && state.Selected == "fast"
		}
		if ready {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("health choice", s.Engine().GroupStatus())
	}
	q := new(D.Msg)
	q.SetQuestion("dns-policy.test.", D.TypeA)
	if m, err := s.Engine().ExchangeDNS(context.Background(), q); err != nil || len(m.Answer) != 1 {
		t.Fatal("DNS through automatic group", m, err)
	}
	select {
	case delay := <-dnsProxies:
		if delay != 0 {
			t.Fatal("DNS used static first member instead of observed healthy member")
		}
	case <-time.After(time.Second):
		t.Fatal("DNS bypassed selected outbound")
	}
	time.Sleep(1200 * time.Millisecond)
	after := s.GetConfiguration(true)
	if after.Revision != before.Revision || after.Profile != before.Profile {
		t.Fatal("observed health changed configuration")
	}
	ex, e := s.Engine().Explain(context.Background(), generation.ExplainRequest{Destination: "example.test:443"})
	if e != nil || ex.Outbound != "direct" {
		t.Fatal("manual selection overwritten", ex, e)
	}
	mustLayerCommit(t, s, ChangeRequest{BaseRevision: s.ActiveRevision(), Patch: []model.Op{{Op: "set", Path: "/groups/parent/selected", Value: []byte(`"auto"`)}}})
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		ex, e = s.Engine().Explain(context.Background(), generation.ExplainRequest{Destination: "example.test:443"})
		if e == nil && ex.Outbound == "fast" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e != nil || ex.Outbound != "fast" {
		t.Fatal("automatic choice did not reach router", ex, e)
	}
}
