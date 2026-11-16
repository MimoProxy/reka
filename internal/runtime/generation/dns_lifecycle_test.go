package generation

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	D "github.com/miekg/dns"
)

func TestDNSPoolCommitKeepsActiveQueryAndReleasesRetiredOutbound(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var sockets, closed atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		q := new(D.Msg)
		if err := q.Unpack(raw); err != nil {
			t.Error(err)
			return
		}
		if q.Question[0].Name == "hold.test." {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		m := new(D.Msg)
		m.SetReply(q)
		rr, _ := D.NewRR(q.Question[0].Name + " 30 IN A 192.0.2.8")
		m.Answer = []D.RR{rr}
		raw, _ = m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(raw)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			sockets.Add(1)
		}
		if state == http.StateClosed {
			closed.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	e := NewEngine(EngineOptions{})
	defer e.Close()
	endpoint := server.URL + "/dns-query#resolver&skip-cert-verify=true"
	profile := fmt.Sprintf("schema-version: 1\noutbounds: [{id: resolver, type: direct}]\ndns: {nameserver: [%q]}\nrules: [{match: {all: true}, outbound: direct}]\n", endpoint)
	old := pinFlowApply(t, e, profile, "", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := e.QueryDNS(ctx, api.DNSQueryRequest{Name: "warm.test"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		result, err := e.QueryDNS(ctx, api.DNSQueryRequest{Name: "hold.test"})
		if err == nil && len(result.Answer) != 1 {
			err = fmt.Errorf("lost active answer: %+v", result)
		}
		done <- err
	}()
	<-entered
	pinFlowApply(t, e, "schema-version: 1\nrules: [{match: {all: true}, outbound: direct}]\n", "", 2)
	select {
	case <-old.outbounds["resolver"].Lease().Drained():
		t.Fatal("active query lost its resolver")
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal("configuration switch interrupted active DNS query", err)
	}
	pinFlowWaitDrained(t, old.outbounds["resolver"])
	deadline := time.Now().Add(time.Second)
	for closed.Load() != sockets.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if closed.Load() != sockets.Load() {
		t.Fatal("retired DNS connection leaked", sockets.Load(), closed.Load())
	}
}

func TestDNSRespectRulesCacheFollowsRoutingMode(t *testing.T) {
	address, _ := pinFlowDNS(t)
	e := NewEngine(EngineOptions{})
	defer e.Close()
	profile := fmt.Sprintf("schema-version: 1\ndns: {nameserver: [%q], respect-rules: true}\nrules: [{match: {all: true}, outbound: direct}]\n", address)
	pinFlowApply(t, e, profile, "routing: {mode: rule, global: reject}\n", 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	query := api.DNSQueryRequest{Name: "routing-cache.test"}
	if _, err := e.QueryDNS(ctx, query); err != nil {
		t.Fatal(err)
	}
	pinFlowApply(t, e, profile, "routing: {mode: global, global: reject}\n", 2)
	if _, err := e.QueryDNS(ctx, query); err == nil {
		t.Fatal("DNS reused a cache entry resolved under the previous routing mode")
	}
}
