package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/resource"
	D "github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

func TestNativeClientTrafficProbeAndResourcesOverWire(t *testing.T) {
	address, svc := startServer(t)
	client, err := Connect(address, "native-client-contract")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	proxyAddress := commitListener(t, client, nil, func(listen string) string {
		return fmt.Sprintf("listeners: [{id: mixed, type: mixed, listen: %q}]\n", listen)
	})
	dialer, _ := proxy.SOCKS5("tcp", proxyAddress, nil, &net.Dialer{Timeout: time.Second})
	payload := []byte("short-connection-payload")
	for range 12 {
		conn, err := dialer.Dial("tcp", echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(svc.Engine().Connections()) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(svc.Engine().Connections()) != 0 {
		t.Fatal("short fixtures still active")
	}
	var traffic api.Traffic
	if err := client.Call("GetTraffic", nil, &traffic); err != nil || traffic.Epoch == "" || traffic.UploadTotal != uint64(12*len(payload)) || traffic.DownloadTotal != traffic.UploadTotal {
		t.Fatal("closed-flow accounting", traffic, err)
	}
	before := svc.GetConfiguration(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	var probe api.ProbeResult
	if err := client.Call("ProbeOutbound", api.ProbeRequest{Outbound: "alt", URL: server.URL, TimeoutMS: 1000}, &probe); err != nil || probe.ResolvedOutbound != "alt" || probe.StatusCode != 204 || probe.DelayMS < 1 {
		t.Fatal(probe, err)
	}
	// The first request on each connection is slow; a unified probe reports
	// only the second request, which reuses the connection.
	type requestsKey struct{}
	slow := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count := r.Context().Value(requestsKey{}).(*int); *count == 0 {
			time.Sleep(300 * time.Millisecond)
		}
		*r.Context().Value(requestsKey{}).(*int)++
		w.WriteHeader(204)
	}))
	slow.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, requestsKey{}, new(int))
	}
	slow.Start()
	defer slow.Close()
	if err := client.Call("ProbeOutbound", api.ProbeRequest{Outbound: "alt", URL: slow.URL, TimeoutMS: 2000}, &probe); err != nil || probe.DelayMS < 300 {
		t.Fatal("probe without connection reuse", probe, err)
	}
	if err := client.Call("ProbeOutbound", api.ProbeRequest{Outbound: "alt", URL: slow.URL, TimeoutMS: 2000, Unified: true}, &probe); err != nil || probe.StatusCode != 204 || probe.DelayMS >= 300 {
		t.Fatal("unified probe", probe, err)
	}
	after := svc.GetConfiguration(true)
	if before.Revision != after.Revision || before.Profile != after.Profile || before.Overlay != after.Overlay {
		t.Fatal("manual probe changed configuration")
	}
	var afterTraffic api.Traffic
	if err := client.Call("GetTraffic", nil, &afterTraffic); err != nil || afterTraffic.UploadTotal != traffic.UploadTotal || afterTraffic.DownloadTotal != traffic.DownloadTotal {
		t.Fatal("probe became application traffic", afterTraffic, err)
	}
	data := []byte("immutable provider attachment")
	var staged api.StageResourceResult
	if err := client.Call("StageResource", api.StageResourceRequest{Hash: resource.Hash(data), Size: len(data), Data: data}, &staged); err != nil || !staged.Ready {
		t.Fatal(staged, err)
	}
}

func TestNativeDNSAndRoutingModeContract(t *testing.T) {
	address, svc := startServer(t)
	client, err := Connect(address, "native-dns-mode-contract")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	setMode := func(mode string) {
		t.Helper()
		value, _ := json.Marshal(model.Routing{Mode: mode, Global: "alt"})
		var result service.Result
		err := client.Call("CommitConfiguration", service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: svc.ActiveRevision(), LocalPatch: []model.Op{{Op: "set", Path: "/routing", Value: value}}}}, &result)
		if err != nil || result.State != "committed" || result.Plan.Interrupts || !result.Plan.RoutingChanged {
			t.Fatal(result, err)
		}
	}
	for _, item := range []struct{ mode, want string }{{"global", "alt"}, {"direct", "direct"}, {"rule", "reject"}} {
		setMode(item.mode)
		var route api.Explanation
		if err := client.Call("ExplainRoute", api.ExplainRequest{Destination: "10.0.0.7:443"}, &route); err != nil || route.Outbound != item.want {
			t.Fatal(item.mode, route, err)
		}
		var rules api.RulesPage
		if err := client.Call("GetRules", map[string]int{"limit": 100}, &rules); err != nil || rules.Mode != item.mode || len(rules.Rules) == 0 {
			t.Fatal(rules, err)
		}
		if item.mode != "rule" && (rules.Total != 1 || rules.Rules[0].Type != "MATCH") {
			t.Fatal("inactive configured rules presented as active", rules)
		}
	}
	if svc.GetConfiguration(true).Profile != testProfile {
		t.Fatal("mode switching rewrote stored rules")
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int32
	dns := &D.Server{PacketConn: packet, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		queries.Add(1)
		m := new(D.Msg)
		m.SetReply(q)
		rr, _ := D.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.7")
		m.Answer = []D.RR{rr}
		_ = w.WriteMsg(m)
	})}
	ready := make(chan struct{})
	dns.NotifyStartedFunc = func() { close(ready) }
	go dns.ActivateAndServe()
	<-ready
	defer dns.Shutdown()
	profile := fmt.Sprintf("schema-version: 1\noutbounds: [{id: alt, type: direct}]\ndns: {nameserver: [%q], default-nameserver: [%q], enhanced-mode: fake-ip}\nrules: [{match: {all: true}, outbound: direct}]\n", packet.LocalAddr().String(), packet.LocalAddr().String())
	var result service.Result
	if err := client.Call("CommitConfiguration", service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: svc.ActiveRevision(), Profile: &profile}}, &result); err != nil || result.State != "committed" {
		t.Fatal(result, err)
	}
	query := func(fake bool) api.DNSQueryResult {
		t.Helper()
		var response api.DNSQueryResult
		if err := client.Call("QueryDNS", api.DNSQueryRequest{Name: "native-cache.test", Type: "A", Fake: fake}, &response); err != nil || len(response.Answer) != 1 {
			t.Fatal(response, err)
		}
		return response
	}
	if !strings.Contains(query(false).Answer[0], "192.0.2.7") {
		t.Fatal("ordinary DNS response missing")
	}
	query(false)
	if queries.Load() != 1 {
		t.Fatal("ordinary cache missed", queries.Load())
	}
	fake := query(true).Answer[0]
	var flushed struct {
		Cleared int `json:"cleared"`
	}
	if err := client.Call("FlushDNSCache", nil, &flushed); err != nil || flushed.Cleared == 0 {
		t.Fatal(flushed, err)
	}
	query(false)
	if queries.Load() != 2 || query(true).Answer[0] != fake {
		t.Fatal("cache flush invalidated a Fake IP mapping")
	}
}
