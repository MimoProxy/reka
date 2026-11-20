package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/history"
	"golang.org/x/net/proxy"
)

func TestTemporaryRulesScenesAndArenaOverIPC(t *testing.T) {
	address, svc := startServer(t)
	client, err := Connect(address, "workflows")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	listener := reservedPort(t)
	badHost, badPort, err := net.SplitHostPort(reservedPort(t))
	if err != nil {
		t.Fatal(err)
	}
	profile := fmt.Sprintf(`schema-version: 1
outbounds:
  - {id: alt, type: direct}
  - {id: down, type: http, server: %q, port: %s}
rules:
  - {id: lab, match: {network-scene: lab}, outbound: direct}
  - {id: otherwise, match: {all: true}, outbound: reject}
`, badHost, badPort)
	local := fmt.Sprintf("listeners: [{id: mixed, type: mixed, listen: %q}]\nnetwork-scenes: [{id: lab}]\n", listener)
	var commit service.Result
	if err := client.Call("CommitConfiguration", service.CommitRequest{ChangeRequest: service.ChangeRequest{
		BaseRevision: 1, Profile: &profile, Local: &local,
	}}, &commit); err != nil || commit.State != "committed" {
		t.Fatal(commit, err)
	}
	before := svc.GetConfiguration(true)
	explain := func(outbound, scene, source string) {
		t.Helper()
		var result api.Explanation
		if err := client.Call("ExplainRoute", api.ExplainRequest{Destination: "check.example:80"}, &result); err != nil ||
			result.Outbound != outbound || result.NetworkScene != scene || result.RuleSource != source {
			t.Fatal(result, err)
		}
	}
	explain("reject", "", "")
	if err := client.Call("SetNetworkScene", map[string]string{"scene": "lab"}, nil); err != nil {
		t.Fatal(err)
	}
	explain("direct", "lab", "")
	add := func(ttl int) api.TemporaryRule {
		t.Helper()
		var result api.TemporaryRule
		if err := client.Call("AddTemporaryRule", api.TemporaryRuleRequest{Rule: "DOMAIN,check.example,alt", TTLSeconds: ttl}, &result); err != nil || !result.Active {
			t.Fatal(result, err)
		}
		return result
	}
	temp := add(30)
	explain("alt", "lab", "temporary")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	dialer, err := proxy.SOCKS5("tcp", listener, nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: dialer.(proxy.ContextDialer).DialContext}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "check.example"
	response, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal(response.StatusCode)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		var page history.Page
		if err := client.Call("ListConnectionHistory", history.ListOptions{Limit: 1}, &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Rows) > 0 {
			var trace api.ConnectionTrace
			if err := json.Unmarshal(page.Rows[0].Data, &trace); err != nil || trace.Outbound != "alt" || trace.RuleID != temp.ID ||
				trace.SniffedDomain != "check.example" || trace.NetworkScene != "lab" || trace.RuleSource != "temporary" {
				t.Fatal(trace, err)
			}
			var timeline api.ConnectionTimeline
			if err := client.Call("GetConnectionTimeline", api.TimelineRequest{ID: trace.ID, Epoch: page.Epoch}, &timeline); err != nil ||
				timeline.Live || len(timeline.Events) != 7 || timeline.Events[0].Stage != "accepted" || timeline.Events[6].Stage != "closed" {
				t.Fatal(timeline, err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("connection did not reach history")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := client.Call("RemoveTemporaryRule", map[string]string{"id": temp.ID}, nil); err != nil {
		t.Fatal(err)
	}
	explain("direct", "lab", "")
	expiring := add(1)
	if remaining := time.Until(expiring.ExpiresAt); remaining > 0 {
		time.Sleep(remaining + 10*time.Millisecond)
	}
	explain("direct", "lab", "")
	var rules []api.TemporaryRule
	if err := client.Call("ListTemporaryRules", nil, &rules); err != nil || len(rules) != 0 {
		t.Fatal(rules, err)
	}
	var scene api.NetworkSceneStatus
	if err := client.Call("SetNetworkScene", map[string]string{"scene": ""}, &scene); err != nil || scene.Current != "" {
		t.Fatal(scene, err)
	}
	explain("reject", "", "")
	var arena api.ArenaResult
	if err := client.Call("RunNodeArena", api.ArenaRequest{Outbounds: []string{"down", "alt"}, Rounds: 2, TimeoutMS: 800, URL: origin.URL}, &arena); err != nil ||
		arena.Winner != "alt" || len(arena.Ranking) != 2 || arena.Ranking[0].Successes != 2 || arena.Ranking[1].Successes != 0 {
		t.Fatal(arena, err)
	}
	if after := svc.GetConfiguration(true); before.Revision != after.Revision || before.Profile != after.Profile || before.Local != after.Local {
		t.Fatal("runtime workflows changed saved configuration")
	}
}

func TestClosingControlServerCancelsNodeArena(t *testing.T) {
	_, svc := startServer(t)
	server := NewServer(NewHandler(svc))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	client, err := api.NewClient(conn, "arena-shutdown")
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	defer client.Close()
	started := make(chan struct{}, 2)
	unblock := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		started <- struct{}{}
		select {
		case <-request.Context().Done():
		case <-unblock:
		}
	}))
	defer origin.Close()
	defer close(unblock)
	go client.Call("RunNodeArena", api.ArenaRequest{Outbounds: []string{"direct", "alt"}, URL: origin.URL, Rounds: 1, TimeoutMS: 15000}, nil)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		server.Close()
		t.Fatal("arena did not reach loopback fixture")
	}
	done := make(chan struct{})
	go func() {
		server.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown waited for an arena probe after closing its connection")
	}
}
