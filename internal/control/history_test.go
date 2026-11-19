package control

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/history"
	D "github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

func reservedPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func TestHistoryConnectionFailureAndDNSCacheOverIPC(t *testing.T) {
	address, _ := startServer(t)
	client, err := Connect(address, "history-test")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serverAddress := reservedPort(t)
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &D.Server{PacketConn: packet, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		m := new(D.Msg)
		m.SetReply(q)
		answer, _ := D.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.5")
		m.Answer = []D.RR{answer}
		_ = w.WriteMsg(m)
	})}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go server.ActivateAndServe()
	<-ready
	defer server.Shutdown()
	profile := fmt.Sprintf(`schema-version: 1
dns: {nameserver: [%q]}
rules:
 - {id: block, match: {domain: "blocked.test"}, outbound: reject}
 - {match: {all: true}, outbound: direct}
`, packet.LocalAddr().String())
	local := fmt.Sprintf("listeners: [{id: mixed, type: mixed, listen: %q}]\n", serverAddress)
	var commit service.Result
	if err := client.Call("CommitConfiguration", service.CommitRequest{ChangeRequest: service.ChangeRequest{
		BaseRevision: 1, Profile: &profile, Local: &local,
	}}, &commit); err != nil || commit.State != "committed" {
		t.Fatal(commit, err)
	}
	dialer, _ := proxy.SOCKS5("tcp", serverAddress, nil, &net.Dialer{Timeout: time.Second})
	for _, target := range []string{"blocked.test:443", reservedPort(t)} {
		if c, err := dialer.Dial("tcp", target); err == nil {
			c.Close()
			t.Fatal("unexpected successful connection", target)
		}
	}
	var connections history.Page
	if err := client.Call("ListConnectionHistory", nil, &connections); err != nil || len(connections.Rows) != 2 {
		t.Fatal(connections, err)
	}
	first, last := string(connections.Rows[0].Data), string(connections.Rows[1].Data)
	if !strings.Contains(first, `"error_stage":"dial"`) || !strings.Contains(last, `"rule_id":"block"`) ||
		!strings.Contains(last, `"close_reason":"rejected"`) {
		t.Fatal(first, last)
	}
	for range 2 {
		var result api.DNSQueryResult
		if err := client.Call("QueryDNS", api.DNSQueryRequest{Name: "history.test"}, &result); err != nil || len(result.Answer) != 1 {
			t.Fatal(result, err)
		}
	}
	var queries history.Page
	if err := client.Call("ListDNSHistory", nil, &queries); err != nil || len(queries.Rows) != 2 {
		t.Fatal(queries, err)
	}
	var latest, upstream map[string]any
	_ = json.Unmarshal(queries.Rows[0].Data, &latest)
	_ = json.Unmarshal(queries.Rows[1].Data, &upstream)
	var result struct {
		Upstream struct {
			Outbound string `json:"outbound"`
		} `json:"upstream"`
	}
	_ = json.Unmarshal(queries.Rows[1].Data, &result)
	if latest["result_source"] != "cache" || latest["upstream"] != nil || upstream["result_source"] != "upstream" ||
		result.Upstream.Outbound != "direct" || upstream["origin"] != "control" {
		t.Fatal(latest, upstream)
	}
	var cleared map[string]int
	if err := client.Call("ClearHistory", map[string]string{"kind": "dns"}, &cleared); err != nil || cleared["cleared"] != 2 {
		t.Fatal(cleared, err)
	}
}
