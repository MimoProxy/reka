package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/testnet"
	D "github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

// closedAddress returns a loopback address nothing listens on, for a
// destination that must refuse connections. Nothing in the test binds it.
func closedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

// commitListener commits profile, when set, with the local document that
// local builds around a mixed listener address, and returns that address. A
// port another process took first is retried on a new port.
func commitListener(t *testing.T, client *Client, profile *string, local func(listen string) string) string {
	t.Helper()
	return testnet.RetryAddr(t, func(listen netip.AddrPort) error {
		document := local(listen.String())
		var commit service.Result
		if err := client.Call("CommitConfiguration", service.CommitRequest{ChangeRequest: service.ChangeRequest{
			BaseRevision: 1, Profile: profile, Local: &document,
		}}, &commit); err != nil {
			return err
		}
		if commit.State != "committed" {
			return fmt.Errorf("commit: %+v", commit)
		}
		return nil
	}).String()
}

func TestHistoryConnectionFailureAndDNSCacheOverIPC(t *testing.T) {
	address, _ := startServer(t)
	client, err := Connect(address, "history-test")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
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
	serverAddress := commitListener(t, client, &profile, func(listen string) string {
		return fmt.Sprintf("listeners: [{id: mixed, type: mixed, listen: %q}]\n", listen)
	})
	dialer, _ := proxy.SOCKS5("tcp", serverAddress, nil, &net.Dialer{Timeout: time.Second})
	if c, err := dialer.Dial("tcp", "blocked.test:443"); err == nil {
		c.Close()
		t.Fatal("known blocked domain was not rejected during the SOCKS handshake")
	}
	c, err := dialer.Dial("tcp", closedAddress(t))
	if err != nil {
		t.Fatal("SOCKS handshake did not allow payload for domain recovery", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := c.Read(b[:]); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("SOCKS tunnel did not close after dial failure: read %d bytes, %v", n, err)
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
