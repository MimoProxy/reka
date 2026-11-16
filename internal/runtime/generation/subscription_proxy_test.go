package generation

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestSubscriptionProxyUsesNamedGroupAndRejectsUnknown(t *testing.T) {
	var hops, requests atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write([]byte("nodes")) }))
	defer origin.Close()
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() {
		for {
			c, e := proxy.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				reader := bufio.NewReader(c)
				request, e := http.ReadRequest(reader)
				if e != nil {
					return
				}
				if request.Method != "CONNECT" {
					return
				}
				remote, e := net.Dial("tcp", request.Host)
				if e != nil {
					return
				}
				defer remote.Close()
				hops.Add(1)
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go io.Copy(remote, reader)
				io.Copy(c, remote)
			}()
		}
	}()
	port := proxy.Addr().(*net.TCPAddr).Port
	profile := fmt.Sprintf("schema-version: 1\noutbounds: [{id: relay, name: Relay, type: http, server: 127.0.0.1, port: %d}]\ngroups: [{id: choice, name: Choice, type: select, members: [relay], selected: relay}]\n", port)
	eff, ds := compile.Compile([]byte(profile), nil, compile.Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	engine := NewEngine(EngineOptions{})
	defer engine.Close()
	prepared, err := engine.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Activate(prepared, 1); err != nil {
		t.Fatal(err)
	}
	client, err := engine.SubscriptionProxyClient("airport", "Choice")
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "nodes" || hops.Load() != 1 || requests.Load() != 1 {
		t.Fatal("named provider route bypassed", hops.Load(), requests.Load())
	}
	for _, name := range []string{"missing", "REJECT"} {
		client, _ = engine.SubscriptionProxyClient("airport", name)
		if response, err = client.Get(origin.URL); err == nil {
			response.Body.Close()
			t.Fatal("unavailable provider proxy fell back direct")
		}
		client.CloseIdleConnections()
	}
	if requests.Load() != 1 {
		t.Fatal("rejected request reached origin")
	}
}
