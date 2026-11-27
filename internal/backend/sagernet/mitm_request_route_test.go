package sagernet

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/httprewrite"
)

// A connection rejected by its own rule still serves requests an earlier
// request rule accepts, on the same kept-alive connection.
func TestHTTPRequestRoutes(t *testing.T) {
	target := "http://example.net/moved"
	set, err := httprewrite.New(httprewrite.Spec{
		HTTPRewrites: []httprewrite.HTTPRewrite{{ID: "move", Match: "^http://example[.]com/old$", Action: "header", Target: &target}},
	}, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	accepted, origin := httpRelayOrigin(t, "192.0.2.1:80")
	drop := &Outbound{tag: "drop", typ: "reject-drop", out: newDropOutbound("drop")}
	var mu sync.Mutex
	var requests []HTTPRequestInfo
	var rerouted []*HTTPRequestInfo
	released := make(chan struct{}, 4)
	route := &MITMRoute{
		PlainHTTP: true, Host: "example.com", Rewrite: set,
		RouteRequest: func(_ context.Context, request HTTPRequestInfo) (Route, bool) {
			mu.Lock()
			requests = append(requests, request)
			mu.Unlock()
			switch request.URL {
			case "http://example.com/accepted":
				return Route{Outbound: accepted, Release: func() { released <- struct{}{} }}, true
			case "http://example.com/rejected":
				return Route{}, true
			case "http://example.com/dropped":
				return Route{Outbound: drop}, true
			}
			return Route{}, false
		},
		Reroute: func(_ context.Context, _ Destination, request *HTTPRequestInfo) Route {
			mu.Lock()
			rerouted = append(rerouted, request)
			mu.Unlock()
			return Route{}
		},
	}
	wire, _ := httpRelayWire(t, Route{Outbound: rejectedOutbound, MITM: route}, "192.0.2.1:80")
	reader := bufio.NewReader(wire)
	send := func(path string, status int) {
		t.Helper()
		writeHTTPRelayBytes(t, wire, "GET "+path+" HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Example/1.0\r\n\r\n")
		if path == "/accepted" {
			req, err := http.ReadRequest(bufio.NewReader(origin))
			if err != nil || req.URL.Path != path || req.UserAgent() != "Example/1.0" {
				t.Fatalf("origin request = %v, error %v", req, err)
			}
			writeHTTPRelayBytes(t, origin, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
		res, err := http.ReadResponse(reader, nil)
		if err != nil || res.StatusCode != status {
			t.Fatalf("%s response = %v, error %v", path, res, err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}
	send("/accepted", http.StatusOK)
	select {
	case <-released:
	case <-time.After(mitmH2TestTimeout):
		t.Fatal("request route was not released")
	}
	send("/kept", http.StatusNotFound)
	send("/rejected", http.StatusNotFound)
	send("/old", http.StatusNotFound)
	// A dropped request gets no response and ends the connection.
	writeHTTPRelayBytes(t, wire, "GET /dropped HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_ = wire.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("dropped request was answered")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 4 || requests[0].UserAgent != "Example/1.0" || requests[3].URL != "http://example.com/dropped" {
		t.Fatalf("routed requests = %+v", requests)
	}
	if len(rerouted) != 1 || rerouted[0] == nil || rerouted[0].URL != target {
		t.Fatalf("rerouted requests = %+v", rerouted)
	}
}
