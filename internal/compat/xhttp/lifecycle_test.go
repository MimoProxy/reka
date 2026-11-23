package xhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type countedReader struct {
	io.Reader
	closed atomic.Int32
}

func (c *countedReader) Close() error { c.closed.Add(1); return nil }

func TestInitialConnectionObserverUsesFirstSelection(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	ready := make(chan bool, 1)
	var addr NetAddr
	var selected []httptrace.GotConnInfo
	ctx := WithInitialConnObserver(t.Context(), func(info httptrace.GotConnInfo) {
		if len(ready) != 0 || addr.RemoteAddr() != info.Conn.RemoteAddr() {
			t.Fatal("dial readiness did not wait for the socket observation")
		}
		selected = append(selected, info)
	})
	trace := httptrace.ContextClientTrace(newAddrContext(&addr, ctx, ready))
	trace.GotConn(httptrace.GotConnInfo{Conn: conn, Reused: true})
	select {
	case got := <-ready:
		if !got {
			t.Fatal("the first selection reported failure")
		}
	default:
		t.Fatal("the first selection did not signal readiness")
	}
	trace.GotConn(httptrace.GotConnInfo{Conn: peer})
	if len(selected) != 1 || selected[0].Conn != conn || !selected[0].Reused || len(ready) != 0 {
		t.Fatalf("retry replaced the first selection: %+v", selected)
	}
}

func TestResponseHandoffAndConcurrentClose(t *testing.T) {
	for i := 0; i < 1000; i++ {
		waiting := NewWaitReadCloser()
		body := &countedReader{Reader: strings.NewReader("reply")}
		var workers sync.WaitGroup
		workers.Add(3)
		go func() { defer workers.Done(); waiting.Set(body) }()
		go func() { defer workers.Done(); _ = waiting.Close() }()
		go func() { defer workers.Done(); _ = waiting.Close() }()
		workers.Wait()
		if n := body.closed.Load(); n != 1 {
			t.Fatalf("response closed %d times", n)
		}
	}
}
func TestClientRetainsImmutableConfigurationAndRefusesAfterClose(t *testing.T) {
	cfg := &Config{Host: "xhttp.test", Mode: "packet-up", Headers: map[string]string{"X-Token": "original"}, ReuseConfig: &ReuseConfig{MaxConnections: "2"}}
	maker := func() http.RoundTripper { t.Fatal("closed client created a transport"); return nil }
	client, err := NewClient(cfg, maker, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Headers["X-Token"] = "changed"
	cfg.ReuseConfig.MaxConnections = "7"
	if client.cfg.Headers["X-Token"] != "original" || client.cfg.ReuseConfig.MaxConnections != "2" {
		t.Fatal("mutable configuration retained")
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Dial(context.Background()); err == nil {
		t.Fatal("closed client accepted a stream")
	}
}
func TestRejectUnboundedAndInvalidConfiguration(t *testing.T) {
	for _, modify := range []func(*Config){
		func(c *Config) { c.SessionLength = "999999999"; c.SessionTable = "number" },
		func(c *Config) { c.ScMaxEachPostBytes = "999999999" },
		func(c *Config) { c.Headers = map[string]string{"X-Key": "bad\r\nvalue"} },
		func(c *Config) { c.ReuseConfig = &ReuseConfig{MaxConnections: "999999999"} },
		func(c *Config) { c.ReuseConfig = &ReuseConfig{HKeepAlivePeriod: "-2"} },
		func(c *Config) { c.Mode = "stream-one"; c.DownloadConfig = &Config{Host: "other.test"} },
	} {
		cfg := &Config{Host: "xhttp.test"}
		modify(cfg)
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("invalid configuration accepted: %+v", cfg)
		}
	}
}
