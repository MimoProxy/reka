package sagernet

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestXHTTPCancelInitialDial(t *testing.T) {
	exited := make(chan struct{})
	client, err := newXHTTPClient(XHTTPClientOptions{Config: &XHTTPConfig{Host: "cancel.test", Mode: "packet-up"}}, XHTTPHooks{DialTCP: func(ctx context.Context, _, _ bool) (net.Conn, error) {
		defer close(exited)
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err = client.Dial(ctx); err == nil {
		t.Fatal("cancelled dial succeeded")
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("dial callback retained after cancellation")
	}
}
func TestXHTTPDownloadECHUsesScopedLookup(t *testing.T) {
	for _, downloadProtocol := range []string{"h2", "h3"} {
		t.Run(downloadProtocol, func(t *testing.T) {
			cfg := &XHTTPConfig{Host: "xhttp.test", Path: "/ech", Mode: "packet-up"}
			address, _ := startXHTTPReferenceMode(t, cfg, downloadProtocol, true)
			endpoint := netip.MustParseAddrPort(address)
			ds := &TLSSpec{ServerName: "xhttp.test", Insecure: true, ALPN: []string{downloadProtocol}, ECH: &ECHSpec{QueryServerName: "download-ech.test"}}
			options, _ := json.Marshal(map[string]any{"reka_xhttp": map[string]any{"host": cfg.Host, "path": cfg.Path, "mode": cfg.Mode, "download-settings": map[string]any{"reka_tls": ds}}})
			type echContextKey struct{}
			var lookups atomic.Int32
			b := New(Options{Logger: testLogger(t)})
			defer b.Close()
			out, err := b.NewOutbound("download-ech", VLESSSpec{Server: "127.0.0.1", Port: endpoint.Port(), UUID: "ca302b35-d67e-437a-bbcb-47773e5bc7d6", Options: options, TLS: &TLSSpec{ServerName: "xhttp.test", Insecure: true, ALPN: []string{"h2"}}, ECHLookup: func(ctx context.Context, name string) ([]byte, error) {
				if ctx.Value(echContextKey{}) != "scoped DNS pins" {
					return nil, errors.New("ECH lost scoped route context")
				}
				if name != "download-ech.test" {
					return nil, errors.New("query name lost")
				}
				lookups.Add(1)
				return nil, errors.New("scoped ECH test refusal")
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), echContextKey{}, "scoped DNS pins"), time.Second)
			defer cancel()
			if _, err = out.Dial(ctx, "tcp", "example.test:443"); err == nil || !strings.Contains(err.Error(), "scoped ECH test refusal") {
				t.Fatalf("unexpected ECH result: %v", err)
			}
			if lookups.Load() != 1 {
				t.Fatalf("scoped ECH called %d times", lookups.Load())
			}
		})
	}
}

func TestXHTTPDialKeepsScopedContext(t *testing.T) {
	type scopedKey struct{}
	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		t.Run(mode, func(t *testing.T) {
			seen := make(chan bool, 1)
			client, err := newXHTTPClient(XHTTPClientOptions{Config: &XHTTPConfig{Host: "context.test", Mode: mode}}, XHTTPHooks{DialTCP: func(ctx context.Context, _, _ bool) (net.Conn, error) {
				seen <- ctx.Value(scopedKey{}) == "native-dns-generation"
				return nil, errors.New("intentional dial refusal")
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), scopedKey{}, "native-dns-generation"), time.Second)
			defer cancel()
			if _, err = client.Dial(ctx); err == nil {
				t.Fatal("dial should fail")
			}
			select {
			case ok := <-seen:
				if !ok {
					t.Fatal("scoped context lost")
				}
			case <-time.After(time.Second):
				t.Fatal("dial not called")
			}
		})
	}
}
