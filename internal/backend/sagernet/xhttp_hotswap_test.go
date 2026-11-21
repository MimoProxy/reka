package sagernet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	RT "github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/testnet"
)

func TestXHTTPHotSwapDrainsOwnedPools(t *testing.T) {
	cfg := &XHTTPConfig{Host: "xhttp.test", Path: "/hot-update", Mode: "packet-up", ScMinPostsIntervalMs: "1"}
	peer, certificate := startXHTTPReferenceMode(t, cfg, "h2", true)
	endpoint := netip.MustParseAddrPort(peer)
	block, _ := pem.Decode([]byte(certificate))
	pin := sha256.Sum256(block.Bytes)
	security := &TLSSpec{ServerName: "xhttp.test", CertificatePin: hex.EncodeToString(pin[:]), ALPN: []string{"h2"}}
	b := New(Options{Logger: testLogger(t), HalfCloseTimeout: 50 * time.Millisecond})
	defer b.Close()
	makeOutbound := func(tag string) *Outbound {
		options, _ := json.Marshal(map[string]any{"reka_xhttp": map[string]any{"host": cfg.Host, "path": cfg.Path, "mode": cfg.Mode, "sc-min-posts-interval-ms": "1", "xmux": map[string]any{"max-connections": "1"}}})
		out, err := b.NewOutbound(tag, VLESSSpec{Server: "127.0.0.1", Port: endpoint.Port(), UUID: "ca302b35-d67e-437a-bbcb-47773e5bc7d6", TLS: security, Options: options})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	old := makeOutbound("old")
	drained := make(chan int64, 1)
	runtime := RT.New(map[string]*Outbound{"proxy": old}, RT.Options{DrainTimeout: 3 * time.Second, OnClosed: func(_ string, generation uint64, forced int64, _ error) {
		if generation == 1 {
			drained <- forced
		}
	}})
	defer runtime.Close()
	b.SetRoute(runtimeRoute(t, runtime))
	var inbound *Inbound
	listen := testnet.RetryAddr(t, func(address netip.AddrPort) (err error) {
		inbound, err = b.NewMixedInbound("xhttp-test", address)
		return err
	})
	defer inbound.Close()
	target := netip.MustParseAddrPort("198.51.100.1:443")
	first, err := socks5Connect(listen, target)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	transfer := func(c net.Conn, marker string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		payload := bytes.Repeat([]byte(marker), 1024)
		done := make(chan error, 1)
		go func() { _, e := c.Write(payload); done <- e }()
		reply := make([]byte, len(payload))
		if _, err = io.ReadFull(c, reply); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reply, payload) {
			t.Fatal("payload changed across update")
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
	}
	transfer(first, "before-update")
	next := makeOutbound("new")
	if _, err = runtime.Commit(map[string]*Outbound{"proxy": next}); err != nil {
		t.Fatal(err)
	}
	transfer(first, "old-stream-after-update")
	if !old.Lease().Retired() || old.Active() != 1 {
		t.Fatalf("old retired=%v active=%d", old.Lease().Retired(), old.Active())
	}
	select {
	case <-drained:
		t.Fatal("old pool closed before its flow ended")
	default:
	}
	second, err := socks5Connect(listen, target)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	transfer(second, "new-stream")
	_ = first.Close()
	select {
	case forced := <-drained:
		if forced != 0 {
			t.Fatalf("forced %d old flows", forced)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old XHTTP pool did not drain")
	}
	transfer(second, "new-stream-after-old-pool-close")
	_ = second.Close()
	runtime.Close()
	if stats := runtime.Stats(); stats.Forced != 0 || stats.Retiring != 0 {
		t.Fatalf("runtime resources: %+v", stats)
	}
}
