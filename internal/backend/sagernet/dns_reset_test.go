package sagernet

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	RD "github.com/MimoProxy/reka/internal/dns"
	D "github.com/miekg/dns"
)

func TestDNSPoolNetworkResetStartsFreshWithoutInterruptingActiveQuery(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		raw, _ = dnsTestAnswer(q).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	pool := NewDNSPool()
	defer pool.Retire()
	var opened, closed atomic.Int32
	dial := func(ctx context.Context, network, address, _ string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		opened.Add(1)
		return &dnsCountConn{Conn: c, closed: &closed}, nil
	}
	ep, _ := RD.ParseEndpoint(server.URL)
	done := make(chan error, 1)
	query := func(name string) *D.Msg { q := new(D.Msg); q.SetQuestion(name, D.TypeA); return q }
	go func() { _, err := pool.Exchange(context.Background(), ep, query("hold.test."), nil, dial); done <- err }()
	<-entered
	pool.ResetIdle()
	if closed.Load() != 0 {
		t.Fatal("active query was closed on network change")
	}
	if _, err := pool.Exchange(context.Background(), ep, query("fresh.test."), nil, dial); err != nil {
		t.Fatal(err)
	}
	if opened.Load() != 2 {
		t.Fatal("new network query reused old physical transport", opened.Load())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal("old active query failed", err)
	}
	deadline := time.Now().Add(time.Second)
	for closed.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if closed.Load() != 1 {
		t.Fatal("old active transport did not retire", closed.Load())
	}
}
