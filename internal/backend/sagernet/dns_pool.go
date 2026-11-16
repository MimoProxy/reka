package sagernet

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	RD "github.com/MimoProxy/reka/internal/dns"
	D "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	SD "github.com/sagernet/sing-box/dns"
	DT "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

// DNSPool belongs to one immutable configuration. The caller resolves a group
// to its actual outbound ID before Exchange; endpoint, scope and selected ID
// form the key. Dial callbacks only use the current exchange's context.
type DNSPool struct {
	mu      sync.Mutex
	entries map[string]*dnsPoolEntry
	retired bool
	stop    chan struct{}
}
type dnsPoolEntry struct {
	active    int
	used      time.Time
	draining  bool
	exchange  func(context.Context, *D.Msg) (*D.Msg, error)
	idle      func()
	resetIdle func()
	close     func()
}

func NewDNSPool() *DNSPool {
	p := &DNSPool{entries: map[string]*dnsPoolEntry{}, stop: make(chan struct{})}
	go func() {
		timer := time.NewTicker(15 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-p.stop:
				return
			case now := <-timer.C:
				p.mu.Lock()
				for key, e := range p.entries {
					if e.active == 0 && now.Sub(e.used) >= 30*time.Second {
						delete(p.entries, key)
						e.close()
					}
				}
				p.mu.Unlock()
			}
		}
	}()
	return p
}

func (p *DNSPool) Retire() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retired {
		return
	}
	p.retired = true
	close(p.stop)
	for key, e := range p.entries {
		delete(p.entries, key)
		e.draining = true
		e.idle()
		if e.active == 0 {
			e.close()
		}
	}
}

func (p *DNSPool) ResetIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()
	// New queries must not join an old physical connection while a network
	// change leaves an earlier HTTP/2 or multiplexed query still in progress.
	for key, entry := range p.entries {
		delete(p.entries, key)
		entry.draining = true
		entry.idle()
		if entry.active == 0 {
			entry.close()
		}
	}
}

func (p *DNSPool) Exchange(ctx context.Context, ep RD.Endpoint, q *D.Msg, lookup func(context.Context, string) ([]netip.Addr, error), dial DNSDial) (*D.Msg, error) {
	if (ep.Scheme != "tls" && ep.Scheme != "tcp" && ep.Scheme != "https" && ep.Scheme != "http") || ep.PreferH3 {
		return ExchangeDNS(ctx, ep, q, lookup, dial)
	}
	encoded, _ := json.Marshal(ep)
	key := string(encoded)
	p.mu.Lock()
	if p.retired {
		p.mu.Unlock()
		return ExchangeDNS(ctx, ep, q, lookup, dial)
	}
	e := p.entries[key]
	if e == nil {
		if len(p.entries) >= 64 {
			for old, entry := range p.entries {
				if entry.active == 0 {
					delete(p.entries, old)
					entry.close()
					break
				}
			}
		}
		if len(p.entries) >= 64 {
			p.mu.Unlock()
			return ExchangeDNS(ctx, ep, q, lookup, dial)
		}
		e = newDNSPoolEntry(ep, lookup, dial)
		p.entries[key] = e
	}
	e.active++
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		e.active--
		e.used = time.Now()
		if e.draining && e.active == 0 {
			e.close()
		}
	}()
	ctx, cancel := context.WithDeadline(ctx, exchangeDeadline(ctx))
	defer cancel()
	m, err := e.exchange(ctx, q)
	if err == nil {
		err = checkReply(q, m)
	}
	return m, err
}

type dnsPoolDialer struct {
	ep     RD.Endpoint
	lookup func(context.Context, string) ([]netip.Addr, error)
	dial   DNSDial
	config *tls.Config
}

func (d *dnsPoolDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	host := d.ep.Host
	if _, err := netip.ParseAddr(host); err != nil {
		ips, err := d.lookup(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("DNS endpoint bootstrap failed")
		}
		host = ips[0].String()
	}
	conn, err := d.dial(ctx, network, net.JoinHostPort(host, d.ep.Port), d.ep.Via)
	if err != nil {
		return nil, err
	}
	if d.config == nil {
		return conn, nil
	}
	tc := tls.Client(conn, d.config)
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}
func (*dnsPoolDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("stream DNS transport cannot listen for packets")
}

func newDNSPoolEntry(ep RD.Endpoint, lookup func(context.Context, string) ([]netip.Addr, error), dial DNSDial) *dnsPoolEntry {
	config := dnsTLSConfig(ep, nil)
	d := &dnsPoolDialer{ep: ep, lookup: lookup, dial: dial}
	if ep.Scheme == "tls" {
		d.config = config
	}
	if ep.Scheme == "tls" || ep.Scheme == "tcp" {
		// Reuse sing-box's query multiplexer, including per-query wire IDs,
		// cancellation, reconnect and idle retention. TLS remains Reka's
		// verified connection wrapper so endpoint verification options agree.
		tr := DT.NewTCPRaw(SD.NewTransportAdapter(ep.Scheme, "reka-dns", nil), d, M.ParseSocksaddr(net.JoinHostPort(ep.Host, ep.Port)))
		scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
		_ = tr.Start(adapter.StartStateStart, scope)
		tr.SetKeepIdleConnections(true)
		return &dnsPoolEntry{used: time.Now(), exchange: tr.Exchange, idle: func() { tr.SetKeepIdleConnections(false) }, resetIdle: tr.CloseIdleConnections, close: func() { _ = scope.Close() }}
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: config, ForceAttemptHTTP2: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: dnsTimeout, ResponseHeaderTimeout: dnsTimeout, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, M.Socksaddr{})
	}}
	return &dnsPoolEntry{used: time.Now(), exchange: func(ctx context.Context, q *D.Msg) (*D.Msg, error) { return exchangeDoHTransport(ctx, ep, q, tr) }, idle: tr.CloseIdleConnections, resetIdle: tr.CloseIdleConnections, close: tr.CloseIdleConnections}
}
