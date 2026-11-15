package sagernet

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	RD "github.com/MimoProxy/reka/internal/dns"
	D "github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type LookupFunc func(context.Context, string) ([]netip.Addr, error)
type lookupKey struct{}

func WithLookup(ctx context.Context, fn LookupFunc) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, lookupKey{}, fn)
}

type leasedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *leasedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (o *Outbound) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if !o.lease.Acquire() {
		return nil, errors.New("outbound retired")
	}
	c, e := o.out.DialContext(ctx, network, M.ParseSocksaddr(address))
	if e != nil {
		o.lease.Release()
		return nil, e
	}
	return &leasedConn{Conn: c, release: o.lease.Release}, nil
}

type DNSDial func(context.Context, string, string, string) (net.Conn, error)

func ExchangeDNS(ctx context.Context, ep RD.Endpoint, q *D.Msg, lookup func(context.Context, string) ([]netip.Addr, error), dial DNSDial) (*D.Msg, error) {
	return exchangeDNS(ctx, ep, q, lookup, dial, nil)
}

func exchangeDNS(ctx context.Context, ep RD.Endpoint, q *D.Msg, lookup func(context.Context, string) ([]netip.Addr, error), dial DNSDial, roots *x509.CertPool) (*D.Msg, error) {
	tlsConfig := &tls.Config{ServerName: ep.Host, MinVersion: tls.VersionTLS12, RootCAs: roots}
	host := ep.Host
	if _, e := netip.ParseAddr(host); e != nil {
		ips, e := lookup(ctx, host)
		if e != nil || len(ips) == 0 {
			return nil, errors.New("DNS endpoint bootstrap failed")
		}
		host = ips[0].String()
	}
	address := net.JoinHostPort(host, ep.Port)
	open := func(ctx context.Context, network string) (net.Conn, error) {
		return dial(ctx, network, address, ep.Via)
	}
	if ep.Scheme == "udp" || ep.Scheme == "tcp" {
		network := ep.Scheme
		m, e := exchangePlainDNS(ctx, network, address, ep.Via, q, dial)
		if e != nil || network != "udp" || !m.Truncated {
			return m, e
		}
		return exchangePlainDNS(ctx, "tcp", address, ep.Via, q, dial)
	}
	if ep.Scheme == "https" {
		wire, e := q.Pack()
		if e != nil {
			return nil, e
		}
		tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: tlsConfig, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return open(ctx, "tcp") }}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("DNS redirect forbidden") }}
		req, e := http.NewRequestWithContext(ctx, "POST", "https://"+net.JoinHostPort(ep.Host, ep.Port)+ep.Path, bytes.NewReader(wire))
		if e != nil {
			return nil, e
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		res, e := client.Do(req)
		if e != nil {
			return nil, e
		}
		defer res.Body.Close()
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/dns-message") {
			return nil, errors.New("invalid DoH response")
		}
		b, e := io.ReadAll(io.LimitReader(res.Body, 65536))
		if e != nil || len(b) > 65535 {
			return nil, errors.New("invalid DoH size")
		}
		m := new(D.Msg)
		if e = m.Unpack(b); e != nil {
			return nil, e
		}
		if m.Id != q.Id || !m.Response {
			return nil, errors.New("invalid DNS response identity")
		}
		return m, nil
	}
	if ep.Scheme != "tls" {
		return nil, errors.New("unsupported DNS transport")
	}
	exchange := func() (*D.Msg, error) {
		c, e := open(ctx, "tcp")
		if e != nil {
			return nil, e
		}
		defer c.Close()
		tc := tls.Client(c, tlsConfig)
		if e = tc.HandshakeContext(ctx); e != nil {
			return nil, e
		}
		c = tc
		deadline := time.Now().Add(5 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		c.SetDeadline(deadline)
		dc := &D.Conn{Conn: c, UDPSize: 1232}
		client := &D.Client{Net: "tcp", Timeout: 5 * time.Second}
		m, _, e := client.ExchangeWithConnContext(ctx, q, dc)
		return m, e
	}
	return exchange()
}

type DNSListener struct{ udp, tcp *D.Server }

func NewDNSListener(address string, exchange func(context.Context, *D.Msg) (*D.Msg, error)) (*DNSListener, error) {
	packet, e := net.ListenPacket("udp", address)
	if e != nil {
		return nil, e
	}
	listener, e := net.Listen("tcp", packet.LocalAddr().String())
	if e != nil {
		packet.Close()
		return nil, e
	}
	handler := D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		m, e := exchange(ctx, q)
		if e != nil {
			m = new(D.Msg)
			m.SetRcode(q, D.RcodeServerFailure)
		}
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			size := uint16(512)
			if o := q.IsEdns0(); o != nil {
				size = max(512, o.UDPSize())
			}
			m.Truncate(int(min(size, 4096)))
		}
		_ = w.WriteMsg(m)
	})
	d := &DNSListener{udp: &D.Server{PacketConn: packet, Handler: handler}, tcp: &D.Server{Listener: listener, Handler: handler}}
	go d.udp.ActivateAndServe()
	go d.tcp.ActivateAndServe()
	return d, nil
}
func (d *DNSListener) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = d.udp.ShutdownContext(ctx)
	_ = d.tcp.ShutdownContext(ctx)
}

// One bounded connected socket per query, with cancellation and strict reply
// identity checks. UDP truncation is retried over TCP by exchangeDNS.
func exchangePlainDNS(ctx context.Context, network, address, via string, q *D.Msg, dial DNSDial) (*D.Msg, error) {
	c, e := dial(ctx, network, address, via)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if e = c.SetDeadline(deadline); e != nil {
		return nil, e
	}
	var m *D.Msg
	if network == "tcp" {
		dc := &D.Conn{Conn: c}
		if e = dc.WriteMsg(q); e != nil {
			return nil, e
		}
		m, e = dc.ReadMsg()
		if e != nil {
			return nil, e
		}
	} else {
		wire, e := q.Pack()
		if e != nil {
			return nil, e
		}
		if n, e := c.Write(wire); e != nil {
			return nil, e
		} else if n != len(wire) {
			return nil, io.ErrShortWrite
		}
		raw := make([]byte, 65535)
		for attempt := 0; attempt < 16; attempt++ {
			n, e := c.Read(raw)
			if e != nil {
				return nil, e
			}
			m = new(D.Msg)
			if e = m.Unpack(raw[:n]); e != nil {
				return nil, e
			}
			if m.Id == q.Id {
				break
			}
			m = nil
		}
	}
	if m == nil || !m.Response || m.Id != q.Id || m.Opcode != q.Opcode || len(m.Question) != len(q.Question) {
		return nil, errors.New("invalid DNS response identity")
	}
	for i, v := range q.Question {
		r := m.Question[i]
		if !strings.EqualFold(r.Name, v.Name) || r.Qtype != v.Qtype || r.Qclass != v.Qclass {
			return nil, errors.New("invalid DNS response question")
		}
	}
	return m, nil
}
