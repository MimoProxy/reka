package sagernet

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	D "github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"

	RD "github.com/MimoProxy/reka/internal/dns"
)

// dnsTimeout bounds one upstream exchange when the context allows longer.
const dnsTimeout = 5 * time.Second

// LookupFunc resolves a host name to addresses.
type LookupFunc func(context.Context, string) ([]netip.Addr, error)

type lookupKey struct{}

type pinnedOutboundsKey struct{}

// WithPinnedOutbounds permits DNS work belonging to a captured routing
// snapshot to borrow its exact outbounds even after a concurrent retirement.
// Pins are owned by the preparation; every borrowed socket retains its pin.
func WithPinnedOutbounds(ctx context.Context, pins map[*Outbound]*PinnedOutbound) context.Context {
	copy := make(map[*Outbound]*PinnedOutbound, len(pins))
	for out, pin := range pins {
		copy[out] = pin
	}
	return context.WithValue(ctx, pinnedOutboundsKey{}, copy)
}

// WithLookup attaches the resolver outbounds use for server host names.
func WithLookup(ctx context.Context, fn LookupFunc) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, lookupKey{}, fn)
}

// leasedConn holds a lease on its outbound until it is closed.
type leasedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *leasedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// Dial opens a connection through the outbound for the kernel's own use
// (DNS upstreams, downloads). The connection holds a lease, so a replaced
// outbound drains before it closes.
func (o *Outbound) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if pins, ok := ctx.Value(pinnedOutboundsKey{}).(map[*Outbound]*PinnedOutbound); ok {
		if pin := pins[o]; pin != nil {
			return pin.Dial(ctx, network, address)
		}
	}
	if !o.lease.Acquire() {
		return nil, errors.New("outbound retired")
	}
	c, err := o.out.DialContext(ctx, network, M.ParseSocksaddr(address))
	if err != nil {
		o.lease.Release()
		return nil, err
	}
	return &leasedConn{Conn: c, release: o.lease.Release}, nil
}

// DNSDial opens a connection to a DNS upstream through the outbound named
// by via.
type DNSDial func(ctx context.Context, network, address, via string) (net.Conn, error)

// ExchangeDNS sends q to one upstream endpoint over UDP, TCP, DoT or DoH.
// A host-name endpoint is first resolved with lookup (the bootstrap path).
func ExchangeDNS(ctx context.Context, ep RD.Endpoint, q *D.Msg, lookup func(context.Context, string) ([]netip.Addr, error), dial DNSDial) (*D.Msg, error) {
	return exchangeDNS(ctx, ep, q, lookup, dial, nil)
}

// exchangeDNS is ExchangeDNS with the TLS roots tests use.
func exchangeDNS(ctx context.Context, ep RD.Endpoint, q *D.Msg, lookup func(context.Context, string) ([]netip.Addr, error), dial DNSDial, roots *x509.CertPool) (*D.Msg, error) {
	host := ep.Host
	if _, err := netip.ParseAddr(host); err != nil {
		ips, err := lookup(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("DNS endpoint bootstrap failed")
		}
		host = ips[0].String()
	}
	address := net.JoinHostPort(host, ep.Port)
	open := func(ctx context.Context, network string) (net.Conn, error) {
		return dial(ctx, network, address, ep.Via)
	}
	// Certificates are checked against the configured name, not the
	// bootstrap address.
	tlsConfig := dnsTLSConfig(ep, roots)

	var (
		m   *D.Msg
		err error
	)
	switch ep.Scheme {
	case "udp", "tcp":
		m, err = exchangePlainDNS(ctx, ep.Scheme, open, q)
		if err == nil && ep.Scheme == "udp" && m.Truncated {
			m, err = exchangePlainDNS(ctx, "tcp", open, q)
		}
	case "quic", "h3":
		m, err = exchangeQUICDNS(ctx, ep, q, open, tlsConfig, address)
	case "https", "http":
		h3 := false
		if ep.PreferH3 {
			h3, err = preferHTTP3(ctx, open, tlsConfig, address)
		}
		if err == nil {
			if h3 {
				ep.Scheme = "h3"
				m, err = exchangeQUICDNS(ctx, ep, q, open, tlsConfig, address)
			} else {
				m, err = exchangeDoH(ctx, ep, open, tlsConfig, q)
			}
		}
	case "tls":
		m, err = exchangeDoT(ctx, open, tlsConfig, q)
	default:
		return nil, errors.New("unsupported DNS transport")
	}
	if err != nil {
		return nil, err
	}
	if err := checkReply(q, m); err != nil {
		return nil, err
	}
	return m, nil
}

func dnsTLSConfig(ep RD.Endpoint, roots *x509.CertPool) *tls.Config {
	tlsConfig := &tls.Config{ServerName: ep.Host, MinVersion: tls.VersionTLS12, RootCAs: roots}
	tlsConfig.InsecureSkipVerify = ep.Params["skip-cert-verify"] == "true"
	if name := ep.Params["name-cert-verify"]; name != "" {
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("DNS peer did not present a certificate")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: intermediates})
			return err
		}
	}

	return tlsConfig
}

// exchangeDeadline is the earlier of the context deadline and dnsTimeout.
func exchangeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(dnsTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return deadline
}

// exchangePlainDNS sends one query on its own connected socket. A UDP
// socket skips replies whose ID does not match (late answers to earlier
// queries); the caller checks the rest of the reply.
func exchangePlainDNS(ctx context.Context, network string, open func(context.Context, string) (net.Conn, error), q *D.Msg) (*D.Msg, error) {
	c, err := open(ctx, network)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if err := c.SetDeadline(exchangeDeadline(ctx)); err != nil {
		return nil, err
	}
	if network == "tcp" {
		dc := &D.Conn{Conn: c}
		if err := dc.WriteMsg(q); err != nil {
			return nil, err
		}
		return dc.ReadMsg()
	}
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	if n, err := c.Write(wire); err != nil {
		return nil, err
	} else if n != len(wire) {
		return nil, io.ErrShortWrite
	}
	raw := make([]byte, 65535)
	for range 16 {
		n, err := c.Read(raw)
		if err != nil {
			return nil, err
		}
		m := new(D.Msg)
		if err := m.Unpack(raw[:n]); err != nil {
			return nil, err
		}
		if m.Id == q.Id {
			return m, nil
		}
	}
	return nil, errors.New("invalid DNS response identity")
}

// exchangeDoH posts one query to a DNS-over-HTTPS endpoint. Redirects are
// refused, and the reply must be a DNS message of at most 64 KiB.
func exchangeDoH(ctx context.Context, ep RD.Endpoint, open func(context.Context, string) (net.Conn, error), tlsConfig *tls.Config, q *D.Msg) (*D.Msg, error) {
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   tlsConfig,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return open(ctx, "tcp")
		},
	}
	defer transport.CloseIdleConnections()
	return exchangeDoHTransport(ctx, ep, q, transport)
}
func exchangeDoHTransport(ctx context.Context, ep RD.Endpoint, q *D.Msg, transport http.RoundTripper) (*D.Msg, error) {
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   dnsTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("DNS redirect forbidden")
		},
	}
	scheme := "https"
	if ep.Scheme == "http" {
		scheme = "http"
	}
	url := scheme + "://" + net.JoinHostPort(ep.Host, ep.Port) + ep.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/dns-message") {
		return nil, errors.New("invalid DoH response")
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil || len(body) > 65535 {
		return nil, errors.New("invalid DoH size")
	}
	m := new(D.Msg)
	if err := m.Unpack(body); err != nil {
		return nil, err
	}
	return m, nil
}

// exchangeDoT sends one query over a fresh DNS-over-TLS connection.
func exchangeDoT(ctx context.Context, open func(context.Context, string) (net.Conn, error), tlsConfig *tls.Config, q *D.Msg) (*D.Msg, error) {
	c, err := open(ctx, "tcp")
	if err != nil {
		return nil, err
	}
	defer c.Close()
	tc := tls.Client(c, tlsConfig)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if err := tc.SetDeadline(exchangeDeadline(ctx)); err != nil {
		return nil, err
	}
	client := &D.Client{Net: "tcp", Timeout: dnsTimeout}
	m, _, err := client.ExchangeWithConnContext(ctx, q, &D.Conn{Conn: tc, UDPSize: 1232})
	return m, err
}

// checkReply rejects a reply that does not answer q: wrong ID, opcode or
// question, or not a response at all.
func checkReply(q, m *D.Msg) error {
	if m == nil || !m.Response || m.Id != q.Id || m.Opcode != q.Opcode || len(m.Question) != len(q.Question) {
		return errors.New("invalid DNS response identity")
	}
	for i, want := range q.Question {
		got := m.Question[i]
		if !strings.EqualFold(got.Name, want.Name) || got.Qtype != want.Qtype || got.Qclass != want.Qclass {
			return errors.New("invalid DNS response question")
		}
	}
	return nil
}

// DNSListener answers DNS queries on one address over UDP and TCP.
type DNSListener struct{ udp, tcp *D.Server }

// NewDNSListener serves exchange on address. UDP replies are truncated to
// the client's EDNS size (512 bytes without EDNS, at most 4096).
func NewDNSListener(address string, exchange func(context.Context, *D.Msg) (*D.Msg, error)) (*DNSListener, error) {
	packet, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", packet.LocalAddr().String())
	if err != nil {
		packet.Close()
		return nil, err
	}
	handler := D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout+time.Second)
		defer cancel()
		m, err := exchange(ctx, q)
		if err != nil {
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
	d := &DNSListener{
		udp: &D.Server{PacketConn: packet, Handler: handler},
		tcp: &D.Server{Listener: listener, Handler: handler},
	}
	go d.udp.ActivateAndServe()
	go d.tcp.ActivateAndServe()
	return d, nil
}

// Close stops both servers, waiting up to a second for in-flight queries.
func (d *DNSListener) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = d.udp.ShutdownContext(ctx)
	_ = d.tcp.ShutdownContext(ctx)
}
