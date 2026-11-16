package sagernet

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	RD "github.com/MimoProxy/reka/internal/dns"
	D "github.com/miekg/dns"
	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

// dnsPacketConn preserves the selected outbound and its lease. QUIC sends
// only to this connected peer; it cannot open an unprotected second socket.
type dnsPacketConn struct {
	net.Conn
	remote net.Addr
}

func (c *dnsPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, e := c.Read(p)
	return n, c.remote, e
}
func (c *dnsPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
func (c *dnsPacketConn) LocalAddr() net.Addr {
	if a, ok := c.Conn.LocalAddr().(*net.UDPAddr); ok {
		return a
	}
	return &net.UDPAddr{}
}

// Like the pinned reference, prefer-h3 races TLS and QUIC handshakes. It
// sends a single DNS query using the first successfully negotiated transport.
func preferHTTP3(ctx context.Context, open func(context.Context, string) (net.Conn, error), cfg *tls.Config, address string) (bool, error) {
	ctx, cancel := context.WithDeadline(ctx, exchangeDeadline(ctx))
	defer cancel()
	type result struct {
		h3  bool
		err error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	wg.Go(func() {
		conn, e := open(ctx, "tcp")
		if e != nil {
			results <- result{false, e}
			return
		}
		defer conn.Close()
		c := cfg.Clone()
		c.NextProtos = []string{"h2", "http/1.1"}
		results <- result{false, tls.Client(conn, c).HandshakeContext(ctx)}
	})
	wg.Go(func() {
		conn, e := open(ctx, "udp")
		if e != nil {
			results <- result{true, e}
			return
		}
		defer conn.Close()
		remote, e := net.ResolveUDPAddr("udp", address)
		if e != nil {
			results <- result{true, e}
			return
		}
		c := cfg.Clone()
		c.NextProtos = []string{"h3"}
		c.MinVersion = tls.VersionTLS13
		qc, e := quic.Dial(ctx, &dnsPacketConn{conn, remote}, remote, c, &quic.Config{})
		if e == nil {
			qc.CloseWithError(0, "")
		}
		results <- result{true, e}
	})
	defer wg.Wait()
	var failures []error
	for range 2 {
		r := <-results
		if r.err == nil {
			cancel()
			return r.h3, nil
		}
		failures = append(failures, r.err)
	}
	return false, errors.Join(failures...)
}

func exchangeQUICDNS(ctx context.Context, ep RD.Endpoint, q *D.Msg, open func(context.Context, string) (net.Conn, error), cfg *tls.Config, address string) (*D.Msg, error) {
	ctx, cancel := context.WithDeadline(ctx, exchangeDeadline(ctx))
	defer cancel()
	var mu sync.Mutex
	var packets []net.Conn
	closed := false
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		closed = true
		for _, p := range packets {
			p.Close()
		}
	}()
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	// The resolved address is used for QUIC bookkeeping only; open performs
	// the actual bootstrap and connection through the chosen outbound.
	dial := func(ctx context.Context, _ string, t *tls.Config, c *quic.Config) (*quic.Conn, error) {
		conn, e := open(ctx, "udp")
		if e != nil {
			return nil, e
		}
		mu.Lock()
		if closed {
			mu.Unlock()
			conn.Close()
			return nil, net.ErrClosed
		}
		packets = append(packets, conn)
		mu.Unlock()
		result, e := quic.Dial(ctx, &dnsPacketConn{conn, remote}, remote, t, c)
		if e != nil {
			conn.Close()
		}
		return result, e
	}
	cfg = cfg.Clone()
	cfg.MinVersion = tls.VersionTLS13
	if ep.Scheme == "h3" {
		tr := &http3.Transport{TLSClientConfig: cfg, Dial: dial}
		defer tr.Close()
		return exchangeDoHTransport(ctx, ep, q, tr)
	}
	cfg.NextProtos = []string{"doq"}
	connection, err := dial(ctx, "", cfg, &quic.Config{})
	if err != nil {
		return nil, err
	}
	defer connection.CloseWithError(0, "")
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stream.SetDeadline(exchangeDeadline(ctx))
	request := q.Copy()
	request.Id = 0
	wire, err := request.Pack()
	if err != nil {
		return nil, err
	}
	if len(wire) > 65535 {
		return nil, errors.New("DoQ query exceeds maximum message size")
	}
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	if _, err = stream.Write(frame); err != nil {
		return nil, err
	}
	if err = stream.Close(); err != nil {
		return nil, err
	}
	header := make([]byte, 2)
	if _, err = io.ReadFull(stream, header); err != nil {
		return nil, err
	}
	response := make([]byte, int(binary.BigEndian.Uint16(header)))
	if _, err = io.ReadFull(stream, response); err != nil {
		return nil, err
	}
	// RFC 9250 requires one DNS message per stream and a zero wire ID.
	extra := make([]byte, 1)
	if n, e := stream.Read(extra); n != 0 || e != io.EOF {
		return nil, errors.New("invalid DoQ stream framing")
	}
	m := new(D.Msg)
	if err = m.Unpack(response); err != nil {
		return nil, err
	}
	if err = checkReply(request, m); err != nil {
		return nil, err
	}
	m.Id = q.Id
	return m, nil
}
