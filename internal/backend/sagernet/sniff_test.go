package sagernet

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/testnet"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/proxy"
)

func sniffTLSHello(t *testing.T, name string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		_ = tls.Client(client, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	}()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	return append(header, body...)
}

func TestSniffStreamFragmentedAndReplay(t *testing.T) {
	for _, tc := range []struct {
		name, protocol string
		payload        []byte
	}{
		{"http", "http", []byte("GET /payload HTTP/1.1\r\nHost: Fragmented.Example:443\r\nX-Test: yes\r\n\r\nbody")},
		{"tls", "tls", sniffTLSHello(t, "fragmented.example")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() {
				defer client.Close()
				for pos := 0; pos < len(tc.payload); {
					end := min(pos+7, len(tc.payload))
					if _, err := client.Write(tc.payload[pos:end]); err != nil {
						return
					}
					pos = end
				}
			}()
			original := Destination{Addr: netip.MustParseAddr("192.0.2.4"), Port: 443}
			conn, md, observed := sniffStream(context.Background(), server, Metadata{Destination: original}, SniffOptions{Enabled: true, Timeout: time.Second})
			if md.SniffedDomain != "fragmented.example" || md.Protocol != tc.protocol || md.Destination != original {
				t.Fatalf("sniff result changed original target or lost hint: %+v", md)
			}
			if observed.protocol != tc.protocol || observed.domain != md.SniffedDomain {
				t.Fatalf("unexpected sniff observation: %+v", observed)
			}
			got, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(got, tc.payload) {
				t.Fatalf("sniff consumed or changed bytes: %d/%d: %v", len(got), len(tc.payload), err)
			}
			if replay, ok := conn.(*sniffReplayConn); !ok || replay.prefix != nil {
				t.Fatal("consumed prefix retained")
			}
		})
	}
}

func TestSniffStreamBudgetCancellationAndServerFirst(t *testing.T) {
	t.Run("byte-budget", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		payload := []byte("GET /incomplete HTTP/1.1\r\nHost: example.test\r\n\r\n")
		go func() { _, _ = client.Write(payload); client.Close() }()
		conn, md, observed := sniffStream(context.Background(), server, Metadata{Protocol: "dns"}, SniffOptions{Enabled: true, MaxBytes: 12})
		if md.SniffedDomain != "" {
			t.Fatal("unread host guessed")
		}
		if observed != (sniffObservation{}) || md.Protocol != "dns" {
			t.Fatalf("unexpected sniff result: %+v, %+v", md, observed)
		}
		if replay := conn.(*sniffReplayConn); len(replay.prefix) > 12 {
			t.Fatal("byte budget exceeded")
		}
		got, err := io.ReadAll(conn)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatal("budget fallback lost bytes", err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		ctx, cancel := context.WithCancel(context.Background())
		timer := time.AfterFunc(20*time.Millisecond, cancel)
		defer timer.Stop()
		start := time.Now()
		_, md, _ := sniffStream(ctx, server, Metadata{}, SniffOptions{Enabled: true, Timeout: time.Second})
		if time.Since(start) > 500*time.Millisecond || md.SniffedDomain != "" {
			t.Fatal("cancelled sniff retained a blocking read")
		}
	})
	t.Run("server-first", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		start := time.Now()
		conn, _, _ := sniffStream(context.Background(), server, Metadata{Destination: Destination{Port: 25}}, SniffOptions{Enabled: true, Timeout: time.Second})
		if conn != server || time.Since(start) > 100*time.Millisecond {
			t.Fatal("server-first connection waited for a client payload")
		}
	})
	t.Run("close-prefix", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		go func() { _, _ = client.Write([]byte("bad")) }()
		conn, _, _ := sniffStream(context.Background(), server, Metadata{}, SniffOptions{Enabled: true})
		conn.Close()
		if conn.(*sniffReplayConn).prefix != nil {
			t.Fatal("closed replay retained its prefix")
		}
	})
}

func TestSniffSOCKSHandshakeAndOriginalTarget(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	out, err := b.NewOutbound("direct", DirectSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	var prepared, released atomic.Int32
	observed := make(chan Metadata, 4)
	b.SetPrepareFlow(func(context.Context, Metadata) PreparedFlow {
		prepared.Add(1)
		return PreparedFlow{Sniff: SniffOptions{Enabled: true, Timeout: time.Second}, Route: func(ctx context.Context, md Metadata) Route {
			observed <- md
			return Fixed(out)(ctx, md)
		}, Release: func() { released.Add(1) }}
	})
	var inbound *Inbound
	listen := testnet.RetryAddr(t, func(address netip.AddrPort) (err error) {
		inbound, err = b.NewInbound("mixed", "mixed", address)
		return err
	})
	defer inbound.Close()
	target := echoServer(t)
	dialer, err := proxy.SOCKS5("tcp", listen.String(), nil, &net.Dialer{Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", target.String())
	if err != nil {
		t.Fatal("client did not receive SOCKS success before sending its payload", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("GET / HTTP/1.1\r\nHost: nonexistent.sniff.test\r\n\r\n")
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("matched hostname replaced the reachable IP or damaged payload", err)
	}
	md := <-observed
	if md.SniffedDomain != "nonexistent.sniff.test" || md.Destination.Addr != target.Addr() || md.Protocol != "http" || prepared.Load() != 1 || released.Load() != 1 {
		t.Fatalf("unexpected route or preparation lifecycle: %+v prepared=%d released=%d", md, prepared.Load(), released.Load())
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "sniff-tls-ok") }))
	defer tlsServer.Close()
	tlsTarget := netip.MustParseAddrPort(tlsServer.Listener.Addr().String())
	raw, err := dialer.Dial("tcp", tlsTarget.String())
	if err != nil {
		t.Fatal("SOCKS success blocked before TLS ClientHello", err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	tlsConn := tls.Client(raw, &tls.Config{ServerName: "nonexistent.tls-sniff.test", InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal("sniffed ClientHello was not replayed intact", err)
	}
	md = <-observed
	if md.Protocol != "tls" || md.SniffedDomain != "nonexistent.tls-sniff.test" || md.Destination.Addr != tlsTarget.Addr() || released.Load() != 2 {
		t.Fatalf("unexpected TLS route: %+v released=%d", md, released.Load())
	}
}

func TestSniffConcurrentLimitFallsBackAndReleasesPreparation(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	for range 64 {
		if !b.router.takeSniffSlot() {
			t.Fatal("could not reserve configured slots")
		}
		defer b.router.releaseSniffSlot()
	}
	var released atomic.Int32
	picked := make(chan Metadata, 1)
	b.SetPrepareFlow(func(context.Context, Metadata) PreparedFlow {
		return PreparedFlow{Sniff: SniffOptions{Enabled: true, Timeout: time.Second}, Route: func(_ context.Context, md Metadata) Route { picked <- md; return Route{} }, Release: func() { released.Add(1) }}
	})
	client, server := net.Pipe()
	defer client.Close()
	go b.router.RouteConnectionEx(context.Background(), server, adapter.InboundContext{}, nil)
	select {
	case md := <-picked:
		if md.SniffedDomain != "" {
			t.Fatal("overflow invented a domain")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("concurrency overflow blocked on sniffing")
	}
	deadline := time.Now().Add(time.Second)
	for released.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if released.Load() != 1 {
		t.Fatal("preparation pin leaked or released twice", released.Load())
	}
}

func TestSniffHTTPConnectAndOptInDestinationOverride(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	direct, err := b.NewOutbound("direct", DirectSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	observed := make(chan Metadata, 1)
	b.SetPrepareFlow(func(context.Context, Metadata) PreparedFlow {
		return PreparedFlow{Sniff: SniffOptions{Enabled: true, OverrideDestination: true, Timeout: time.Second}, Route: func(ctx context.Context, md Metadata) Route {
			observed <- md
			return Fixed(direct)(ctx, md)
		}}
	})
	var inbound *Inbound
	listen := testnet.RetryAddr(t, func(address netip.AddrPort) (err error) {
		inbound, err = b.NewInbound("http", "http", address)
		return err
	})
	defer inbound.Close()
	echo := echoServer(t)
	// The IP is deliberately different from the loopback echo listener. Only
	// explicit override may turn the sniffed localhost name into this endpoint.
	original := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), echo.Port())
	conn, err := net.Dial("tcp", listen.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", original, original)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatal("CONNECT did not succeed before the client payload", status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	payload := []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("explicit override did not reach the sniffed hostname", err)
	}
	md := <-observed
	if md.Destination.Addr != original.Addr() || md.SniffedDomain != "localhost" {
		t.Fatal("route hint overwrote original metadata", md)
	}
	active := b.Connections()
	if len(active) != 1 || active[0].Metadata.Destination.Domain != "localhost" || active[0].OriginalDestination != original.String() {
		t.Fatalf("active connection lost its original target after the override: %+v", active)
	}
}

// A genuine QUIC client produces CRYPTO frames split across several Initial
// datagrams. Keeping a long ALPN list makes the fragmentation deterministic.
func sniffQUICInitial(t *testing.T, name string) [][]byte {
	t.Helper()
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	protos := []string{"h3"}
	for i := range 12 {
		protos = append(protos, strings.Repeat(string(rune('a'+i)), 200))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = quic.Dial(ctx, client, server.LocalAddr(), &tls.Config{ServerName: name, InsecureSkipVerify: true, NextProtos: protos}, &quic.Config{})
	}()
	server.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var packets [][]byte
	for len(packets) < 32 {
		packet := make([]byte, 2048)
		n, _, err := server.ReadFrom(packet)
		if err != nil {
			break
		}
		packets = append(packets, packet[:n])
	}
	<-done
	if len(packets) < 2 {
		t.Fatal("QUIC fixture did not produce several Initial datagrams")
	}
	return packets
}

func TestSniffQUICFragmentedPacketsAndBudgets(t *testing.T) {
	packets := sniffQUICInitial(t, "quic.fragmented.test")
	for _, tc := range []struct {
		name                 string
		maxPackets, maxBytes int
		wantDomain           string
	}{
		{"fragmented", 32, 65536, "quic.fragmented.test"},
		{"packet-budget", 1, 65536, ""},
		{"byte-budget", 32, 20, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &udpSession{ctx: ctx}
			f := &udpFlow{s: s, ctx: ctx, cancel: cancel, notify: make(chan struct{}, 1)}
			for _, packet := range packets {
				f.pending = append(f.pending, buf.As(append([]byte(nil), packet...)))
			}
			defer func() {
				for _, b := range f.pending {
					b.Release()
				}
			}()
			md, _ := f.sniffQUIC(Metadata{Destination: Destination{Addr: netip.MustParseAddr("192.0.2.3"), Port: 443}}, SniffOptions{Timeout: time.Second, MaxPackets: tc.maxPackets, MaxBytes: tc.maxBytes})
			if md.SniffedDomain != tc.wantDomain || !md.Destination.Addr.IsValid() {
				t.Fatalf("unexpected QUIC routing hint: %+v", md)
			}
			for i, b := range f.pending {
				if !bytes.Equal(b.Bytes(), packets[i]) {
					t.Fatal("sniffing altered a retained datagram")
				}
			}
		})
	}
}

func TestSniffUDPStopReleasesPreparationAndPackets(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	var released atomic.Int32
	b.SetPrepareFlow(func(context.Context, Metadata) PreparedFlow {
		return PreparedFlow{Sniff: SniffOptions{Enabled: true, Protocols: []string{"quic"}, Timeout: time.Second}, Route: func(context.Context, Metadata) Route { return Route{} }, Release: func() { released.Add(1) }}
	})
	ctx, cancel := context.WithCancel(context.Background())
	s := &udpSession{b: b, r: b.router, ctx: ctx, cancel: cancel, flows: map[M.Socksaddr]*udpFlow{}, rejected: map[M.Socksaddr]time.Time{}}
	f := s.flow(M.ParseSocksaddr("192.0.2.1:443"))
	retained := buf.NewPacket()
	_, _ = retained.Write([]byte("retained packet"))
	s.mu.Lock()
	f.pending = append(f.pending, retained)
	s.mu.Unlock()
	f.close()
	deadline := time.Now().Add(time.Second)
	for released.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if released.Load() != 1 || len(f.pending) != 0 || retained.Cap() != 0 {
		t.Fatal("stopped flow retained preparation resources", released.Load())
	}
}

func TestSniffUDPForwardsRetainedQUICDatagrams(t *testing.T) {
	packets := sniffQUICInitial(t, "udp-preserved.test")
	// Only the first flight is needed; retransmissions can exceed the ordinary
	// pending queue, which intentionally drops overflow like a congested link.
	packets = packets[:min(8, len(packets))]
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		payload := make([]byte, 65535)
		for {
			n, peer, err := echo.ReadFrom(payload)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(payload[:n], peer)
		}
	}()
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	direct, err := b.NewOutbound("direct", DirectSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	observed := make(chan Metadata, 1)
	b.SetPrepareFlow(func(context.Context, Metadata) PreparedFlow {
		return PreparedFlow{Sniff: SniffOptions{Enabled: true, Protocols: []string{"quic"}}, Route: func(ctx context.Context, md Metadata) Route {
			observed <- md
			return Fixed(direct)(ctx, md)
		}}
	})
	var inbound *Inbound
	listen := testnet.RetryAddr(t, func(address netip.AddrPort) (err error) {
		inbound, err = b.NewInbound("socks", "socks", address)
		return err
	})
	defer inbound.Close()
	client := New(Options{Logger: testLogger(t)})
	defer client.Close()
	out, err := client.NewOutbound("socks", SOCKSSpec{Server: "127.0.0.1", Port: listen.Port()})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := out.Dial(ctx, "udp", echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	for _, packet := range packets {
		if _, err := conn.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	for i, packet := range packets {
		got := make([]byte, 65535)
		n, err := conn.Read(got)
		if err != nil || !bytes.Equal(got[:n], packet) {
			t.Fatalf("retained QUIC datagram %d changed/reordered: %v", i, err)
		}
	}
	md := <-observed
	if md.SniffedDomain != "udp-preserved.test" || md.Protocol != "quic" || !md.Destination.Addr.IsLoopback() {
		t.Fatalf("QUIC selection did not retain its original peer: %+v", md)
	}
	active := b.Connections()
	if len(active) != 1 || active[0].Metadata.SniffedDomain != md.SniffedDomain || active[0].Metadata.Destination.String() != echo.LocalAddr().String() {
		t.Fatalf("active UDP connection lost its domain or original peer: %+v", active)
	}
}

func TestSniffDiscardedDomainReplaysPayload(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	data := []byte("GET / HTTP/1.1\r\nHost: private.example\r\n\r\nrest of stream")
	go func() {
		defer client.Close()
		_, _ = client.Write(data)
	}()
	options := SniffOptions{Enabled: true, OverrideDestination: true, Timeout: time.Second,
		SkipDomain: func(domain string) bool { return domain == "private.example" }}
	conn, md, _ := sniffStream(context.Background(), server, Metadata{Destination: Destination{Port: 80}}, options)
	replayed, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(replayed, data) || md.SniffedDomain != "" || md.Protocol != "" {
		t.Fatalf("excluded result or replay was incorrect: %+v, %q, %v", md, replayed, err)
	}
}
