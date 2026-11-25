package sagernet

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"

	"github.com/MimoProxy/reka/internal/history"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// With MITM HTTP/2 off, a client that offers only h2 is relayed undecrypted
// instead of failing an HTTP/1.1-only handshake; clients that also offer
// http/1.1 are still intercepted.
func TestMITMHTTP2DisabledRelaysHTTP2OnlyClients(t *testing.T) {
	for _, test := range []struct {
		name      string
		alpn      []string
		wantMITM  bool
		wantProto string
	}{
		{"h2 only", []string{"h2"}, false, "h2"},
		{"h2 and http/1.1", []string{"h2", "http/1.1"}, true, "http/1.1"},
		{"no ALPN", nil, true, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			origin := newMITMH2Origin(t, true, func(w http.ResponseWriter, r *http.Request) {})
			issuer, _ := mitmRelayTestIssuer(t, "HTTP/2 bypass test CA")
			records := history.New()
			backend := New(Options{History: records, Logger: testLogger(t)})
			t.Cleanup(func() { _ = backend.Close() })
			out := &Outbound{tag: "origin", typ: "direct", out: origin}
			route := &MITMRoute{Host: mitmH2TestHost, Issuer: issuer, SkipServerCertVerify: true}
			backend.SetRoute(func(context.Context, Metadata) Route { return Route{Outbound: out, MITM: route} })
			client, inbound := connectionEventPipe(t)
			done := make(chan struct{})
			go backend.router.RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
				Inbound: "test", InboundType: "mixed", Destination: M.ParseSocksaddr(mitmH2TestHost + ":443"),
			}, func(error) { close(done) })

			ctx, cancel := context.WithTimeout(t.Context(), mitmH2TestTimeout)
			defer cancel()
			conn := tls.Client(client, &tls.Config{ServerName: mitmH2TestHost, NextProtos: test.alpn, InsecureSkipVerify: true})
			if err := conn.HandshakeContext(ctx); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			state := conn.ConnectionState()
			issuedByMITM := state.PeerCertificates[0].Issuer.CommonName == "HTTP/2 bypass test CA"
			if issuedByMITM != test.wantMITM || state.NegotiatedProtocol != test.wantProto {
				t.Fatalf("MITM certificate = %v, ALPN = %q; want %v, %q", issuedByMITM, state.NegotiatedProtocol, test.wantMITM, test.wantProto)
			}
			connections := backend.Connections()
			if len(connections) != 1 {
				t.Fatalf("active connections = %v", connections)
			}
			live := connections[0]
			wantSkipped := ""
			if !test.wantMITM {
				wantSkipped = mitmSkipH2Disabled
			}
			if live.MITM != test.wantMITM || live.MITMSkipped != wantSkipped {
				t.Fatalf("MITM diagnostics = %+v", live.MITMConnectionInfo)
			}
			_ = conn.Close()
			<-done
		})
	}
}

var _ net.Conn = (*mitmPeekedConn)(nil)
