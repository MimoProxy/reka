package sagernet

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

// mitmTLSFingerprint describes a ClientHello without per-connection values.
func mitmTLSFingerprint(t *testing.T, hello []byte) (string, []string) {
	t.Helper()
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	isGrease := func(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }
	var shape bytes.Buffer
	for _, c := range spec.CipherSuites {
		if isGrease(c) {
			c = 0x0a0a
		}
		fmt.Fprintf(&shape, "c%d,", c)
	}
	var alpn []string
	for _, ext := range spec.Extensions {
		switch ext := ext.(type) {
		case *utls.ALPNExtension:
			alpn = ext.AlpnProtocols
		case *utls.SNIExtension:
			shape.WriteString("sni")
		case *utls.SupportedCurvesExtension:
			fmt.Fprint(&shape, "groups")
			for _, g := range ext.Curves {
				if isGrease(uint16(g)) {
					g = 0x0a0a
				}
				fmt.Fprintf(&shape, ":%d", g)
			}
		case *utls.KeyShareExtension:
			fmt.Fprint(&shape, "shares")
			for _, k := range ext.KeyShares {
				if isGrease(uint16(k.Group)) {
					k.Group = 0x0a0a
				}
				fmt.Fprintf(&shape, ":%d", k.Group)
			}
		case *utls.SignatureAlgorithmsExtension:
			fmt.Fprintf(&shape, "sigs%v", ext.SupportedSignatureAlgorithms)
		case *utls.SupportedVersionsExtension:
			fmt.Fprint(&shape, "versions")
			for _, v := range ext.Versions {
				if isGrease(v) {
					v = 0x0a0a
				}
				fmt.Fprintf(&shape, ":%d", v)
			}
		default:
			fmt.Fprintf(&shape, "%T", ext)
		}
		shape.WriteByte(',')
	}
	return shape.String(), alpn
}

// captureMITMUpstreamClientHello runs the upstream handshake against a
// crypto/tls server and returns the ClientHello record it sent.
func captureMITMUpstreamClientHello(t *testing.T, host string, nextProtos []string) ([]byte, string, string) {
	t.Helper()
	certPEM, keyPEM, _ := hy2TestCertificate(t)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type serverResult struct {
		hello      []byte
		serverName string
		err        error
	}
	done := make(chan serverResult, 1)
	go func() {
		serverWire, err := listener.Accept()
		if err != nil {
			done <- serverResult{err: err}
			return
		}
		defer serverWire.Close()
		conn := &mitmRecordingConn{Conn: serverWire}
		server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
		err = server.Handshake()
		// Copy the recording before reads continue on this goroutine.
		done <- serverResult{hello: bytes.Clone(conn.buf.Bytes()), serverName: server.ConnectionState().ServerName, err: err}
		_, _ = io.Copy(io.Discard, server)
	}()
	clientWire, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientWire.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := mitmUpstreamTLSHandshake(ctx, clientWire, host, true, nextProtos)
	if err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	state := conn.ConnectionState()
	if !state.HandshakeComplete || !state.NegotiatedProtocolIsMutual || conn.NetConn() != clientWire {
		t.Fatalf("connection state %+v", state)
	}
	data := result.hello
	length := int(data[3])<<8 | int(data[4])
	return data[:5+length], state.NegotiatedProtocol, result.serverName
}

type mitmRecordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *mitmRecordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.buf.Write(p[:n])
	return n, err
}

func TestMITMUpstreamTLSMatchesAppleClientHello(t *testing.T) {
	want, wantALPN := mitmTLSFingerprint(t, mitmAppleClientHello)
	if !reflect.DeepEqual(wantALPN, []string{"h2", "http/1.1"}) {
		t.Fatalf("captured ALPN %v", wantALPN)
	}
	for _, test := range []struct {
		name, host, sni string
		alpn            []string
		protocol        string
	}{
		{name: "h2", host: "example.com", sni: "example.com", alpn: []string{"h2", "http/1.1"}, protocol: "h2"},
		{name: "http/1.1", host: "example.com", sni: "example.com", alpn: []string{"http/1.1"}, protocol: "http/1.1"},
		{name: "IP address", host: "192.0.2.1", alpn: []string{"h2", "http/1.1"}, protocol: "h2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			hello, protocol, sni := captureMITMUpstreamClientHello(t, test.host, test.alpn)
			got, alpn := mitmTLSFingerprint(t, hello)
			if test.sni == "" {
				// Apple omits SNI for an IP address.
				want := bytes.Replace([]byte(want), []byte("sni,"), nil, 1)
				if got != string(want) {
					t.Fatalf("ClientHello\n got %s\nwant %s", got, want)
				}
			} else if got != want {
				t.Fatalf("ClientHello\n got %s\nwant %s", got, want)
			}
			if !reflect.DeepEqual(alpn, test.alpn) || sni != test.sni || protocol != test.protocol {
				t.Fatalf("ALPN %v, SNI %q, negotiated %q", alpn, sni, protocol)
			}
		})
	}
}

func TestMITMRequestNeedsH2(t *testing.T) {
	for _, test := range []struct {
		contentType string
		trailer     bool
		want        bool
	}{
		{"application/grpc", false, true},
		{"Application/GRPC+proto", false, true},
		{"application/grpc-web+proto", false, false},
		{"application/json", false, false},
		{"", true, true},
		{"", false, false},
	} {
		req, err := http.NewRequest(http.MethodPost, "https://example.com/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if test.contentType != "" {
			req.Header.Set("Content-Type", test.contentType)
		}
		if test.trailer {
			req.Trailer = http.Header{"X-Checksum": nil}
		}
		if got := mitmRequestNeedsH2(req); got != test.want {
			t.Errorf("Content-Type %q, trailer %v: needs HTTP/2 = %v", test.contentType, test.trailer, got)
		}
	}
}
