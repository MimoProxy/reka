package sagernet

import (
	"context"
	"crypto/tls"
	_ "embed"
	"net"
	"net/netip"

	utls "github.com/metacubex/utls"
)

// mitmAppleClientHello is a ClientHello sent by Apple's URLSession
// (CFNetwork 3896). Intercepted traffic mostly comes from Apple devices, and
// some CDNs reject clients whose TLS or HTTP/2 fingerprint does not match the
// app named in the request. The upstream handshake reuses its cipher suites,
// extensions and their order; GREASE values, random data and key shares are
// generated per connection.
//
//go:embed mitm_apple_client_hello.bin
var mitmAppleClientHello []byte

// mitmTLSConn is the upstream TLS connection net/http drives after a custom
// TLS dial.
type mitmTLSConn interface {
	net.Conn
	// ConnectionState lets net/http switch to HTTP/2 after ALPN and lets
	// request history read the negotiated protocol.
	ConnectionState() tls.ConnectionState
	NetConn() net.Conn
}

// mitmUTLSConn presents a uTLS connection with crypto/tls's connection state.
type mitmUTLSConn struct {
	*utls.UConn
}

func (c *mitmUTLSConn) ConnectionState() tls.ConnectionState {
	v := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:            v.Version,
		HandshakeComplete:  v.HandshakeComplete,
		DidResume:          v.DidResume,
		CipherSuite:        v.CipherSuite,
		NegotiatedProtocol: v.NegotiatedProtocol,
		// crypto/tls always reports true; net/http checks it before using ALPN.
		NegotiatedProtocolIsMutual: true,
		ServerName:                 v.ServerName,
		PeerCertificates:           v.PeerCertificates,
		VerifiedChains:             v.VerifiedChains,
	}
}

// mitmAppleClientHelloSpec returns the Apple ClientHello for host, offering
// nextProtos in ALPN. Apple omits SNI for an IP address.
func mitmAppleClientHelloSpec(host string, nextProtos []string) (*utls.ClientHelloSpec, error) {
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(mitmAppleClientHello)
	if err != nil {
		return nil, err
	}
	_, ipErr := netip.ParseAddr(host)
	extensions := spec.Extensions[:0]
	for _, ext := range spec.Extensions {
		switch ext := ext.(type) {
		case *utls.SNIExtension:
			if ipErr != nil {
				ext.ServerName = host
				extensions = append(extensions, ext)
			}
			continue
		case *utls.ALPNExtension:
			ext.AlpnProtocols = append([]string(nil), nextProtos...)
		}
		extensions = append(extensions, ext)
	}
	spec.Extensions = extensions
	return spec, nil
}

// mitmUpstreamTLSHandshake runs the upstream handshake with the Apple
// ClientHello. Certificate verification follows crypto/tls.
func mitmUpstreamTLSHandshake(ctx context.Context, conn net.Conn, host string, skipVerify bool, nextProtos []string) (mitmTLSConn, error) {
	spec, err := mitmAppleClientHelloSpec(host, nextProtos)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(conn, &utls.Config{
		ServerName: host, InsecureSkipVerify: skipVerify, MinVersion: utls.VersionTLS12, NextProtos: nextProtos,
	}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, err
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return &mitmUTLSConn{UConn: uconn}, nil
}
