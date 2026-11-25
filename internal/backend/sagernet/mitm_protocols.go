package sagernet

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// mitmSkipH2Disabled marks a matching connection that was relayed without
// decryption because its client only offered HTTP/2 while MITM HTTP/2 is off.
const mitmSkipH2Disabled = "h2-disabled"

var errClientHelloInspected = errors.New("client hello inspected")

func mitmTLSNextProtos(h2 bool) []string {
	if h2 {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

func mitmHTTPProtocols(h2 bool) *http.Protocols {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetHTTP2(h2)
	return p
}

// mitmClientHelloMaxBytes bounds the bytes read while looking for the ALPN
// list: a ClientHello fits in one TLS record (16 KiB plus its header).
const mitmClientHelloMaxBytes = 16<<10 + 5

// peekMITMClientHello reads the client's ClientHello without consuming it and
// reports whether it offers h2 through ALPN but not http/1.1. Such clients,
// gRPC among them, cannot complete an HTTP/1.1-only MITM handshake: crypto/tls
// rejects it with no_application_protocol. The returned conn replays the
// bytes read and has already reported handshake success to the inbound, so
// SOCKS and HTTP proxy clients send their ClientHello and later reports are
// no-ops. A missing or malformed ClientHello reports false and leaves the
// MITM handshake to fail as before.
func peekMITMClientHello(conn net.Conn) (net.Conn, bool) {
	_ = N.ReportConnHandshakeSuccess(conn, conn)
	_ = conn.SetReadDeadline(time.Now().Add(mitmTLSHandshakeTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	var (
		prefix []byte
		protos []string
		found  bool
	)
	for len(prefix) < mitmClientHelloMaxBytes {
		chunk := make([]byte, min(4096, mitmClientHelloMaxBytes-len(prefix)))
		n, readErr := conn.Read(chunk)
		prefix = append(prefix, chunk[:n]...)
		if n > 0 {
			_ = tls.Server(bufio.NewReadOnlyConn(bytes.NewReader(prefix)), &tls.Config{
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					protos, found = slices.Clone(hello.SupportedProtos), true
					return nil, errClientHelloInspected
				},
			}).HandshakeContext(context.Background())
			if found {
				break
			}
		}
		if readErr != nil || n == 0 {
			break
		}
	}
	peeked := &mitmPeekedConn{sniffReplayConn: &sniffReplayConn{Conn: conn, prefix: prefix}}
	return peeked, found && slices.Contains(protos, "h2") && !slices.Contains(protos, "http/1.1")
}

// mitmPeekedConn replays a peeked ClientHello. Handshake success was already
// reported, so it answers later reports itself instead of letting them reach
// the inbound a second time.
type mitmPeekedConn struct {
	*sniffReplayConn
}

func (c *mitmPeekedConn) ConnHandshakeSuccess(net.Conn) error { return nil }

func (c *mitmPeekedConn) HandshakeSuccess() error { return nil }
