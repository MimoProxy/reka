package sagernet

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func TestMITMLocalReplyWithPendingUpload(t *testing.T) {
	const host = "local-reply.test"
	text, body := "text", "local response"
	informational := http.StatusEarlyHints
	rules, err := httprewrite.New(httprewrite.Spec{
		MapLocal: []httprewrite.MapLocal{
			{ID: "local", Match: "https://local-reply[.]test/reply$", DataType: &text, Data: &body},
			{ID: "informational", Match: "https://local-reply[.]test/hints$", DataType: &text, Data: &body, StatusCode: &informational},
		},
	}, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	issuer, roots := mitmRelayTestIssuer(t, "Local response test CA")
	wire := mitmLocalTestConnection(t, &MITMRoute{Host: host, Issuer: issuer, Rewrite: rules}, 0)
	client := tls.Client(wire, &tls.Config{ServerName: host, RootCAs: roots})
	reader := bufio.NewReader(client)
	if _, err := io.WriteString(client, "POST /reply HTTP/1.1\r\nHost: "+host+"\r\nContent-Length: 4\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reply, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(reply.Body)
	reply.Body.Close()
	if err != nil || reply.StatusCode != http.StatusOK || string(payload) != body {
		t.Fatalf("local response: status %d, body %q, error %v", reply.StatusCode, payload, err)
	}
	if _, err := io.WriteString(client, "dataGET /hints HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reply, err = http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Body.Close()
	if reply.StatusCode != http.StatusBadGateway {
		t.Fatalf("informational local response status = %d, want %d", reply.StatusCode, http.StatusBadGateway)
	}
	if _, err := io.Copy(io.Discard, reply.Body); err != nil {
		t.Fatal(err)
	}
}

func TestMITMPinFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		sent bool
		want string
	}{
		{"certificate alert", &net.OpError{Op: "remote error", Err: tls.AlertError(48)}, true, "unknown_ca"},
		{"local TLS error", &net.OpError{Op: "local error", Err: tls.AlertError(48)}, true, ""},
		{"early disconnect", io.EOF, false, ""},
		{"disconnect after certificate", io.ErrUnexpectedEOF, true, "eof_after_certificate"},
		{"reset after certificate", syscall.ECONNRESET, true, "reset_after_certificate"},
		{"timeout after certificate", os.ErrDeadlineExceeded, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mitmPinFailure(tc.err, tc.sent); got != tc.want {
				t.Fatalf("certificate failure = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMITMRelayUpstreamCertificateVerification(t *testing.T) {
	const host = "untrusted-origin.test"
	issuer, roots := mitmRelayTestIssuer(t, "Relay certificate test CA")
	origin, _ := mitmRelayTestIssuer(t, "Untrusted origin test CA")
	cert, err := origin.Certificate(host)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		skip bool
		want int
	}{
		{"verify", false, http.StatusBadGateway},
		{"skip verification", true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := New(Options{Logger: testLogger(t)})
			t.Cleanup(func() { _ = backend.Close() })
			client, inbound := connectionEventPipe(t)
			remote, originWire := connectionEventPipe(t)
			deadline := time.Now().Add(3 * time.Second)
			_ = client.SetDeadline(deadline)
			_ = originWire.SetDeadline(deadline)

			originResult := make(chan error, 1)
			go func() {
				defer originWire.Close()
				server := tls.Server(originWire, &tls.Config{Certificates: []tls.Certificate{*cert}})
				if err := server.Handshake(); err != nil {
					originResult <- err
					return
				}
				req, err := http.ReadRequest(bufio.NewReader(server))
				if err == nil {
					err = req.Body.Close()
				}
				if err == nil {
					response := &http.Response{
						StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1, ContentLength: 2,
						Body: io.NopCloser(strings.NewReader("ok")),
					}
					err = response.Write(server)
				}
				originResult <- err
			}()
			out := &Outbound{tag: "origin", typ: "direct", out: mitmRelayTestOutbound{
				dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { return remote, nil },
			}}
			backend.SetRoute(func(context.Context, Metadata) Route {
				return Route{Outbound: out, MITM: &MITMRoute{Host: host, Issuer: issuer, SkipServerCertVerify: tc.skip}}
			})
			done := make(chan struct{})
			go backend.router.RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
				Inbound: "test", Destination: M.ParseSocksaddr(host + ":443"),
			}, func(error) { close(done) })
			conn := tls.Client(client, &tls.Config{ServerName: host, RootCAs: roots})
			if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != tc.want || tc.skip && string(body) != "ok" {
				t.Fatalf("upstream verification response: status %d, body %q, error %v", response.StatusCode, body, err)
			}
			if err := <-originResult; (err == nil) != tc.skip {
				t.Fatalf("origin handshake and response: %v", err)
			}
			_ = client.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("client connection did not finish")
			}
		})
	}
}
