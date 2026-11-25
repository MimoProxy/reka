package sagernet

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/script"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const mitmH2WireTimeout = 8 * time.Second

func TestMITMHTTP2StreamActions(t *testing.T) {
	const host = "actions.test"
	ref := func(value string) *string { return &value }
	set, err := httprewrite.New(httprewrite.Spec{
		HTTPRewrites: []httprewrite.HTTPRewrite{
			{ID: "close", Match: "/close$", Action: "reject", Response: ref("close")},
			{ID: "drop", Match: "/drop", Action: "reject", Response: ref("drop")},
		},
		MapLocal: []httprewrite.MapLocal{{ID: "reply", Match: "/ok$", DataType: ref("text"), Data: ref("alive")}},
	}, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	issuer, roots := mitmRelayTestIssuer(t, "Stream action test CA")
	started := make(chan struct{}, 10)
	route := &MITMRoute{Host: host, H2: true, Issuer: issuer, Rewrite: set,
		OnRequest: func() { started <- struct{}{} },
		MatchScript: func(kind script.Kind, rawURL string) *MITMScript {
			if kind != script.KindHTTPRequest || !strings.HasSuffix(rawURL, "/abort") {
				return nil
			}
			return &MITMScript{ID: "abort", Run: func(context.Context, *script.Input) (script.Result, error) {
				return script.Result{Action: script.ActionAbort}, nil
			}}
		},
	}
	const dropTimeout = 300 * time.Millisecond
	client := mitmH2WireClient(t, mitmLocalTestConnection(t, route, dropTimeout), host, roots)
	ctx, cancel := context.WithTimeout(t.Context(), mitmH2WireTimeout)
	defer cancel()
	countedTrip := func(path string) (*http.Response, error) {
		response, err := mitmH2WireRoundTrip(ctx, client, host, path, nil)
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatalf("handler did not start for %s", path)
		}
		return response, err
	}
	for _, path := range []string{"/close", "/abort", "/drop"} {
		begin := time.Now()
		response, err := countedTrip(path)
		if response != nil {
			response.Body.Close()
			t.Fatalf("%s returned HTTP status %d", path, response.StatusCode)
		}
		assertMITMH2StreamReset(t, err)
		if path == "/drop" && time.Since(begin) < dropTimeout {
			t.Fatal("drop reset its stream before its timeout")
		}
		response, err = countedTrip("/ok")
		assertMITMH2WireReply(t, response, err, http.StatusOK, "alive")
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	cancelled := make(chan error, 1)
	go func() {
		response, err := mitmH2WireRoundTrip(requestCtx, client, host, "/drop-cancel", nil)
		if response != nil {
			response.Body.Close()
			err = fmt.Errorf("drop returned HTTP status %d", response.StatusCode)
		}
		cancelled <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("drop stream did not start")
	}
	response, err := countedTrip("/ok")
	assertMITMH2WireReply(t, response, err, http.StatusOK, "alive")
	cancelRequest()
	select {
	case err := <-cancelled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled drop = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("drop stream did not cancel")
	}
}

func TestMITMHTTP2ServerStreamLimit(t *testing.T) {
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.Config.Protocols = mitmHTTPProtocols(true)
	server.Config.HTTP2 = mitmHTTP2Config()
	server.Config.HTTP2.MaxConcurrentStreams = 2
	transport := server.Client().Transport.(*http.Transport)
	ctx, cancel := context.WithTimeout(t.Context(), mitmH2WireTimeout)
	defer cancel()
	client, err := transport.NewClientConn(ctx, "https", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := mitmH2WireRoundTrip(ctx, client, "example.com", "/", nil)
	assertMITMH2WireReply(t, response, err, http.StatusNoContent, "")
	ready := make(chan struct{}, 1)
	client.SetStateHook(func(conn *http.ClientConn) {
		if conn.Available() == 2 {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	})
	if client.Available() != 2 {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatalf("available streams = %d, want 2", client.Available())
		}
	}
	for range 2 {
		if err := client.Reserve(); err != nil {
			t.Fatal(err)
		}
		defer client.Release()
	}
	if err := client.Reserve(); err == nil {
		client.Release()
		t.Fatal("client reserved a stream above the server limit")
	}
}

func TestMITMHTTP2UpstreamResetKeepsOtherStreams(t *testing.T) {
	reset := make(chan struct{})
	finishHealthy := make(chan struct{})
	fixture := newMITMH2Fixture(t, &MITMRoute{H2: true, MatchScript: func(kind script.Kind, rawURL string) *MITMScript {
		if kind != script.KindHTTPResponse || !strings.HasSuffix(rawURL, "/script-abort") {
			return nil
		}
		return &MITMScript{ID: "response-abort", Run: func(context.Context, *script.Input) (script.Result, error) {
			return script.Result{Action: script.ActionAbort}, nil
		}}
	}}, true, true, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reset-before-headers":
			panic(http.ErrAbortHandler)
		case "/reset-after-headers":
			_, _ = io.WriteString(w, "partial")
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Error(err)
				return
			}
			select {
			case <-reset:
				panic(http.ErrAbortHandler)
			case <-r.Context().Done():
			}
		case "/healthy":
			_, _ = io.WriteString(w, "partial")
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Error(err)
				return
			}
			select {
			case <-finishHealthy:
				_, _ = io.WriteString(w, " healthy")
			case <-r.Context().Done():
			}
		default:
			_, _ = io.WriteString(w, "healthy")
		}
	})
	res, err := fixture.client.RoundTrip(fixture.request(t, http.MethodGet, "/reset-before-headers", nil))
	assertMITMH2WireReply(t, res, err, http.StatusBadGateway, "HTTPS upstream request failed\n")
	res, err = fixture.client.RoundTrip(fixture.request(t, http.MethodGet, "/script-abort", nil))
	if res != nil {
		res.Body.Close()
		t.Fatalf("response script abort returned HTTP status %d", res.StatusCode)
	}
	assertMITMH2StreamReset(t, err)

	res, err = fixture.client.RoundTrip(fixture.request(t, http.MethodGet, "/reset-after-headers", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	assertMITMH2PartialReply(t, res)
	healthy, err := fixture.client.RoundTrip(fixture.request(t, http.MethodGet, "/healthy", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Body.Close()
	assertMITMH2PartialReply(t, healthy)
	close(reset)
	_, err = io.ReadAll(res.Body)
	assertMITMH2StreamReset(t, err)
	close(finishHealthy)
	assertMITMH2WireReply(t, healthy, nil, http.StatusOK, " healthy")
	healthy, err = fixture.client.RoundTrip(fixture.request(t, http.MethodGet, "/healthy-again", nil))
	assertMITMH2WireReply(t, healthy, err, http.StatusOK, "healthy")
	if dials := fixture.dials.Load(); dials != 1 {
		t.Fatalf("upstream dials = %d, want a single multiplexed connection", dials)
	}
}

func TestMITMHTTP2UpstreamGoAwayReplaysBufferedRequest(t *testing.T) {
	ref := func(value string) *string { return &value }
	set, err := httprewrite.New(httprewrite.Spec{BodyRewrites: []httprewrite.BodyRewrite{{
		ID: "request-body", Match: "/retry$", Phase: "request",
		Replace: []httprewrite.Replacement{{Pattern: ref("original"), Value: ref("rewritten")}},
	}}}, httprewrite.Options{MaxBodySize: 64})
	if err != nil {
		t.Fatal(err)
	}
	const payload = "rewritten upload"
	fixture, served := mitmH2FrameProxy(t, &MITMRoute{Rewrite: set, MaxBodySize: 64}, mitmH2FrameConfig{},
		func(origin *mitmH2FrameOrigin) error {
			request, err := origin.nextRequest()
			if err != nil || request.body != payload {
				return fmt.Errorf("original upstream request body = %q, %v", request.body, err)
			}
			// Last stream ID zero tells the transport this request never ran,
			// even though the test peer received its complete upload.
			if err := origin.fr.WriteGoAway(0, http2.ErrCodeNo, nil); err != nil {
				return err
			}
			return origin.writer.Flush()
		},
		func(origin *mitmH2FrameOrigin) error {
			request, err := origin.nextRequest()
			if err != nil || request.body != payload {
				return fmt.Errorf("retried upstream request body = %q, %v", request.body, err)
			}
			return origin.reply(request.id, request.body, true)
		},
	)
	ctx, cancel := context.WithTimeout(t.Context(), mitmH2WireTimeout)
	defer cancel()
	res, err := mitmH2WireRoundTrip(ctx, fixture.client, mitmH2TestHost, "/retry", strings.NewReader("original upload"))
	assertMITMH2WireReply(t, res, err, http.StatusOK, payload)
	assertMITMH2OriginDone(t, ctx, served, 2)
}

func TestMITMHTTP2UpstreamCapsStreamingDataFrames(t *testing.T) {
	const (
		chunkSize = 100 << 10
		window    = 1 << 20
		frameCap  = 16 << 10
	)
	chunks := []string{strings.Repeat("a", chunkSize), strings.Repeat("b", chunkSize), strings.Repeat("c", chunkSize)}
	payload := strings.Join(chunks, "")
	config := mitmH2FrameConfig{
		settings: []http2.Setting{
			{ID: http2.SettingMaxFrameSize, Val: 1 << 20},
			{ID: http2.SettingInitialWindowSize, Val: window},
		},
		connectionWindowIncrement: window,
	}
	fixture, served := mitmH2FrameProxy(t, &MITMRoute{}, config, func(origin *mitmH2FrameOrigin) error {
		ready, err := origin.nextRequest()
		if err != nil {
			return err
		}
		if err := origin.reply(ready.id, "ready", true); err != nil {
			return err
		}
		upload, err := origin.nextRequest()
		if err != nil {
			return err
		}
		if upload.hasContentLength {
			return errors.New("streaming request unexpectedly declared Content-Length")
		}
		if upload.maxDataFrameSize > frameCap {
			return fmt.Errorf("largest upstream DATA frame payload = %d bytes, want at most %d", upload.maxDataFrameSize, frameCap)
		}
		if upload.body != payload {
			return fmt.Errorf("upstream upload differs from the %d-byte payload: received %d bytes", len(payload), len(upload.body))
		}
		return origin.reply(upload.id, "received", true)
	})
	ctx, cancel := context.WithTimeout(t.Context(), mitmH2WireTimeout)
	defer cancel()
	// The first reply confirms the upstream client processed SETTINGS before
	// the upload begins on the reused connection.
	res, err := mitmH2WireRoundTrip(ctx, fixture.client, mitmH2TestHost, "/ready", nil)
	assertMITMH2WireReply(t, res, err, http.StatusOK, "ready")
	reader, writer := io.Pipe()
	defer reader.Close()
	go func() {
		defer writer.Close()
		for _, chunk := range chunks {
			if _, err := io.WriteString(writer, chunk); err != nil {
				return
			}
		}
	}()
	res, err = mitmH2WireRoundTrip(ctx, fixture.client, mitmH2TestHost, "/upload", reader)
	if res != nil {
		defer res.Body.Close()
	}
	assertMITMH2OriginDone(t, ctx, served, 1)
	assertMITMH2WireReply(t, res, err, http.StatusOK, "received")
	if dials := fixture.dials.Load(); dials != 1 {
		t.Fatalf("upstream dials = %d, want one reused connection", dials)
	}
	live := fixture.live(t)
	if live.MITMClientProtocol != "h2" || !slices.Equal(live.MITMUpstreamProtocols, []string{"h2"}) {
		t.Fatalf("live MITM diagnostics = %+v", live.MITMConnectionInfo)
	}
	for _, row := range fixture.requestHistory(t, 2) {
		if row.ConnectionID != live.ID || row.UpstreamHTTP != "HTTP/2.0" {
			t.Fatalf("request history = %+v", row)
		}
		if row.Path == "/ready" && row.TLSMS == nil {
			t.Fatalf("first upstream request did not record TLS handshake timing: %+v", row)
		}
	}
}

func TestMITMHTTP2UpstreamGoAwayAcceptedStream(t *testing.T) {
	for _, started := range []bool{false, true} {
		name := "before-headers"
		if started {
			name = "after-headers"
		}
		t.Run(name, func(t *testing.T) {
			ref := func(value string) *string { return &value }
			set, err := httprewrite.New(httprewrite.Spec{MapLocal: []httprewrite.MapLocal{{
				ID: "local", Match: "/local$", DataType: ref("text"), Data: ref("healthy"),
			}}}, httprewrite.Options{})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), mitmH2WireTimeout)
			defer cancel()
			finish := make(chan struct{})
			fixture, served := mitmH2FrameProxy(t, &MITMRoute{Rewrite: set}, mitmH2FrameConfig{}, func(origin *mitmH2FrameOrigin) error {
				request, err := origin.nextRequest()
				if err != nil {
					return err
				}
				if started {
					if err := origin.reply(request.id, "partial", false); err != nil {
						return err
					}
					select {
					case <-finish:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				if err := origin.fr.WriteGoAway(request.id, http2.ErrCodeNo, nil); err != nil {
					return err
				}
				// Closing the connection leaves this accepted stream incomplete.
				return origin.writer.Flush()
			})
			res, err := mitmH2WireRoundTrip(ctx, fixture.client, mitmH2TestHost, "/origin", nil)
			if started {
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				assertMITMH2PartialReply(t, res)
				local, err := mitmH2WireRoundTrip(ctx, fixture.client, mitmH2TestHost, "/local", nil)
				assertMITMH2WireReply(t, local, err, http.StatusOK, "healthy")
				close(finish)
				_, err = io.ReadAll(res.Body)
				assertMITMH2StreamReset(t, err)
			} else {
				assertMITMH2WireReply(t, res, err, http.StatusBadGateway, "HTTPS upstream request failed\n")
			}
			assertMITMH2OriginDone(t, ctx, served, 1)
			local, err := mitmH2WireRoundTrip(ctx, fixture.client, mitmH2TestHost, "/local", nil)
			assertMITMH2WireReply(t, local, err, http.StatusOK, "healthy")
		})
	}
}

func assertMITMH2PartialReply(t *testing.T, res *http.Response) {
	t.Helper()
	const want = "partial"
	if res.StatusCode != http.StatusOK || res.ProtoMajor != 2 {
		t.Fatalf("response = %s %s, want HTTP/2 status 200", res.Proto, res.Status)
	}
	b := make([]byte, len(want))
	if _, err := io.ReadFull(res.Body, b); err != nil || string(b) != want {
		t.Fatalf("partial response = %q, %v", b, err)
	}
}

type mitmH2FrameOrigin struct {
	fr          *http2.Framer
	writer      *bufio.Writer
	settingsAck bool
}

type mitmH2FrameConfig struct {
	settings                  []http2.Setting
	connectionWindowIncrement uint32
}

// The raw origin controls its HTTP/2 SETTINGS and GOAWAY last stream ID.
// The relay still handshakes and uses net/http on both hops.
func mitmH2FrameProxy(t *testing.T, route *MITMRoute, config mitmH2FrameConfig, sessions ...func(*mitmH2FrameOrigin) error) (*mitmH2Fixture, <-chan error) {
	t.Helper()
	clientIssuer, roots := mitmRelayTestIssuer(t, "Client wire test CA")
	originIssuer, _ := mitmRelayTestIssuer(t, "Origin wire test CA")
	originCert, err := originIssuer.GetCertificate(&tls.ClientHelloInfo{ServerName: mitmH2TestHost})
	if err != nil {
		t.Fatal(err)
	}
	route.Host, route.Issuer, route.H2, route.SkipServerCertVerify = mitmH2TestHost, clientIssuer, true, true
	fixture := &mitmH2Fixture{records: history.New(), done: make(chan struct{})}
	fixture.backend = New(Options{History: fixture.records, Logger: testLogger(t)})
	t.Cleanup(func() { _ = fixture.backend.Close() })
	client, inbound := connectionEventPipe(t)
	served := make(chan error, len(sessions))
	out := &Outbound{tag: "origin", typ: "direct", out: mitmRelayTestOutbound{
		dial: func(_ context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
			i := int(fixture.dials.Add(1)) - 1
			if i >= len(sessions) {
				return nil, errors.New("unexpected upstream dial")
			}
			remote, peer := net.Pipe()
			_ = peer.SetDeadline(time.Now().Add(mitmH2WireTimeout))
			go func() {
				defer peer.Close()
				server := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{*originCert}, NextProtos: []string{"h2"}})
				served <- serveMITMH2Frames(server, config, sessions[i])
			}()
			return &mitmH2OriginConn{Conn: remote, closed: &fixture.closed}, nil
		},
	}}
	fixture.backend.SetRoute(func(context.Context, Metadata) Route { return Route{Outbound: out, MITM: route} })
	go fixture.backend.router.RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
		Inbound: "test", InboundType: "mixed", Destination: M.ParseSocksaddr(mitmH2TestHost + ":443"),
	}, func(error) { close(fixture.done) })
	t.Cleanup(func() {
		_ = client.Close()
		fixture.waitClosed(t)
	})
	fixture.client = mitmH2WireClient(t, client, mitmH2TestHost, roots)
	return fixture, served
}

func serveMITMH2Frames(server *tls.Conn, config mitmH2FrameConfig, session func(*mitmH2FrameOrigin) error) error {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(server, preface); err != nil {
		return err
	}
	if string(preface) != http2.ClientPreface {
		return fmt.Errorf("upstream preface = %q", preface)
	}
	writer := bufio.NewWriter(server)
	fr := http2.NewFramer(writer, server)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	frame, err := fr.ReadFrame()
	if err != nil {
		return err
	}
	if settings, ok := frame.(*http2.SettingsFrame); !ok || settings.IsAck() {
		return fmt.Errorf("first upstream frame = %T, want SETTINGS", frame)
	}
	if err := fr.WriteSettings(config.settings...); err != nil {
		return err
	}
	if err := fr.WriteSettingsAck(); err != nil {
		return err
	}
	if config.connectionWindowIncrement != 0 {
		if err := fr.WriteWindowUpdate(0, config.connectionWindowIncrement); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	return session(&mitmH2FrameOrigin{fr: fr, writer: writer})
}

type mitmH2FrameRequest struct {
	id               uint32
	body             string
	hasContentLength bool
	maxDataFrameSize uint32
}

func (o *mitmH2FrameOrigin) nextRequest() (mitmH2FrameRequest, error) {
	var request mitmH2FrameRequest
	var ended bool
	var body strings.Builder
	// Drain the SETTINGS ACK before writing. net.Pipe has no socket
	// buffer and the client's frame reader may be blocked writing its ACK.
	for !ended || !o.settingsAck {
		frame, err := o.fr.ReadFrame()
		if err != nil {
			return mitmH2FrameRequest{}, err
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			o.settingsAck = o.settingsAck || frame.IsAck()
		case *http2.MetaHeadersFrame:
			for _, field := range frame.RegularFields() {
				if field.Name == "content-length" {
					request.hasContentLength = true
				}
			}
			if frame.StreamEnded() {
				request.id, ended = frame.StreamID, true
			}
		case *http2.DataFrame:
			request.maxDataFrameSize = max(request.maxDataFrameSize, frame.Header().Length)
			body.Write(frame.Data())
			if frame.StreamEnded() {
				request.id, ended = frame.StreamID, true
			}
		}
	}
	request.body = body.String()
	return request, nil
}

func (o *mitmH2FrameOrigin) reply(id uint32, body string, end bool) error {
	var block bytes.Buffer
	if err := hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
		return err
	}
	if err := o.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
		return err
	}
	if err := o.fr.WriteData(id, end, []byte(body)); err != nil {
		return err
	}
	return o.writer.Flush()
}

func assertMITMH2OriginDone(t *testing.T, ctx context.Context, served <-chan error, count int) {
	t.Helper()
	for range count {
		select {
		case err := <-served:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("wire origin did not finish")
		}
	}
}

func mitmH2WireClient(t *testing.T, conn net.Conn, host string, roots *x509.CertPool) *http.ClientConn {
	t.Helper()
	transport := &http.Transport{
		Protocols:       mitmHTTPProtocols(true),
		TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext:     func(context.Context, string, string) (net.Conn, error) { return conn, nil },
	}
	ctx, cancel := context.WithTimeout(t.Context(), mitmH2WireTimeout)
	defer cancel()
	client, err := transport.NewClientConn(ctx, "https", host+":443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func mitmH2WireRoundTrip(ctx context.Context, client *http.ClientConn, host, path string, body io.Reader) (*http.Response, error) {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	request, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, body)
	if err != nil {
		return nil, err
	}
	return client.RoundTrip(request)
}

func assertMITMH2StreamReset(t *testing.T, err error) {
	t.Helper()
	var streamError http2.StreamError
	if !errors.As(err, &streamError) || streamError.Code != http2.ErrCodeInternal {
		t.Fatalf("stream error = %v, want RST_STREAM INTERNAL_ERROR", err)
	}
}

func assertMITMH2WireReply(t *testing.T, response *http.Response, err error, status int, want string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != status || response.ProtoMajor != 2 {
		t.Fatalf("response = %s %s, want HTTP/2 status %d", response.Proto, response.Status, status)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != want {
		t.Fatalf("response body = %q, %v, want %q", body, err, want)
	}
}
