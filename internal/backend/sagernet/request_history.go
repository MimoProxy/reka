package sagernet

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/MimoProxy/reka/internal/history"
)

const httpObservationKey = "reka.inbound.http-observation.v1"

type requestHistoryKey struct{}

type requestRecord struct {
	history.Scope
	ID            uint64    `json:"id"`
	ConnectionID  uint64    `json:"connection_id,omitempty"`
	Start         time.Time `json:"start"`
	DurationMS    int64     `json:"duration_ms"`
	TTFBMS        *int64    `json:"ttfb_ms,omitempty"`
	DialMS        *int64    `json:"dial_ms,omitempty"`
	DNSMS         *int64    `json:"dns_ms,omitempty"`
	TLSMS         *int64    `json:"tls_ms,omitempty"`
	Reused        *bool     `json:"reused,omitempty"`
	UpstreamHTTP  string    `json:"upstream_http_version,omitempty"`
	Detail        bool      `json:"detail,omitempty"`
	Inbound       string    `json:"inbound"`
	Client        string    `json:"client,omitempty"`
	Method        string    `json:"method"`
	Scheme        string    `json:"scheme"`
	Host          string    `json:"host"`
	Path          string    `json:"path"`
	HTTPVersion   string    `json:"http_version"`
	StatusCode    int       `json:"status_code,omitempty"`
	StatusSource  string    `json:"status_source,omitempty"`
	RequestBytes  int64     `json:"request_bytes"`
	ResponseBytes int64     `json:"response_bytes"`
	Error         string    `json:"error,omitempty"`
}

type requestObservation struct {
	mu        sync.Mutex
	store     *history.Store
	start     time.Time
	summary   requestRecord
	up        atomic.Int64
	down      atomic.Int64
	tlsStart  time.Time
	detail    *requestDetail
	upBody    *observedBody
	downBody  *observedBody
	bodyLimit int
}

var requestSequence atomic.Uint64

func (b *Backend) observeHTTP(tag string) context.Context {
	if b.history == nil {
		return b.ctx
	}
	// The locked sing HTTP parser calls this only for parsed, authenticated
	// forward requests, after the CONNECT and upgrade branches.
	begin := func(ctx context.Context, request *http.Request, client string) (context.Context, func(*http.Response), func(int, error)) {
		ctx, obs := b.beginRequest(ctx, request, tag, client)
		return ctx, obs.response, obs.finish
	}
	return context.WithValue(b.ctx, httpObservationKey, begin)
}

func (b *Backend) beginRequest(ctx context.Context, req *http.Request, tag, client string) (context.Context, *requestObservation) {
	start := time.Now()
	obs := &requestObservation{store: b.history, start: start, summary: requestRecord{
		ID: requestSequence.Add(1), Start: start.UTC(), Inbound: tag, Client: history.Text(client, 128),
		Method: history.Text(req.Method, 32), Scheme: history.Text(req.URL.Scheme, 12),
		Host: history.Text(req.URL.Host, 320), Path: requestPath(req.URL), HTTPVersion: req.Proto,
	}}
	if b.historyScope != nil {
		obs.summary.Scope = b.historyScope()
	}
	if req.Body != nil && req.Body != http.NoBody {
		obs.upBody = &observedBody{ReadCloser: req.Body, count: &obs.up}
		req.Body = obs.upBody
	}
	ctx = context.WithValue(ctx, requestHistoryKey{}, obs)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			obs.mu.Lock()
			defer obs.mu.Unlock()
			if obs.summary.TTFBMS == nil {
				elapsed := time.Since(start).Milliseconds()
				obs.summary.TTFBMS = &elapsed
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			obs.mu.Lock()
			obs.summary.Reused = &info.Reused
			obs.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			obs.mu.Lock()
			obs.tlsStart = time.Now()
			obs.mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			obs.mu.Lock()
			if !obs.tlsStart.IsZero() {
				elapsed := time.Since(obs.tlsStart).Milliseconds()
				obs.summary.TLSMS = &elapsed
			}
			obs.mu.Unlock()
		},
	})
	return ctx, obs
}

func requestPath(u *url.URL) string {
	path := history.Text(u.EscapedPath(), 1024)
	if path == "" {
		return "/"
	}
	// Query strings and userinfo are intentionally excluded. Also mask the
	// common path form /<credential-kind>/<value>.
	parts := strings.Split(path, "/")
	for i := 1; i+1 < len(parts); i++ {
		segment, _ := url.PathUnescape(parts[i])
		switch strings.ToLower(segment) {
		case "token", "password", "secret", "api-key", "api_key", "reset", "session":
			parts[i+1] = "[redacted]"
			i++
		}
	}
	return strings.Join(parts, "/")
}

func bindRequestConnection(ctx context.Context, attempt *connectionAttempt) {
	if obs, _ := ctx.Value(requestHistoryKey{}).(*requestObservation); obs != nil {
		obs.mu.Lock()
		obs.summary.ConnectionID = attempt.ID
		obs.summary.Scope = attempt.Scope
		obs.mu.Unlock()
	}
}

func observeRequestLookup(ctx context.Context, lookup LookupFunc) LookupFunc {
	obs, _ := ctx.Value(requestHistoryKey{}).(*requestObservation)
	if obs == nil || lookup == nil {
		return lookup
	}
	return func(ctx context.Context, domain string) ([]netip.Addr, error) {
		start := time.Now()
		addresses, err := lookup(ctx, domain)
		ms := time.Since(start).Milliseconds()
		obs.mu.Lock()
		if obs.summary.DNSMS != nil {
			ms += *obs.summary.DNSMS
		}
		obs.summary.DNSMS = &ms
		obs.mu.Unlock()
		return addresses, err
	}
}

func observeRequestDial(ctx context.Context, ms *int64) {
	if obs, _ := ctx.Value(requestHistoryKey{}).(*requestObservation); obs != nil {
		obs.mu.Lock()
		obs.summary.DialMS = ms
		obs.mu.Unlock()
	}
}

func (obs *requestObservation) response(res *http.Response) {
	obs.mu.Lock()
	obs.summary.StatusCode = res.StatusCode
	obs.summary.StatusSource = "origin"
	obs.summary.UpstreamHTTP = res.Proto
	obs.mu.Unlock()
	if res.Body != nil && res.Body != http.NoBody {
		obs.downBody = &observedBody{ReadCloser: res.Body, count: &obs.down, limit: obs.bodyLimit}
		res.Body = obs.downBody
	}
	if obs.detail != nil {
		obs.detail.Response.Headers = debugHeaders(res.Header)
	}
}

func (obs *requestObservation) finish(proxyStatus int, err error) {
	obs.mu.Lock()
	record := obs.summary
	obs.mu.Unlock()
	if record.StatusCode == 0 && proxyStatus != 0 {
		record.StatusCode, record.StatusSource = proxyStatus, "proxy"
	}
	record.DurationMS = time.Since(obs.start).Milliseconds()
	record.RequestBytes, record.ResponseBytes = obs.up.Load(), obs.down.Load()
	if err != nil {
		record.Error = connectionReason(err, "error")
	}
	if obs.detail != nil {
		record.Detail = true
		if obs.bodyLimit > 0 {
			obs.detail.Request.Body = obs.upBody.preview()
			obs.detail.Response.Body = obs.downBody.preview()
			if obs.detail.Request.Body != nil {
				obs.detail.Request.Body.ContentEncoding = obs.detail.Request.Headers.Get("Content-Encoding")
			}
			if obs.detail.Response.Body != nil {
				obs.detail.Response.Body.ContentEncoding = obs.detail.Response.Headers.Get("Content-Encoding")
			}
		}
		obs.store.RecordFlow(history.Requests, record.Scope, obs.start, record.ConnectionID, record, obs.detail)
		return
	}
	obs.store.RecordFlow(history.Requests, record.Scope, obs.start, record.ConnectionID, record, nil)
}

type observedBody struct {
	io.ReadCloser
	count *atomic.Int64
	limit int
	mu    sync.Mutex
	data  []byte
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.count.Add(int64(n))
	if b.limit > 0 && n > 0 {
		b.mu.Lock()
		b.data = append(b.data, p[:min(n, b.limit-len(b.data))]...)
		b.mu.Unlock()
	}
	return n, err
}

// The summary stays small. Details use the same headers/body-preview shape as
// Mimo CaptureBackend, scoped to an explicitly authorized debug session.
type requestDetail struct {
	Request     debugMessage `json:"request"`
	Response    debugMessage `json:"response"`
	BodyOmitted bool         `json:"body_omitted,omitempty"`
}

type debugMessage struct {
	Headers http.Header  `json:"headers"`
	Body    *bodyPreview `json:"body,omitempty"`
}

type bodyPreview struct {
	Encoding        string `json:"encoding"`
	Data            string `json:"data"`
	Size            int64  `json:"size"`
	Truncated       bool   `json:"truncated"`
	ContentEncoding string `json:"content_encoding,omitempty"`
}

func (obs *requestObservation) enableDetail(header http.Header, limit int, omitted bool) {
	obs.detail = &requestDetail{Request: debugMessage{Headers: debugHeaders(header)}, BodyOmitted: omitted}
	obs.bodyLimit = limit
	if obs.upBody != nil {
		obs.upBody.limit = limit
	}
}

func (b *observedBody) preview() *bodyPreview {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	size := b.count.Load()
	preview := &bodyPreview{Size: size, Truncated: size > int64(len(b.data))}
	if utf8.Valid(b.data) {
		preview.Encoding, preview.Data = "utf8", string(b.data)
	} else {
		preview.Encoding, preview.Data = "base64", base64.StdEncoding.EncodeToString(b.data)
	}
	return preview
}

func debugHeaders(header http.Header) http.Header {
	clean := make(http.Header)
	for _, name := range []string{"Accept", "Accept-Encoding", "Cache-Control", "Content-Type", "Content-Length",
		"Content-Encoding", "Content-Range", "Date", "Server", "Vary"} {
		values := header.Values(name)
		for _, v := range values[:min(2, len(values))] {
			clean.Add(name, history.Text(v, 384))
		}
	}
	return clean
}
