// Package subscription fetches complete resource bundles. It never activates
// configuration; ConfigService promotes successful bundles transactionally.
package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/MimoProxy/reka/internal/api"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

type Error struct{ Code string }

func (e *Error) Error() string  { return e.Code }
func failure(code string) error { return &Error{code} }
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "refresh_failed"
}
func ValidURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.Fragment == ""
}
func HTTPClient(protect func(int) error) *http.Client {
	control := func(_, _ string, conn syscall.RawConn) error {
		if protect == nil {
			return nil
		}
		var err error
		if e := conn.Control(func(fd uintptr) { err = protect(int(fd)) }); e != nil {
			return e
		}
		return err
	}
	return HTTPClientWithControl(control, nil)
}

func HTTPClientWithControl(control func(string, string, syscall.RawConn) error, lookup func(context.Context, string) ([]net.IP, error)) *http.Client {
	resolverDialer := &net.Dialer{Timeout: 10 * time.Second, Control: control}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: control, Resolver: &net.Resolver{PreferGo: true, Dial: resolverDialer.DialContext}}
	dial := dialer.DialContext
	if lookup != nil {
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if net.ParseIP(host) != nil {
				return dialer.DialContext(ctx, network, address)
			}
			ips, err := lookup(ctx, host)
			if err != nil {
				return nil, err
			}
			var last error
			for _, ip := range ips {
				c, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return c, nil
				}
				last = err
			}
			if last == nil {
				last = fmt.Errorf("no bootstrap addresses")
			}
			return nil, last
		}
	}
	transport := &http.Transport{Proxy: nil, DialContext: dial, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 64 << 10, MaxIdleConns: 8, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 4, IdleConnTimeout: 30 * time.Second}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return failure("redirect_limit")
		}
		prev := via[len(via)-1].URL
		if prev.Scheme == "https" && req.URL.Scheme != "https" {
			return failure("redirect_downgrade")
		}
		if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
			return failure("redirect_scheme")
		}
		if !strings.EqualFold(req.URL.Scheme+"://"+req.URL.Host, via[0].URL.Scheme+"://"+via[0].URL.Host) {
			req.Header = make(http.Header)
			req.Header.Set("User-Agent", "Reka/dev")
			req.URL.User = nil
		}
		return nil
	}}
}

type Entry struct {
	Usage    *api.SubscriptionUsage `json:"usage,omitempty"`
	Fallback bool                   `json:"fallback,omitempty"`
	Checked  time.Time              `json:"checked,omitempty"`
	Request  string                 `json:"request"`
	Hash     string                 `json:"hash"`
	ETag     string                 `json:"etag,omitempty"`
	Modified string                 `json:"modified,omitempty"`
	Next     time.Time              `json:"next"`
}
type Fetcher struct {
	Client         *http.Client
	Blobs          *resource.Store
	Now            func() time.Time
	ValidateBody   func([]byte) error
	MaxBytes       int
	MaxBundleBytes int
}
type Batch struct {
	f        *Fetcher
	Previous map[string]Entry
	Entries  map[string]Entry
	Locks    []model.ResourceLock
	Bytes    int
	Force    bool
}

func (f *Fetcher) Batch(previous map[string]Entry, force bool) *Batch {
	return &Batch{f: f, Previous: previous, Entries: map[string]Entry{}, Force: force}
}

func RequestDigest(raw string, headers http.Header) string {
	identity, _ := json.Marshal(struct {
		URL     string
		Headers http.Header
	}{raw, headers})
	return resource.Hash(identity)
}

func (b *Batch) Fetch(ctx context.Context, id, kind, name, raw string, headers http.Header, interval int) ([]byte, error) {
	if !ValidURL(raw) {
		return nil, failure("invalid_url")
	}
	limit := resource.MaxSize
	if kind == "subscription" || kind == "proxy" {
		limit = model.MaxDocumentSize
	}
	if b.f.MaxBytes > 0 {
		limit = min(limit, b.f.MaxBytes)
	}
	sizeCode := "body_too_large"
	if b.f.MaxBundleBytes > 0 && b.f.MaxBundleBytes-b.Bytes < limit {
		limit = b.f.MaxBundleBytes - b.Bytes
		sizeCode = "bundle_too_large"
	}
	now := time.Now().UTC()
	if b.f.Now != nil {
		now = b.f.Now()
	}
	request := RequestDigest(raw, headers)
	old := b.Previous[id]
	var cached []byte
	if old.Request == request && old.Hash != "" {
		cached, _ = b.f.Blobs.Read(old.Hash)
		if len(cached) > limit {
			cached = nil
		}
	}
	entry := old
	var data []byte
	expires := old.Next
	if !old.Checked.IsZero() {
		expires = old.Checked.Add(time.Duration(interval) * time.Second)
	}
	if len(cached) > 0 && !b.Force && now.Before(expires) {
		data = cached
		entry.Next = expires
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return nil, failure("invalid_url")
		}
		req.Header = headers.Clone()
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "Reka/dev")
		}
		if len(cached) > 0 {
			if old.ETag != "" {
				req.Header.Set("If-None-Match", old.ETag)
			}
			if old.Modified != "" {
				req.Header.Set("If-Modified-Since", old.Modified)
			}
		}
		response, err := b.f.Client.Do(req)
		if err != nil {
			return nil, failure("request_failed")
		}
		defer response.Body.Close()
		switch response.StatusCode {
		case http.StatusNotModified:
			if len(cached) == 0 {
				return nil, failure("cache_missing_304")
			}
			data = cached
		case http.StatusOK:
			if response.ContentLength > int64(limit) {
				return nil, failure(sizeCode)
			}
			data, err = io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
			if err != nil {
				return nil, failure("body_read_failed")
			}
			if len(data) > limit {
				return nil, failure(sizeCode)
			}
			if len(data) == 0 {
				return nil, failure("empty_body")
			}
			if b.f.ValidateBody != nil && (old.Hash == "" || resource.Hash(data) != old.Hash) {
				if err := b.f.ValidateBody(data); err != nil {
					return nil, err
				}
			}
		default:
			return nil, failure(fmt.Sprintf("http_status_%d", response.StatusCode))
		}
		entry = Entry{Checked: now, Request: request, ETag: response.Header.Get("ETag"), Modified: response.Header.Get("Last-Modified"), Next: now.Add(time.Duration(interval) * time.Second)}
		if id == "root" && kind == "subscription" {
			entry.Usage = responseUsage(response.Header.Values("Subscription-Userinfo"), old.Usage, response.StatusCode == http.StatusNotModified, now)
		}
		if response.StatusCode == http.StatusNotModified {
			if entry.ETag == "" {
				entry.ETag = old.ETag
			}
			if entry.Modified == "" {
				entry.Modified = old.Modified
			}
		}
	}
	return b.record(id, kind, name, data, entry)
}
func (b *Batch) Inline(id, kind, name string, data []byte) ([]byte, error) {
	return b.record(id, kind, name, data, Entry{Request: resource.Hash(data)})
}
func (b *Batch) record(id, kind, name string, data []byte, entry Entry) ([]byte, error) {
	limit := b.f.MaxBundleBytes
	if limit <= 0 {
		limit = 384 << 20
	}
	b.Bytes += len(data)
	if b.Bytes > limit {
		return nil, failure("bundle_too_large")
	}
	hash, err := b.f.Blobs.Put(data)
	if err != nil {
		return nil, failure("resource_store_failed")
	}
	entry.Hash = hash
	b.Entries[id] = entry
	b.Locks = append(b.Locks, model.ResourceLock{ID: id, Kind: kind, Name: name, Hash: hash, Request: entry.Request})
	return data, nil
}

// FetchFallback materializes the explicitly declared startup payload only on
// an initial network/status failure. A previously committed resource or an
// invalid response never silently becomes the fallback. Its request identity
// is distinct from HTTP, so the next refresh attempts the real URL again.
func (b *Batch) FetchFallback(ctx context.Context, id, kind, name, raw string, headers http.Header, interval int, fallback []byte) ([]byte, error) {
	data, err := b.Fetch(ctx, id, kind, name, raw, headers, interval)
	if err == nil || len(fallback) == 0 || ctx.Err() != nil || b.Previous[id].Hash != "" {
		return data, err
	}
	code := Code(err)
	if code != "request_failed" && !strings.HasPrefix(code, "http_status_") {
		return nil, err
	}
	return b.record(id, kind, name, fallback, Entry{Fallback: true, Request: resource.Hash(append([]byte("declared-startup-fallback:"), fallback...)), Next: time.Now().UTC().Add(time.Duration(interval) * time.Second)})
}
