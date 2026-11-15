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
			host, port, e := net.SplitHostPort(address)
			if e != nil {
				return nil, e
			}
			if net.ParseIP(host) != nil {
				return dialer.DialContext(ctx, network, address)
			}
			ips, e := lookup(ctx, host)
			if e != nil {
				return nil, e
			}
			var last error
			for _, ip := range ips {
				c, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if e == nil {
					return c, nil
				}
				last = e
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
	Checked  time.Time `json:"checked,omitempty"`
	Request  string    `json:"request"`
	Hash     string    `json:"hash"`
	ETag     string    `json:"etag,omitempty"`
	Modified string    `json:"modified,omitempty"`
	Next     time.Time `json:"next"`
}
type Fetcher struct {
	Client *http.Client
	Blobs  *resource.Store
	Now    func() time.Time
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
func (b *Batch) Fetch(ctx context.Context, id, kind, name, raw string, headers http.Header, interval int) ([]byte, error) {
	if !ValidURL(raw) {
		return nil, failure("invalid_url")
	}
	now := time.Now().UTC()
	if b.f.Now != nil {
		now = b.f.Now()
	}
	identity, _ := json.Marshal(struct {
		URL     string
		Headers http.Header
	}{raw, headers})
	request := resource.Hash(identity)
	old := b.Previous[id]
	var cached []byte
	if old.Request == request && old.Hash != "" {
		cached, _ = b.f.Blobs.Read(old.Hash)
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
			if response.ContentLength > resource.MaxSize {
				return nil, failure("body_too_large")
			}
			data, err = io.ReadAll(io.LimitReader(response.Body, resource.MaxSize+1))
			if err != nil {
				return nil, failure("body_read_failed")
			}
			if len(data) > resource.MaxSize {
				return nil, failure("body_too_large")
			}
			if len(data) == 0 {
				return nil, failure("empty_body")
			}
		default:
			return nil, failure(fmt.Sprintf("http_status_%d", response.StatusCode))
		}
		entry = Entry{Checked: now, Request: request, ETag: response.Header.Get("ETag"), Modified: response.Header.Get("Last-Modified"), Next: now.Add(time.Duration(interval) * time.Second)}
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
	b.Bytes += len(data)
	if b.Bytes > 32<<20 {
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
