package subscription

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/resource"
)

func fetcher(t *testing.T) *Fetcher {
	t.Helper()
	blobs, err := resource.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Fetcher{Client: HTTPClient(nil), Blobs: blobs}
}
func TestSubscriptionConditionalCacheAndLimits(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("If-None-Match") == `"version1"` {
			if r.Header.Get("If-Modified-Since") == "" {
				t.Error("missing Last-Modified validator")
			}
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"version1"`)
		w.Header().Set("Last-Modified", "Sun, 15 Nov 2026 00:00:00 GMT")
		w.Write([]byte("payload"))
	}))
	defer server.Close()
	f := fetcher(t)
	defer f.Client.CloseIdleConnections()
	b := f.Batch(nil, true)
	data, err := b.Fetch(context.Background(), "root", "subscription", "", server.URL, nil, 3600)
	if err != nil || string(data) != "payload" {
		t.Fatal(err)
	}
	cached := f.Batch(b.Entries, false)
	if _, err := cached.Fetch(context.Background(), "root", "subscription", "", server.URL, nil, 3600); err != nil || calls.Load() != 1 {
		t.Fatal("interval cache ignored", err)
	}
	conditional := f.Batch(b.Entries, true)
	if _, err := conditional.Fetch(context.Background(), "root", "subscription", "", server.URL, nil, 3600); err != nil || calls.Load() != 2 {
		t.Fatal("304", err)
	}
	if conditional.Entries["root"].Hash != b.Entries["root"].Hash {
		t.Fatal("304 changed bytes")
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(304) }))
	defer empty.Close()
	if _, err := f.Batch(nil, true).Fetch(context.Background(), "root", "subscription", "", empty.URL, nil, 30); Code(err) != "cache_missing_304" {
		t.Fatal("304 without cache accepted", err)
	}
	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "16777217")
		w.WriteHeader(200)
	}))
	defer large.Close()
	if _, err := f.Batch(nil, true).Fetch(context.Background(), "root", "subscription", "", large.URL, nil, 30); Code(err) != "body_too_large" {
		t.Fatal("size limit", err)
	}
}
func TestSubscriptionRedirectCredentialsAndProtect(t *testing.T) {
	var protects atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Token") != "" {
			t.Error("redirect forwarded credentials")
		}
		w.Write([]byte("safe"))
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer origin.Close()
	f := fetcher(t)
	f.Client.CloseIdleConnections()
	f.Client = HTTPClient(func(int) error { protects.Add(1); return nil })
	defer f.Client.CloseIdleConnections()
	if _, err := f.Batch(nil, true).Fetch(context.Background(), "root", "subscription", "", origin.URL, http.Header{"Authorization": {"Bearer secret"}, "X-Token": {"private"}}, 30); err != nil || protects.Load() < 2 {
		t.Fatal("protect path", err, protects.Load())
	}
}
func TestSubscriptionTimeoutAndPrivateBlobs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	f := fetcher(t)
	defer f.Client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := f.Batch(nil, true).Fetch(ctx, "root", "subscription", "", server.URL, nil, 30); err == nil {
		t.Fatal("timeout not enforced")
	}
	root := t.TempDir()
	blobs, _ := resource.Open(root)
	hash, err := blobs.Put([]byte("private subscription"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "resources", "sha256", hash)
	info, err := os.Stat(path)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("blob permissions", err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 20)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.Read(hash); err == nil {
		t.Fatal("corrupt blob accepted")
	}
}

func TestSubscriptionChangingIntervalAndBundleBudget(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); w.Write([]byte("payload")) }))
	defer server.Close()
	f := fetcher(t)
	defer f.Client.CloseIdleConnections()
	now := time.Now().UTC()
	f.Now = func() time.Time { return now }
	first := f.Batch(nil, false)
	if _, err := first.Fetch(context.Background(), "root", "subscription", "", server.URL, nil, 3600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	second := f.Batch(first.Entries, false)
	if _, err := second.Fetch(context.Background(), "root", "subscription", "", server.URL, nil, 30); err != nil || count.Load() != 2 {
		t.Fatal("new interval ignored", err, count.Load())
	}
	limit := f.Batch(nil, true)
	limit.Bytes = 32 << 20
	if _, err := limit.Inline("extra", "proxy", "extra", []byte("x")); Code(err) != "bundle_too_large" {
		t.Fatal("bundle limit", err)
	}
}
