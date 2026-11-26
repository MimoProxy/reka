package generation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestOoklaHostValidation(t *testing.T) {
	for _, host := range []string{"singnet.example.com:8080", "test.example.com", "192.0.2.1:443", "[2001:db8::1]:8080"} {
		if !validOoklaHost(host) {
			t.Errorf("rejected valid host %q", host)
		}
	}
	for _, host := range []string{
		"", "https://example.com:8080", "example.com/path", "example.com?path", "example.com#path",
		"user@example.com:8080", "example.com\\extra", "example%2ecom", "example.com\t", "example.com\u00a0",
		"example.com:", "example.com:0", "example.com:65536", "example.com:https", ":8080",
		"2001:db8::1", "[example.com]:8080", "[fe80::1%25en0]:8080", "example..com",
		strings.Repeat("a", 64) + ".example.com", strings.Repeat("a.", 131) + "com",
	} {
		if validOoklaHost(host) {
			t.Errorf("accepted invalid host %q", host)
		}
	}
}

func TestFetchOoklaServers(t *testing.T) {
	const list = `[{"host":"node.example.com:8080","name":"Singapore","sponsor":"Provider","country":"Singapore","id":"4321"}]`
	for _, tc := range []struct {
		name   string
		body   string
		status int
		err    string
	}{
		{name: "list", body: list, status: http.StatusOK},
		{name: "invalid list", body: "{}", status: http.StatusOK, err: "decode Ookla server list"},
		{name: "size limit", body: list + strings.Repeat(" ", ooklaServerListLimit), status: http.StatusOK, err: "Ookla server list exceeds size limit"},
		{name: "rate limited", status: http.StatusTooManyRequests, err: "Ookla returned HTTP 429"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.TLS == nil ||
					r.URL.RequestURI() != "/api/js/servers?engine=js&https_functional=true&limit=10" {
					t.Errorf("unexpected list request %s %s", r.Method, r.URL)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			servers, err := fetchOoklaServers(t.Context(), server.Client(), ooklaServerListURL)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("fetch error = %v, want %q", err, tc.err)
				}
				return
			}
			want := ooklaServer{Host: "node.example.com:8080", Name: "Singapore", Sponsor: "Provider"}
			if err != nil || len(servers) != 1 || servers[0] != want {
				t.Fatalf("fetch returned %+v, %v", servers, err)
			}
		})
	}
}

func TestOoklaChoosesFastestOfFirstFive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const fast = "fast.example.com:8080"
		const list = `[
			{"host":"user@ignored.example.com"},
			{"host":"slow.example.com"},
			{"host":"error.example.com"},
			{"host":"invalid.example.com:bad"},
			{"host":"` + fast + `","name":"Singapore","sponsor":"Fast ISP"},
			{"host":"outside.example.com"}
		]`
		var probes atomic.Int32
		probesStarted := make(chan struct{})
		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/js/servers":
				_, _ = io.WriteString(w, list)
			case "/hello":
				if r.Method != http.MethodGet || r.TLS == nil {
					t.Errorf("unexpected probe request %s %s", r.Method, r.URL)
				}
				if probes.Add(1) == 3 {
					close(probesStarted)
				}
				select {
				case <-probesStarted:
				case <-r.Context().Done():
					return
				}
				switch r.Host {
				case fast:
					time.Sleep(5 * time.Millisecond)
					_, _ = io.WriteString(w, "hello")
				case "slow.example.com":
					time.Sleep(80 * time.Millisecond)
					_, _ = io.WriteString(w, "hello")
				case "error.example.com":
					w.WriteHeader(http.StatusTooManyRequests)
				default:
					t.Errorf("unexpected probe for %q", r.Host)
				}
			default:
				t.Errorf("unexpected request path %s", r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}
		}))

		endpoints, err := resolveOoklaEndpoints(t.Context(), server.Client(), ooklaServerListURL)
		if err != nil {
			t.Fatal(err)
		}
		if probes.Load() != 3 || endpoints.latency != "https://"+fast+"/hello" || endpoints.server != "Fast ISP · Singapore" {
			t.Fatalf("selection = %q (%q) after %d probes", endpoints.latency, endpoints.server, probes.Load())
		}
		urls := make(chan string, 24)
		for range cap(urls) / 2 {
			go func() {
				urls <- endpoints.download()
				urls <- endpoints.upload()
			}()
		}
		seen := make(map[string]bool)
		for range cap(urls) {
			endpoint, err := url.Parse(<-urls)
			if err != nil {
				t.Fatal(err)
			}
			query := endpoint.Query()
			if endpoint.Scheme != "https" || endpoint.Host != fast ||
				(endpoint.Path == "/download" && query.Get("size") != "25000000") ||
				(endpoint.Path == "/upload" && query.Has("size")) ||
				(endpoint.Path != "/download" && endpoint.Path != "/upload") {
				t.Errorf("invalid transfer endpoint %q", endpoint)
			}
			nonce := query.Get("nocache")
			if nonce == "" || seen[nonce] {
				t.Errorf("empty or duplicate nonce %q", nonce)
			}
			seen[nonce] = true
		}
	})
}

func TestOoklaServerSelectionFailsWhenNoCandidateResponds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/hello" {
				<-r.Context().Done()
				return
			}
			_, _ = io.WriteString(w, `[{"host":"timed-out.example.com:8080"}]`)
		}))
		start := time.Now()
		_, err := resolveOoklaEndpoints(t.Context(), server.Client(), ooklaServerListURL)
		if err == nil || !strings.Contains(err.Error(), "no Ookla server responded") ||
			!errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrOoklaUnreachable) ||
			time.Since(start) != ooklaProbeLimit {
			t.Fatalf("selection error = %v after %s", err, time.Since(start))
		}
	})
}

func TestOoklaProbeAnsweredAtDeadlineFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &http.Client{Transport: speedTestTransport(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/hello" {
				// The transport may still hand back a response that raced the deadline.
				<-request.Context().Done()
				return speedTestResponse(http.StatusOK, http.NoBody), nil
			}
			return speedTestResponse(http.StatusOK, strings.NewReader(`[{"host":"late.example.com:8080"}]`)), nil
		})}
		start := time.Now()
		_, err := resolveOoklaEndpoints(t.Context(), client, ooklaServerListURL)
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrOoklaUnreachable) ||
			time.Since(start) != ooklaProbeLimit {
			t.Fatalf("selection error = %v after %s", err, time.Since(start))
		}
	})
}

func TestOoklaServerListFailureIsUnreachable(t *testing.T) {
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A proxy that blocks speed test sites closes the connection without a response.
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("response writer cannot hijack")
			return
		}
		conn, _, err := hijacker.Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	_, err := resolveOoklaEndpoints(t.Context(), server.Client(), ooklaServerListURL)
	if !errors.Is(err, ErrOoklaUnreachable) {
		t.Fatalf("list failure = %v, want unreachable", err)
	}
}

func TestOoklaServerSelectionReturnsCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/hello" {
				cancel()
				<-r.Context().Done()
				return
			}
			_, _ = io.WriteString(w, `[{"host":"test.example.com:8080"}]`)
		}))
		start := time.Now()
		_, err := resolveOoklaEndpoints(ctx, server.Client(), ooklaServerListURL)
		if err != context.Canceled || time.Since(start) != 0 {
			t.Fatalf("selection error = %v after %s", err, time.Since(start))
		}
	})
}
