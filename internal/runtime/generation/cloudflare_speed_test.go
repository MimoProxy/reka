package generation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type speedTestTransport func(*http.Request) (*http.Response, error)

func (f speedTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type speedTestZeroes struct{}

func (speedTestZeroes) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

type speedTestStalledDownload struct {
	io.Reader
	ctx context.Context
}

func (r speedTestStalledDownload) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		<-r.ctx.Done()
		return n, r.ctx.Err()
	}
	return n, err
}

func speedTestResponse(status int, body io.Reader) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(body)}
}

func speedTestSettings() speedTransferSettings {
	return speedTransferSettings{
		duration: 200 * time.Millisecond, warmup: 25 * time.Millisecond,
		firstByteWarmup: 15 * time.Millisecond, minimumSteady: 200 * time.Millisecond,
		interval: 25 * time.Millisecond, window: 100 * time.Millisecond,
	}
}

func TestSpeedTransferUsesIndependentHTTP1Connections(t *testing.T) {
	type connectionIDKey struct{}
	var nextID atomic.Uint64
	var mu sync.Mutex
	firstWave := make(map[uint64]struct{})
	allConnected := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
			t.Errorf("request used %s, want HTTP/1.1", r.Proto)
		}
		id := r.Context().Value(connectionIDKey{}).(uint64)
		mu.Lock()
		firstWave[id] = struct{}{}
		if len(firstWave) == speedStreams {
			select {
			case <-allConnected:
			default:
				close(allConnected)
			}
		}
		mu.Unlock()

		select {
		case <-r.Context().Done():
			return
		case <-allConnected:
		}

		// Keep all six responses in flight through the phase deadline.
		w.Header().Set("Content-Length", "25000000")
		flush := http.NewResponseController(w)
		chunk := make([]byte, 8192)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if err := flush.Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	})

	dialer := &net.Dialer{}
	dial := dialer.DialContext
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	var server *httptest.Server
	if err == nil {
		server = &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
		t.Cleanup(server.Close)
	} else if errors.Is(err, os.ErrPermission) {
		t.Logf("using in-memory TLS because loopback bind failed: %v", err)
		server = httptest.NewTestServer(t, handler)
	} else {
		t.Fatal(err)
	}
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, connectionIDKey{}, nextID.Add(1))
	}

	var endpoint string
	if listener != nil {
		server.StartTLS()
		endpoint = server.URL
	} else {
		transport := server.Client().Transport.(*http.Transport)
		// Use the raw connection so the production transport still performs
		// the TLS handshake and chooses its own ALPN protocols.
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := transport.DialTLSContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return conn.(*tls.Conn).NetConn(), nil
		}
		endpoint = "https://" + strings.TrimPrefix(server.URL, "http://")
	}
	client := newSpeedClient(t.Context(), dial)
	client.Transport.(*http.Transport).TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	t.Cleanup(client.CloseIdleConnections)

	settings := speedTestSettings()
	settings.duration = 400 * time.Millisecond
	rate, err := runSpeedTransfer(t.Context(), client, SpeedSourceCloudflare, http.MethodGet,
		func() string { return endpoint }, settings, func(CloudflareSpeedPoint) {})
	if err != nil || rate <= 0 {
		t.Fatalf("partial downloads returned %v Mbps, error %v", rate, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(firstWave) != speedStreams {
		t.Fatalf("used %d distinct connections, want %d", len(firstWave), speedStreams)
	}
}

func TestSpeedReadingSourceAndRepeatedTransfers(t *testing.T) {
	const (
		listURL     = "https://speed.example/servers"
		ooklaPrefix = "https://ookla.example:8080"
	)
	for _, scenario := range []struct {
		name, server    string
		source, want    SpeedSource
		latencyRequests uint64
	}{
		{name: "default", want: SpeedSourceCloudflare, latencyRequests: 6},
		{name: "Cloudflare", source: SpeedSourceCloudflare, want: SpeedSourceCloudflare, latencyRequests: 6},
		{name: "Ookla", source: SpeedSourceOokla, want: SpeedSourceOokla, server: "Test ISP · Singapore", latencyRequests: 7},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var latencyRequests, downloads, uploads atomic.Uint64
			isOokla := scenario.want == SpeedSourceOokla
			client := &http.Client{Transport: speedTestTransport(func(r *http.Request) (*http.Response, error) {
				rawURL := r.URL.String()
				switch {
				case isOokla && rawURL == listURL:
					if r.Method != http.MethodGet {
						t.Errorf("server list used %s, want GET", r.Method)
					}
					return speedTestResponse(http.StatusOK, strings.NewReader(`[{"host":"ookla.example:8080","sponsor":"Test ISP","name":"Singapore","id":"1"}]`)), nil
				case !isOokla && rawURL == cloudflareLatencyURL, isOokla && rawURL == ooklaPrefix+"/hello":
					latencyRequests.Add(1)
					if r.Method != http.MethodGet {
						t.Errorf("latency used %s, want GET", r.Method)
					}
					return speedTestResponse(http.StatusOK, strings.NewReader("hello")), nil
				case !isOokla && rawURL == cloudflareDownURL, isOokla && strings.HasPrefix(rawURL, ooklaPrefix+"/download?"):
					if r.Method != http.MethodGet || r.Header.Get("Accept-Encoding") != "identity" {
						t.Errorf("unexpected download request: %s %v", r.Method, r.Header)
					}
					if isOokla && r.URL.Query().Get("size") != "25000000" {
						t.Errorf("unexpected Ookla download size: %s", r.URL.RawQuery)
					}
					if downloads.Add(1) <= speedStreams {
						return speedTestResponse(http.StatusOK, io.LimitReader(speedTestZeroes{}, speedDownloadSize)), nil
					}
					body := speedTestStalledDownload{io.LimitReader(speedTestZeroes{}, 8192), r.Context()}
					return speedTestResponse(http.StatusOK, body), nil
				case !isOokla && rawURL == cloudflareUpURL, isOokla && strings.HasPrefix(rawURL, ooklaPrefix+"/upload?"):
					defer r.Body.Close()
					if r.Method != http.MethodPost || r.ContentLength != speedUploadSize ||
						r.Header.Get("Content-Type") != "application/octet-stream" {
						t.Errorf("unexpected upload request: %s, %d, %v", r.Method, r.ContentLength, r.Header)
					}
					if uploads.Add(1) <= speedStreams {
						n, err := io.Copy(io.Discard, r.Body)
						if err != nil || n != speedUploadSize {
							return nil, errors.New("incorrect upload body length")
						}
						return speedTestResponse(http.StatusOK, strings.NewReader("ok")), nil
					}
					if _, err := io.CopyN(io.Discard, r.Body, 8192); err != nil {
						return nil, err
					}
					<-r.Context().Done()
					return nil, r.Context().Err()
				default:
					return nil, errors.New("unexpected speed test endpoint")
				}
			})}

			settings := speedTestSettings()
			var first, final CloudflareSpeedReading
			start := time.Now()
			err := measureSpeed(t.Context(), client, "relay", scenario.source, listURL, settings, func(reading CloudflareSpeedReading) {
				if first.Phase == "" {
					first = reading
				}
				final = reading
			})
			if err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(start); elapsed < 2*settings.duration {
				t.Fatalf("finished after %s, want two full %s phases", elapsed, settings.duration)
			}
			if samples := latencyRequests.Load(); samples != scenario.latencyRequests {
				t.Fatalf("got %d latency requests, want %d", samples, scenario.latencyRequests)
			}
			if downloads.Load() <= speedStreams || uploads.Load() <= speedStreams {
				t.Fatalf("streams did not repeat requests: %d downloads, %d uploads", downloads.Load(), uploads.Load())
			}
			if first.Phase != "latency" || first.Source != string(scenario.want) || first.Server != "" {
				t.Fatalf("unexpected initial reading: %+v", first)
			}
			if final.Resolved != "relay" || final.Phase != "upload" || final.LatencyMS == nil || final.JitterMS == nil ||
				final.DownloadMbps == nil || *final.DownloadMbps <= 0 || final.UploadMbps == nil || *final.UploadMbps <= 0 ||
				final.Source != string(scenario.want) || final.Server != scenario.server {
				t.Fatalf("incomplete final reading: %+v", final)
			}
			for _, points := range [][]CloudflareSpeedPoint{final.Downloads, final.Uploads} {
				if len(points) != int(settings.duration/settings.interval)+1 || points[0] != (CloudflareSpeedPoint{}) {
					t.Fatalf("unexpected speed curve: %+v", points)
				}
				for i, point := range points {
					if want := (time.Duration(i) * settings.interval).Seconds(); point.Seconds != want {
						t.Errorf("point %d timestamp = %v, want %v", i, point.Seconds, want)
					}
				}
			}
			data, err := json.Marshal(final)
			if err != nil {
				t.Fatal(err)
			}
			var reading map[string]json.RawMessage
			if err := json.Unmarshal(data, &reading); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"phase", "resolved", "source", "latencyMs", "jitterMs", "downloadMbps", "uploadMbps", "downloads", "uploads"} {
				if _, ok := reading[key]; !ok {
					t.Errorf("missing JSON key %q in %s", key, data)
				}
			}
			if _, ok := reading["server"]; ok != (scenario.server != "") {
				t.Errorf("unexpected server key in %s", data)
			}
		})
	}
}

func TestSpeedReadingRejectsUnknownSource(t *testing.T) {
	client := &http.Client{Transport: speedTestTransport(func(r *http.Request) (*http.Response, error) {
		t.Error("unknown source made a request")
		return nil, errors.New("unexpected request")
	})}
	err := measureSpeed(t.Context(), client, "relay", "unknown", "", speedTestSettings(), func(CloudflareSpeedReading) {})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("got error %v for an unknown source", err)
	}
}

func TestSpeedLatencyDrainsAtMostFourKiB(t *testing.T) {
	const payloadSize = 64 << 10
	body := &io.LimitedReader{R: speedTestZeroes{}, N: payloadSize}
	client := &http.Client{Transport: speedTestTransport(func(*http.Request) (*http.Response, error) {
		return speedTestResponse(http.StatusOK, body), nil
	})}
	latency, err := measureSpeedLatency(t.Context(), client, cloudflareLatencyURL, SpeedSourceCloudflare)
	if err != nil || latency < 0 || payloadSize-body.N != 4<<10 {
		t.Fatalf("latency read %d bytes, got %v ms with error %v", payloadSize-body.N, latency, err)
	}
}

func TestSpeedTransferWarmup(t *testing.T) {
	settings := speedTransferSettings{duration: 10 * time.Second, warmup: 2 * time.Second,
		firstByteWarmup: time.Second, minimumSteady: 3 * time.Second}
	for _, scenario := range []struct {
		name           string
		firstByte, end time.Duration
		total, warm    int64
		want           float64
	}{
		{name: "minimum warmup", firstByte: 250 * time.Millisecond, end: 2 * time.Second, total: 17_000_000, warm: 1_000_000, want: 16},
		{name: "late first byte", firstByte: 2500 * time.Millisecond, end: 3500 * time.Millisecond, total: 17_500_000, warm: 1_250_000, want: 20},
		{name: "minimum steady window", firstByte: 6 * time.Second, end: 7 * time.Second, total: 10_000_000, warm: 1_000_000, want: 24},
		{name: "short window fallback", firstByte: 6250 * time.Millisecond, end: 6250 * time.Millisecond, total: 7_500_000, warm: 1_000_000, want: 16},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if end := speedWarmupEnd(scenario.firstByte, settings); end != scenario.end {
				t.Errorf("warmup ended at %s, want %s", end, scenario.end)
			}
			rate := speedTransferRate(scenario.total, scenario.warm, scenario.firstByte, settings)
			if math.Abs(rate-scenario.want) > 1e-9 {
				t.Errorf("got %v Mbps, want %v Mbps", rate, scenario.want)
			}
		})
	}
}

func TestSpeedTransferCurveUsesSlidingWindow(t *testing.T) {
	settings := speedTransferSettings{duration: 2 * time.Second, interval: 250 * time.Millisecond, window: time.Second}
	meter := newSpeedMeter(time.Now(), settings)
	copy(meter.intervalBytes, []int64{1000, 2000, 3000, 4000, 5000})
	for _, scenario := range []struct {
		elapsed time.Duration
		want    float64
	}{
		{elapsed: 250 * time.Millisecond, want: 0.032},
		{elapsed: time.Second, want: 0.080},
		{elapsed: 1250 * time.Millisecond, want: 0.112},
	} {
		point := meter.point(scenario.elapsed)
		if point.Seconds != scenario.elapsed.Seconds() || math.Abs(point.Mbps-scenario.want) > 1e-9 {
			t.Errorf("at %s got %+v, want %v Mbps", scenario.elapsed, point, scenario.want)
		}
	}
}

func TestSpeedTransferMeterStopsAtDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		settings := speedTestSettings()
		meter := newSpeedMeter(time.Now(), settings)
		time.Sleep(settings.duration - time.Nanosecond)
		meter.record(1000)
		time.Sleep(time.Nanosecond)
		meter.record(2000)
		point := meter.point(settings.duration)
		if want := 1000 * 8 / 1_000_000.0 / settings.window.Seconds(); math.Abs(point.Mbps-want) > 1e-9 {
			t.Fatalf("deadline point = %+v, want %v Mbps", point, want)
		}
	})
}

func TestSpeedUploadBodiesRepeatSharedPayload(t *testing.T) {
	payload := speedUploadPayload()
	other := speedUploadPayload()
	if len(payload) == 0 || len(payload) >= speedUploadSize || len(payload) != len(other) || &payload[0] != &other[0] {
		t.Fatal("upload payload must be one shared buffer smaller than the request")
	}
	body := newSpeedUploadBody(payload)
	var first, repeated, independent [128]byte
	if _, err := io.ReadFull(body, first[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(io.Discard, body, int64(len(payload)-len(first))); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(body, repeated[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(newSpeedUploadBody(other), independent[:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first[:], repeated[:]) || !bytes.Equal(first[:], independent[:]) {
		t.Fatal("upload reader did not restart at the start of the shared payload")
	}
}

func TestSpeedTransferCountsIncompleteUpload(t *testing.T) {
	const partialBytes = 32 << 10
	var started atomic.Uint64
	client := &http.Client{Transport: speedTestTransport(func(r *http.Request) (*http.Response, error) {
		defer r.Body.Close()
		if _, err := io.CopyN(io.Discard, r.Body, partialBytes); err != nil {
			return nil, err
		}
		started.Add(1)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	settings := speedTestSettings()
	rate, err := runSpeedTransfer(t.Context(), client, SpeedSourceCloudflare, http.MethodPost,
		func() string { return cloudflareUpURL }, settings, func(CloudflareSpeedPoint) {})
	minimumRate := float64(speedStreams*partialBytes) * 8 / 1_000_000 / settings.duration.Seconds()
	if err != nil || started.Load() != speedStreams || rate < minimumRate {
		t.Fatalf("incomplete uploads returned %v Mbps, %d streams, error %v", rate, started.Load(), err)
	}
}

func TestSpeedTransferPartialFailureKeepsOtherStreams(t *testing.T) {
	var requests atomic.Uint64
	client := &http.Client{Transport: speedTestTransport(func(r *http.Request) (*http.Response, error) {
		attempt := requests.Add(1)
		if attempt <= speedStreams/2 {
			return speedTestResponse(http.StatusTooManyRequests, strings.NewReader("")), nil
		}
		if attempt <= speedStreams {
			return speedTestResponse(http.StatusOK, io.LimitReader(speedTestZeroes{}, speedDownloadSize)), nil
		}
		body := speedTestStalledDownload{io.LimitReader(speedTestZeroes{}, 8192), r.Context()}
		return speedTestResponse(http.StatusOK, body), nil
	})}
	rate, err := runSpeedTransfer(t.Context(), client, SpeedSourceCloudflare, http.MethodGet,
		func() string { return cloudflareDownURL }, speedTestSettings(), func(CloudflareSpeedPoint) {})
	if err != nil || rate <= 0 || requests.Load() <= speedStreams {
		t.Fatalf("partial failure returned %v Mbps, %d requests, error %v", rate, requests.Load(), err)
	}
}

func TestSpeedTransferAllStreamsFail(t *testing.T) {
	for _, scenario := range []struct {
		source SpeedSource
		want   string
	}{
		{source: SpeedSourceCloudflare, want: "Cloudflare returned HTTP 429"},
		{source: SpeedSourceOokla, want: "Ookla returned HTTP 429"},
	} {
		t.Run(string(scenario.source), func(t *testing.T) {
			var requests atomic.Uint64
			client := &http.Client{Transport: speedTestTransport(func(r *http.Request) (*http.Response, error) {
				requests.Add(1)
				return speedTestResponse(http.StatusTooManyRequests, strings.NewReader("")), nil
			})}
			rate, err := runSpeedTransfer(t.Context(), client, scenario.source, http.MethodGet,
				func() string { return cloudflareDownURL }, speedTestSettings(), func(CloudflareSpeedPoint) {})
			if err == nil || err.Error() != scenario.want || rate != 0 || requests.Load() != speedStreams {
				t.Fatalf("total failure returned %v Mbps, %d requests, error %v", rate, requests.Load(), err)
			}
		})
	}
}

func TestSpeedCancellationSkipsUpload(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var uploads atomic.Uint64
	client := &http.Client{Transport: speedTestTransport(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case cloudflareDownURL:
			cancel()
			return nil, request.Context().Err()
		case cloudflareUpURL:
			uploads.Add(1)
		}
		return speedTestResponse(http.StatusOK, strings.NewReader("")), nil
	})}
	settings := speedTestSettings()
	settings.duration = time.Second
	start := time.Now()
	err := measureSpeed(ctx, client, "relay", SpeedSourceCloudflare, "", settings, func(CloudflareSpeedReading) {})
	if !errors.Is(err, context.Canceled) || uploads.Load() != 0 || time.Since(start) >= settings.duration {
		t.Fatalf("canceled test returned %v after %s with %d uploads", err, time.Since(start), uploads.Load())
	}
}

func TestSpeedDialUsesRequestDeadlineAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialed := make(chan time.Time, 1)
		dialResult := make(chan error, 1)
		requestResult := make(chan error, 1)
		client := newSpeedClient(t.Context(), func(ctx context.Context, _, _ string) (net.Conn, error) {
			deadline, _ := ctx.Deadline()
			dialed <- deadline
			<-ctx.Done()
			dialResult <- ctx.Err()
			return nil, ctx.Err()
		})
		defer client.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		req, err := newSpeedRequest(ctx, http.MethodGet, cloudflareDownURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			_, err := client.Do(req)
			requestResult <- err
		}()
		if got, want := <-dialed, time.Now().Add(time.Second); !got.Equal(want) {
			t.Errorf("dial deadline = %s, want %s", got, want)
		}
		start := time.Now()
		cancel()
		if err := <-dialResult; !errors.Is(err, context.Canceled) || time.Since(start) != 0 {
			t.Errorf("dial returned %v after %s", err, time.Since(start))
		}
		if err := <-requestResult; !errors.Is(err, context.Canceled) {
			t.Errorf("request returned %v, want cancellation", err)
		}
	})
}
