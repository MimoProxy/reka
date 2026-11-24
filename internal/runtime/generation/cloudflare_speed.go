package generation

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/model"
)

const (
	cloudflareLatencyURL = "https://speed.cloudflare.com/__down?bytes=0"
	cloudflareDownURL    = "https://speed.cloudflare.com/__down?bytes=25000000"
	cloudflareUpURL      = "https://speed.cloudflare.com/__up"
	speedConnectLimit    = 5 * time.Second // Bound proxy handshakes, TLS, and latency samples.
)

// SpeedSource identifies the service used for latency and throughput tests.
type SpeedSource string

const (
	SpeedSourceCloudflare SpeedSource = "cloudflare"
	SpeedSourceOokla      SpeedSource = "ookla"
)

type CloudflareSpeedPoint struct {
	Seconds float64 `json:"seconds"`
	Mbps    float64 `json:"megabitsPerSecond"`
}

type CloudflareSpeedReading struct {
	Phase        string                 `json:"phase"`
	Resolved     string                 `json:"resolved,omitempty"`
	Source       string                 `json:"source,omitempty"`
	Server       string                 `json:"server,omitempty"`
	LatencyMS    *float64               `json:"latencyMs,omitempty"`
	JitterMS     *float64               `json:"jitterMs,omitempty"`
	DownloadMbps *float64               `json:"downloadMbps,omitempty"`
	UploadMbps   *float64               `json:"uploadMbps,omitempty"`
	Downloads    []CloudflareSpeedPoint `json:"downloads,omitempty"`
	Uploads      []CloudflareSpeedPoint `json:"uploads,omitempty"`
}

// RunCloudflareSpeed runs a Cloudflare speed test on the requested outbound.
func (e *Engine) RunCloudflareSpeed(ctx context.Context, member string, update func(CloudflareSpeedReading)) error {
	return e.RunSpeedTest(ctx, member, SpeedSourceCloudflare, update)
}

// RunSpeedTest pins one resolved leaf and its DNS and dialer dependencies for
// the complete benchmark, including server discovery. The default is Cloudflare.
func (e *Engine) RunSpeedTest(ctx context.Context, member string, source SpeedSource, update func(CloudflareSpeedReading)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	source, err := normalizeSpeedSource(source)
	if err != nil {
		return err
	}
	probeURL := cloudflareLatencyURL
	if source == SpeedSourceOokla {
		probeURL = ooklaServerListURL
	}
	release, err := e.takeProbeSlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	for ctx.Err() == nil {
		snapshot, g := e.current()
		if g.eff == nil || g.router == nil {
			return errors.New("speed test requires an active configuration")
		}
		resolved, err := g.resolveProbe(member, probeURL)
		out := snapshot.Resources[resolved]
		if member == model.OutboundDirect {
			// A profile's direct outbound can have its own detour. The direct
			// diagnostic uses the physical path even in that configuration.
			if configured, _ := g.eff.Outbound(model.OutboundDirect); !configured.Builtin {
				out, err = e.backend.NewOutbound(model.OutboundDirect, sagernet.DirectSpec{})
				if err == nil {
					defer out.Close()
				}
			}
		}
		if err != nil || out == nil {
			return errors.New("speed test outbound unavailable or rejected")
		}
		pins, err := pinProbeOutbounds(g, snapshot, out)
		if err != nil {
			if e.rt.Current() == snapshot {
				return errors.New("speed test runtime stopped")
			}
			continue
		}
		defer closeSniffPins(pins)
		selected := sniffSnapshotContext(sagernet.WithPinnedOutbounds(ctx, pins), snapshot)
		return MeasureSpeed(g.probeLookupContext(selected, out), resolved, pins[out].Dial, source, update)
	}
	return ctx.Err()
}

// MeasureCloudflareSpeed runs a Cloudflare speed test through dial.
func MeasureCloudflareSpeed(
	ctx context.Context,
	resolved string,
	dial func(context.Context, string, string) (net.Conn, error),
	update func(CloudflareSpeedReading),
) error {
	return MeasureSpeed(ctx, resolved, dial, SpeedSourceCloudflare, update)
}

// MeasureSpeed uses dial for all requests. An empty source selects Cloudflare.
// Readings are delivered serially on the caller's goroutine.
func MeasureSpeed(
	ctx context.Context,
	resolved string,
	dial func(context.Context, string, string) (net.Conn, error),
	source SpeedSource,
	update func(CloudflareSpeedReading),
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := newSpeedClient(ctx, dial)
	defer client.CloseIdleConnections()
	return measureSpeed(ctx, client, resolved, source, ooklaServerListURL, defaultSpeedTransferSettings(), update)
}

type speedDialContextKey struct{}

func newSpeedRequest(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	return http.NewRequestWithContext(context.WithValue(ctx, speedDialContextKey{}, ctx), method, rawURL, body)
}

func newSpeedClient(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
	transport := &http.Transport{
		DialContext: func(dialContext context.Context, network, address string) (net.Conn, error) {
			// net/http allows a dial to outlive its initiating request. Bind
			// proxy handshakes to the request's cancellation and deadline.
			requestContext, ok := dialContext.Value(speedDialContextKey{}).(context.Context)
			if !ok {
				requestContext = ctx
			}
			if err := requestContext.Err(); err != nil {
				return nil, err
			}
			deadline := time.Now().Add(speedConnectLimit)
			if requestDeadline, ok := requestContext.Deadline(); ok && requestDeadline.Before(deadline) {
				deadline = requestDeadline
			}
			dialContext, cancel := context.WithDeadline(dialContext, deadline)
			defer cancel()
			stop := context.AfterFunc(requestContext, cancel)
			defer stop()
			return dial(dialContext, network, address)
		},
		// A concurrent HTTP/1.1 request occupies its own TCP connection.
		TLSNextProto:       map[string]func(string, *tls.Conn) http.RoundTripper{},
		DisableCompression: true, TLSHandshakeTimeout: speedConnectLimit,
		MaxIdleConnsPerHost: speedStreams, MaxResponseHeaderBytes: 32 << 10,
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func normalizeSpeedSource(source SpeedSource) (SpeedSource, error) {
	switch source {
	case "", SpeedSourceCloudflare:
		return SpeedSourceCloudflare, nil
	case SpeedSourceOokla:
		return source, nil
	default:
		return "", fmt.Errorf("unknown speed source %q", source)
	}
}

type speedEndpoints struct {
	latency          string
	download, upload func() string
	server           string
}

func measureSpeed(ctx context.Context, client *http.Client, resolved string, source SpeedSource, ooklaListURL string, settings speedTransferSettings, update func(CloudflareSpeedReading)) (err error) {
	defer func() {
		if failure := ctx.Err(); failure != nil {
			err = failure
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	source, err = normalizeSpeedSource(source)
	if err != nil {
		return err
	}
	report := CloudflareSpeedReading{Phase: "latency", Resolved: resolved, Source: string(source)}
	emit := func() {
		snapshot := report
		snapshot.Downloads = slices.Clone(report.Downloads)
		snapshot.Uploads = slices.Clone(report.Uploads)
		update(snapshot)
	}
	emit()
	endpoints := speedEndpoints{
		latency:  cloudflareLatencyURL,
		download: func() string { return cloudflareDownURL },
		upload:   func() string { return cloudflareUpURL },
	}
	if source == SpeedSourceOokla {
		endpoints, err = resolveOoklaEndpoints(ctx, client, ooklaListURL)
		if err != nil {
			return err
		}
		report.Server = endpoints.server
		emit()
	}
	latencies := make([]float64, 0, 5)
	for sample := 0; sample < 6; sample++ {
		value, err := measureSpeedLatency(ctx, client, endpoints.latency, source)
		if err != nil {
			return err
		}
		if sample > 0 { // Exclude the connection warm-up.
			latencies = append(latencies, value)
		}
	}
	jitter := 0.0
	for i := 1; i < len(latencies); i++ {
		jitter += math.Abs(latencies[i] - latencies[i-1])
	}
	jitter /= float64(len(latencies) - 1)
	slices.Sort(latencies)
	report.LatencyMS, report.JitterMS = &latencies[2], &jitter
	report.Phase = "download"
	report.Downloads = append(report.Downloads, CloudflareSpeedPoint{})
	emit()
	down, err := runSpeedTransfer(ctx, client, source, http.MethodGet, endpoints.download, settings, func(point CloudflareSpeedPoint) {
		report.Downloads = append(report.Downloads, point)
		emit()
	})
	if err != nil {
		return err
	}
	report.DownloadMbps = &down
	report.Phase = "upload"
	report.Uploads = append(report.Uploads, CloudflareSpeedPoint{})
	emit()
	up, err := runSpeedTransfer(ctx, client, source, http.MethodPost, endpoints.upload, settings, func(point CloudflareSpeedPoint) {
		report.Uploads = append(report.Uploads, point)
		emit()
	})
	if err != nil {
		return err
	}
	report.UploadMbps = &up
	emit()
	return nil
}

func measureSpeedLatency(ctx context.Context, client *http.Client, rawURL string, source SpeedSource) (float64, error) {
	ctx, cancel := context.WithTimeout(ctx, speedConnectLimit)
	defer cancel()
	// The write callback may run on the transport's goroutine.
	written := make(chan time.Time, 1)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		if info.Err == nil {
			select {
			case written <- time.Now():
			default:
			}
		}
	}})
	req, err := newSpeedRequest(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	response, err := client.Do(req)
	received := time.Now()
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if err := speedHTTPError(source, response.StatusCode); err != nil {
		return 0, err
	}
	if err := drainSpeedResponse(response.Body); err != nil {
		return 0, err
	}
	select {
	case now = <-written:
	default:
	}
	return max(0, received.Sub(now).Seconds()*1000), nil
}

func drainSpeedResponse(body io.Reader) error {
	_, err := io.Copy(io.Discard, io.LimitReader(body, maxProbeBodyBytes))
	return err
}

func speedHTTPError(source SpeedSource, code int) error {
	if code < 200 || code >= 300 {
		if source == SpeedSourceOokla {
			return fmt.Errorf("Ookla returned HTTP %d", code)
		}
		return fmt.Errorf("Cloudflare returned HTTP %d", code)
	}
	return nil
}
