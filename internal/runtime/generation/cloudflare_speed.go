package generation

import (
	"context"
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
	speedDownloadSize    = 25_000_000
	speedConnectLimit    = 5 * time.Second
	speedTransferLimit   = 10 * time.Second
	speedMinimumSample   = time.Millisecond
)

type CloudflareSpeedPoint struct {
	Seconds float64 `json:"seconds"`
	Mbps    float64 `json:"megabitsPerSecond"`
}

type CloudflareSpeedReading struct {
	Phase        string                 `json:"phase"`
	Resolved     string                 `json:"resolved,omitempty"`
	LatencyMS    *float64               `json:"latencyMs,omitempty"`
	JitterMS     *float64               `json:"jitterMs,omitempty"`
	DownloadMbps *float64               `json:"downloadMbps,omitempty"`
	UploadMbps   *float64               `json:"uploadMbps,omitempty"`
	Downloads    []CloudflareSpeedPoint `json:"downloads,omitempty"`
	Uploads      []CloudflareSpeedPoint `json:"uploads,omitempty"`
}

// RunCloudflareSpeed pins one resolved leaf, together with its DNS and dialer
// dependencies, for the complete benchmark. Policy selection itself is untouched.
func (e *Engine) RunCloudflareSpeed(ctx context.Context, member string, update func(CloudflareSpeedReading)) error {
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
		resolved, err := g.resolveProbe(member, cloudflareLatencyURL)
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
		return MeasureCloudflareSpeed(g.probeLookupContext(selected, out), resolved, pins[out].Dial, update)
	}
	return ctx.Err()
}

func MeasureCloudflareSpeed(
	ctx context.Context,
	resolved string,
	dial func(context.Context, string, string) (net.Conn, error),
	update func(CloudflareSpeedReading),
) error {
	transport := &http.Transport{
		DialContext: func(dialContext context.Context, network, address string) (net.Conn, error) {
			// net/http allows a dial to outlive its initiating request. Bind
			// proxy handshakes to the benchmark's cancellation and deadline.
			dialContext, cancel := context.WithTimeout(dialContext, speedConnectLimit)
			defer cancel()
			stop := context.AfterFunc(ctx, cancel)
			defer stop()
			return dial(dialContext, network, address)
		},
		ForceAttemptHTTP2: true, DisableCompression: true, TLSHandshakeTimeout: speedConnectLimit,
		MaxIdleConnsPerHost: 1, MaxResponseHeaderBytes: 32 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return measureCloudflareSpeed(ctx, client, resolved, update)
}

func measureCloudflareSpeed(ctx context.Context, client *http.Client, resolved string, update func(CloudflareSpeedReading)) error {
	report := CloudflareSpeedReading{Phase: "latency", Resolved: resolved}
	emit := func() {
		snapshot := report
		snapshot.Downloads = slices.Clone(report.Downloads)
		snapshot.Uploads = slices.Clone(report.Uploads)
		update(snapshot)
	}
	emit()
	latencies := make([]float64, 0, 5)
	for sample := 0; sample < 6; sample++ {
		value, err := cloudflareLatency(ctx, client)
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
	down, err := cloudflareDownload(ctx, client, func(point CloudflareSpeedPoint) {
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
	up, err := cloudflareUpload(ctx, client, func(point CloudflareSpeedPoint) {
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

func cloudflareLatency(ctx context.Context, client *http.Client) (float64, error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudflareLatencyURL, nil)
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
	if err := speedHTTPStatus(response.StatusCode); err != nil {
		return 0, err
	}
	read, err := io.Copy(io.Discard, io.LimitReader(response.Body, 1))
	if err != nil || read != 0 {
		return 0, errors.New("unexpected Cloudflare latency response")
	}
	select {
	case now = <-written:
	default:
	}
	return max(0, received.Sub(now).Seconds()*1000), nil
}

func cloudflareDownload(ctx context.Context, client *http.Client, publish func(CloudflareSpeedPoint)) (float64, error) {
	phaseCtx, cancel := context.WithTimeout(ctx, speedTransferLimit)
	defer cancel()
	meter := &speedMeter{start: time.Now(), publish: publish}
	req, err := http.NewRequestWithContext(phaseCtx, http.MethodGet, cloudflareDownURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(req)
	if err != nil {
		return meter.result(ctx, phaseCtx, speedDownloadSize, err)
	}
	defer response.Body.Close()
	if err := speedHTTPStatus(response.StatusCode); err != nil {
		return 0, err
	}
	reader := &speedReader{Reader: io.LimitReader(response.Body, speedDownloadSize), meter: meter}
	_, err = io.Copy(io.Discard, reader)
	return meter.result(ctx, phaseCtx, speedDownloadSize, err)
}

func speedHTTPStatus(code int) error {
	if code < 200 || code >= 300 {
		return fmt.Errorf("Cloudflare returned HTTP %d", code)
	}
	return nil
}

type speedReader struct {
	io.Reader
	meter *speedMeter
}

func (r *speedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.meter.record(int64(n))
	}
	return n, err
}

type speedMeter struct {
	start    time.Time
	publish  func(CloudflareSpeedPoint)
	total    int64
	previous int64
	elapsed  float64
	reported float64
}

func (m *speedMeter) record(n int64) {
	m.total += n
	m.elapsed = min(speedTransferLimit.Seconds(), time.Since(m.start).Seconds())
	if m.elapsed-m.reported >= 0.25 {
		m.report(m.elapsed)
	}
}

func (m *speedMeter) report(end float64) {
	if seconds := end - m.reported; seconds > 0 && m.total > m.previous {
		m.publish(CloudflareSpeedPoint{Seconds: end, Mbps: speedMbps(m.total-m.previous, seconds)})
		m.previous, m.reported = m.total, end
	}
}

func (m *speedMeter) result(ctx, phaseCtx context.Context, expected int64, err error) (float64, error) {
	if failure := ctx.Err(); failure != nil {
		return 0, failure
	}
	elapsed := m.elapsed
	if err != nil && phaseCtx.Err() == context.DeadlineExceeded && m.total > 0 && m.total < expected {
		elapsed = speedTransferLimit.Seconds()
	} else if err != nil {
		return 0, err
	} else if m.total != expected {
		return 0, io.ErrUnexpectedEOF
	}
	// Fast transfers may finish within a single clock tick. Use the same
	// minimum duration for the final chart point and the aggregate rate.
	elapsed = max(speedMinimumSample.Seconds(), elapsed)
	m.report(elapsed)
	return speedMbps(m.total, elapsed), nil
}

func speedMbps(bytes int64, seconds float64) float64 {
	return float64(bytes) * 8 / 1_000_000 / seconds
}
