package generation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	// Like Ookla's multi-connection test, use several connections to fill a
	// fast link. Ten seconds leaves time for a steady rate after TCP ramps up.
	speedStreams       = 6
	speedTransferLimit = 10 * time.Second

	// Repeat large requests to amortize HTTP overhead while preserving
	// Cloudflare's existing per-request sizes.
	speedDownloadSize = 25_000_000
	speedUploadSize   = 10_000_000
)

type speedTransferSettings struct {
	duration, warmup, firstByteWarmup, minimumSteady time.Duration
	interval, window                                 time.Duration
}

func defaultSpeedTransferSettings() speedTransferSettings {
	return speedTransferSettings{
		duration:        speedTransferLimit,
		warmup:          2 * time.Second, // Exclude TCP slow start, as discussed in Cloudflare's speed test methodology.
		firstByteWarmup: time.Second,     // Allow time to ramp up even after a slow dial.
		minimumSteady:   3 * time.Second, // Keep a long enough window on paths that take longer to begin transferring.
		interval:        250 * time.Millisecond,
		window:          time.Second, // Smooth short bursts across four chart samples.
	}
}

func runSpeedTransfer(ctx context.Context, client *http.Client, source SpeedSource, method string, endpoint func() string, settings speedTransferSettings, publish func(CloudflareSpeedPoint)) (float64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var payload []byte
	if method == http.MethodPost {
		payload = speedUploadPayload()
	}
	start := time.Now()
	phaseCtx, cancel := context.WithDeadline(ctx, start.Add(settings.duration))
	defer cancel()
	ticker := time.NewTicker(settings.interval)
	defer ticker.Stop()
	meter := newSpeedMeter(start, settings)
	results := make(chan error, speedStreams)
	for range speedStreams {
		go func() {
			for phaseCtx.Err() == nil {
				err := speedTransferRequest(phaseCtx, client, source, method, endpoint(), payload, meter)
				if err != nil {
					results <- err
					return
				}
			}
			results <- phaseCtx.Err()
		}()
	}
	var failure error
	remaining := speedStreams
	next := settings.interval
	publishThrough := func(elapsed time.Duration) {
		for next <= elapsed && ctx.Err() == nil {
			publish(meter.point(next))
			next += settings.interval
		}
	}
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case err := <-results:
			if failure == nil && !errors.Is(err, phaseCtx.Err()) {
				failure = err
			}
			remaining--
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			if remaining == 0 && failure != nil && !meter.hasData() {
				return 0, failure
			}
		case <-ticker.C:
			publishThrough(min(time.Since(start), settings.duration))
		case <-phaseCtx.Done():
			publishThrough(settings.duration)
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			if !meter.hasData() {
				for failure == nil && len(results) > 0 {
					if err := <-results; !errors.Is(err, phaseCtx.Err()) {
						failure = err
					}
				}
				if failure == nil {
					failure = errors.New("speed test transferred no data")
				}
				return 0, failure
			}
			return meter.rate(), nil
		}
	}
}

func speedTransferRequest(ctx context.Context, client *http.Client, source SpeedSource, method, endpoint string, payload []byte, meter *speedMeter) error {
	var body io.Reader
	if method == http.MethodPost {
		body = &speedReader{Reader: newSpeedUploadBody(payload), meter: meter}
	}
	req, err := newSpeedRequest(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "identity")
	if body != nil {
		req.ContentLength = speedUploadSize
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := speedHTTPError(source, response.StatusCode); err != nil {
		return err
	}
	if body != nil {
		return drainSpeedResponse(response.Body)
	}
	reader := &speedReader{Reader: io.LimitReader(response.Body, speedDownloadSize), meter: meter}
	n, err := io.Copy(io.Discard, reader)
	if err == nil && n == 0 {
		return io.ErrUnexpectedEOF
	}
	if err == nil && n == speedDownloadSize {
		// Read through a chunked response's EOF so the connection can be reused.
		if _, err = io.CopyN(io.Discard, response.Body, 1); err == io.EOF {
			return nil
		}
		if err == nil {
			return errors.New("speed test download exceeded requested size")
		}
	}
	return err
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
	start         time.Time
	settings      speedTransferSettings
	mu            sync.Mutex
	intervalBytes []int64
	firstByte     time.Duration
	warmupEnd     time.Duration
	total         int64
	warmBytes     int64
}

func newSpeedMeter(start time.Time, settings speedTransferSettings) *speedMeter {
	return &speedMeter{
		start:         start,
		settings:      settings,
		intervalBytes: make([]int64, (settings.duration+settings.interval-1)/settings.interval),
	}
}

func (m *speedMeter) record(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	elapsed := time.Since(m.start)
	if elapsed >= m.settings.duration {
		return
	}
	if m.total == 0 {
		m.firstByte = elapsed
		m.warmupEnd = speedWarmupEnd(elapsed, m.settings)
	}
	m.total += n
	if elapsed < m.warmupEnd {
		m.warmBytes += n
	}
	m.intervalBytes[elapsed/m.settings.interval] += n
}

func (m *speedMeter) point(end time.Duration) CloudflareSpeedPoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	// The window spans a whole number of reporting intervals. Retaining one
	// count per interval lets delayed ticks still report their original window.
	start := max(0, end-m.settings.window)
	var bytes int64
	for _, amount := range m.intervalBytes[start/m.settings.interval : end/m.settings.interval] {
		bytes += amount
	}
	return CloudflareSpeedPoint{Seconds: end.Seconds(), Mbps: speedMbps(bytes, (end - start).Seconds())}
}

func (m *speedMeter) hasData() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.total > 0
}

func (m *speedMeter) rate() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return speedTransferRate(m.total, m.warmBytes, m.firstByte, m.settings)
}

func speedWarmupEnd(firstByte time.Duration, settings speedTransferSettings) time.Duration {
	end := max(settings.warmup, firstByte+settings.firstByteWarmup)
	if settings.duration-end < settings.minimumSteady {
		return firstByte
	}
	return end
}

func speedTransferRate(total, warmBytes int64, firstByte time.Duration, settings speedTransferSettings) float64 {
	// Measure only after the TCP ramp-up, or from the first byte if that
	// leaves too little time. For upload the send buffers should be similarly
	// occupied at both ends of the steady window, so body reads approximate
	// bytes sent without waiting for a full request to be acknowledged.
	end := speedWarmupEnd(firstByte, settings)
	if end != firstByte {
		total -= warmBytes
	}
	return speedMbps(total, (settings.duration - end).Seconds())
}

func speedMbps(bytes int64, seconds float64) float64 {
	return float64(bytes) * 8 / 1_000_000 / seconds
}
