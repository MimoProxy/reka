package generation

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

const (
	cloudflareUpURL   = "https://speed.cloudflare.com/__up"
	speedUploadSize   = 10_000_000
	speedUploadSample = 128 << 10
)

// cloudflareUpload starts with a sample that can complete on a slow uplink.
// It only includes requests whose full body was written and whose response was
// successful. A timed-out larger sample adds no bytes to the reported rate.
func cloudflareUpload(ctx context.Context, client *http.Client, publish func(CloudflareSpeedPoint)) (float64, error) {
	phaseCtx, cancel := context.WithTimeout(ctx, speedTransferLimit)
	defer cancel()
	deadline, _ := phaseCtx.Deadline()
	start := time.Now()
	elapsed, err := cloudflareUploadSample(phaseCtx, client, speedUploadSample)
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	total := int64(speedUploadSample)
	firstEnd := max(elapsed, time.Since(start).Seconds())
	publish(CloudflareSpeedPoint{
		Seconds: firstEnd,
		Mbps:    speedMbps(total, elapsed),
	})

	// Use 70% of the remaining estimated capacity to leave room for
	// acknowledgement latency or a transient drop in uplink throughput.
	remaining := time.Until(deadline).Seconds()
	estimated := int64(0.70 * remaining * float64(total) / elapsed)
	next := min(int64(speedUploadSize)-total, estimated)
	if next <= speedUploadSample {
		return speedMbps(total, elapsed), nil
	}
	followup, err := cloudflareUploadSample(phaseCtx, client, next)
	if failure := ctx.Err(); failure != nil {
		return 0, failure
	}
	if err == nil {
		total += next
		elapsed += followup
		publish(CloudflareSpeedPoint{
			Seconds: max(firstEnd+followup, time.Since(start).Seconds()),
			Mbps:    speedMbps(next, followup),
		})
	}
	return speedMbps(total, elapsed), nil
}

func cloudflareUploadSample(ctx context.Context, client *http.Client, size int64) (float64, error) {
	body := &speedUploadBody{Reader: io.LimitReader(rand.Reader, size)}
	written := make(chan error, 1)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		select {
		case written <- info.Err:
		default:
		}
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cloudflareUpURL, body)
	if err != nil {
		return 0, err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	start := time.Now()
	response, err := client.Do(req)
	elapsed := max(speedMinimumSample.Seconds(), time.Since(start).Seconds())
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if err := speedHTTPStatus(response.StatusCode); err != nil {
		return 0, err
	}
	if body.read.Load() != size {
		return 0, io.ErrUnexpectedEOF
	}
	select {
	case err := <-written:
		if err != nil {
			return 0, err
		}
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 4096)); err != nil {
		return 0, err
	}
	return elapsed, nil
}

type speedUploadBody struct {
	io.Reader
	read atomic.Int64
}

func (b *speedUploadBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read.Add(int64(n))
	return n, err
}
