package generation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
)

type speedTransport func(*http.Request) (*http.Response, error)

func (f speedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type speedZeroes struct{}

func (speedZeroes) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestCloudflareSpeedUsesBoundedEndpoints(t *testing.T) {
	var measurements, downloads, uploads int
	var uploaded int64
	client := &http.Client{Transport: speedTransport(func(request *http.Request) (*http.Response, error) {
		var body io.Reader = strings.NewReader("")
		switch request.URL.String() {
		case cloudflareLatencyURL:
			if request.Method != http.MethodGet {
				t.Errorf("latency used %s", request.Method)
			}
			measurements++
		case cloudflareDownURL:
			if request.Method != http.MethodGet || request.Header.Get("Accept-Encoding") != "identity" {
				t.Errorf("unexpected download request: %v", request.Header)
			}
			downloads++
			body = io.LimitReader(speedZeroes{}, speedDownloadSize)
		case cloudflareUpURL:
			if request.Method != http.MethodPost ||
				request.Header.Get("Content-Type") != "application/octet-stream" {
				t.Errorf("unexpected upload request: %s, %d, %v", request.Method, request.ContentLength, request.Header)
			}
			uploads++
			if uploads == 1 && request.ContentLength != speedUploadSample {
				t.Errorf("first upload sent %d bytes, want %d", request.ContentLength, speedUploadSample)
			}
			uploaded += confirmSpeedUpload(t, request)
		default:
			return nil, errors.New("unexpected speed test endpoint")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(body), Header: make(http.Header)}, nil
	})}

	var result CloudflareSpeedReading
	if err := measureCloudflareSpeed(t.Context(), client, "relay", func(reading CloudflareSpeedReading) {
		result = reading
	}); err != nil {
		t.Fatal(err)
	}
	if measurements != 6 || downloads != 1 || uploads != 2 {
		t.Fatalf("unexpected request sequence: %d latency, %d download, %d upload", measurements, downloads, uploads)
	}
	if uploaded <= speedUploadSample || uploaded > speedUploadSize {
		t.Fatalf("unexpected aggregate upload size %d", uploaded)
	}
	if result.Resolved != "relay" || result.Phase != "upload" || result.LatencyMS == nil || result.JitterMS == nil ||
		result.DownloadMbps == nil || result.UploadMbps == nil || len(result.Downloads) < 2 || len(result.Uploads) < 2 {
		t.Fatalf("incomplete speed result: %+v", result)
	}
}

func TestSpeedMeterReportsTransferWithinOneClockTick(t *testing.T) {
	var points []CloudflareSpeedPoint
	ctx := t.Context()
	meter := &speedMeter{
		total: speedDownloadSize,
		publish: func(point CloudflareSpeedPoint) {
			points = append(points, point)
		},
	}
	rate, err := meter.result(ctx, ctx, speedDownloadSize, nil)
	if err != nil || len(points) != 1 || points[0].Seconds != speedMinimumSample.Seconds() || points[0].Mbps != rate || rate <= 0 {
		t.Fatalf("unexpected speed result: %v Mbps, points %+v, error %v", rate, points, err)
	}
}

func TestCloudflareUploadRetainsOnlyConfirmedSampleAfterTimeout(t *testing.T) {
	var requests int
	client := &http.Client{Transport: speedTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 2 {
			// The transport may read all bytes without the server confirming
			// any of them before the deadline.
			confirmSpeedUpload(t, request)
			return nil, context.DeadlineExceeded
		}
		confirmSpeedUpload(t, request)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	var points []CloudflareSpeedPoint
	result, err := cloudflareUpload(t.Context(), client, func(point CloudflareSpeedPoint) {
		points = append(points, point)
	})
	if err != nil || requests != 2 || len(points) != 1 || result != points[0].Mbps {
		t.Fatalf("unconfirmed upload counted: result %v, points %+v, requests %d, error %v", result, points, requests, err)
	}
}

func TestCloudflareUploadWithoutAcknowledgementHasNoMeasurement(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		response *http.Response
		err      error
	}{
		{name: "timeout", err: context.DeadlineExceeded},
		{name: "early response", response: &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, err: io.ErrUnexpectedEOF},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client := &http.Client{Transport: speedTransport(func(request *http.Request) (*http.Response, error) {
				_ = request.Body.Close()
				if scenario.response != nil {
					return scenario.response, nil
				}
				return nil, scenario.err
			})}
			result, err := cloudflareUpload(t.Context(), client, func(CloudflareSpeedPoint) {
				t.Error("published a point for an unacknowledged upload")
			})
			if result != 0 || !errors.Is(err, scenario.err) {
				t.Fatalf("unexpected result %v, error %v", result, err)
			}
		})
	}
}

func confirmSpeedUpload(t *testing.T, request *http.Request) int64 {
	t.Helper()
	read, err := io.Copy(io.Discard, request.Body)
	_ = request.Body.Close()
	if err != nil || read != request.ContentLength {
		t.Errorf("upload read %d/%d bytes: %v", read, request.ContentLength, err)
	}
	httptrace.ContextClientTrace(request.Context()).WroteRequest(httptrace.WroteRequestInfo{Err: err})
	return read
}

func TestCloudflareSpeedCancellationSkipsUpload(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var uploads int
	client := &http.Client{Transport: speedTransport(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case cloudflareDownURL:
			cancel()
			return nil, request.Context().Err()
		case cloudflareUpURL:
			uploads++
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})}

	err := measureCloudflareSpeed(ctx, client, "relay", func(CloudflareSpeedReading) {})
	if !errors.Is(err, context.Canceled) || uploads != 0 {
		t.Fatalf("canceled test returned %v with %d uploads", err, uploads)
	}
}
