package sagernet

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/internal/script/gojaengine"
)

const grpcTestContentType = "application/grpc"

func grpcTestFrame(body string) []byte {
	frame := make([]byte, 5+len(body))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(body)))
	copy(frame[5:], body)
	return frame
}

func readGRPCTestFrame(t *testing.T, reader io.Reader, body string) {
	t.Helper()
	want := grpcTestFrame(body)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("gRPC frame = %q, want %q, error %v", got, want, err)
	}
}

func grpcTestTrailers(w http.ResponseWriter) {
	w.Header().Set("Content-Type", grpcTestContentType)
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
}

func grpcTestComplete(w http.ResponseWriter, status, message string) {
	w.Header().Set("Grpc-Status", status)
	w.Header().Set("Grpc-Message", message)
}

func assertGRPCTestTrailers(t *testing.T, res *http.Response, status, message string) {
	t.Helper()
	if res.Trailer.Get("Grpc-Status") != status || res.Trailer.Get("Grpc-Message") != message {
		t.Fatalf("gRPC trailers = %v", res.Trailer)
	}
}

func newGRPCTestRequest(t *testing.T, f *mitmH2Fixture, path string, body io.Reader) *http.Request {
	t.Helper()
	req := f.request(t, http.MethodPost, path, body)
	req.Header.Set("Content-Type", grpcTestContentType)
	req.Header.Set("TE", "trailers")
	return req
}

func TestMITMHTTP2GRPCUnaryBinaryScript(t *testing.T) {
	host := script.NewHost(gojaengine.New(), script.Limits{}, script.Environment{})
	program := &script.Script{
		Kind: script.KindHTTPResponse, BinaryBody: true,
		Source: `
			const body = $response.body;
			if (!($script.binaryBodyMode && body instanceof Uint8Array &&
				body.length === 9 && body[0] === 0 && body[1] === 0 &&
				body[2] === 0 && body[3] === 0 && body[4] === 4 &&
				body[5] === 112 && body[6] === 111 && body[7] === 110 && body[8] === 103)) {
				throw new Error("expected the complete gRPC frame");
			}
			body[5] = 80;
			$done({headers: {"Content-Type": "application/grpc", "X-Binary-Result": "modified"}, body});
		`,
	}
	for _, clientH2 := range []bool{true, false} {
		name := "HTTP/1 client"
		if clientH2 {
			name = "HTTP/2 client"
		}
		t.Run(name, func(t *testing.T) {
			f := newMITMH2Fixture(t, &MITMRoute{
				H2: true, MatchScript: func(kind script.Kind, url string) *MITMScript {
					if kind != script.KindHTTPResponse || !strings.HasSuffix(url, "/unary") {
						return nil
					}
					return &MITMScript{
						ID: "binary-response", RequiresBody: true, MaxSize: 128,
						Run: func(ctx context.Context, input *script.Input) (script.Result, error) {
							return host.Run(ctx, program, input, script.Services{})
						},
					}
				},
			}, clientH2, true, func(w http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(data, grpcTestFrame("ping")) || r.ProtoMajor != 2 ||
					r.Header.Get("TE") != "trailers" || r.Header.Get("Content-Type") != grpcTestContentType {
					t.Errorf("origin gRPC unary protocol = %s, body = %q, headers = %v, error %v", r.Proto, data, r.Header, err)
				}
				grpcTestTrailers(w)
				_, _ = w.Write(grpcTestFrame("pong"))
				grpcTestComplete(w, "0", "complete")
			})
			res, body := f.response(t, newGRPCTestRequest(t, f, "/unary", bytes.NewReader(grpcTestFrame("ping"))))
			if res.StatusCode != http.StatusOK || !bytes.Equal([]byte(body), grpcTestFrame("Pong")) ||
				res.Header.Get("X-Binary-Result") != "modified" || res.Header.Get("Content-Type") != grpcTestContentType {
				t.Fatalf("proxy gRPC unary status = %d, body = %q, headers = %v", res.StatusCode, body, res.Header)
			}
			assertGRPCTestTrailers(t, res, "0", "complete")
			if !clientH2 && !slices.Equal(res.TransferEncoding, []string{"chunked"}) {
				t.Fatalf("HTTP/1 unary response framing = %v", res.TransferEncoding)
			}
			row := f.requestHistory(t, 1)[0]
			if len(row.Scripts) != 1 || row.Scripts[0].Result != "modified" || row.BodyPassthroughs != 0 {
				t.Fatalf("unary script diagnostics = %+v", row)
			}
		})
	}
}

func TestMITMHTTP2GRPCServerStream(t *testing.T) {
	sendFirst := make(chan struct{})
	sendSecond := make(chan struct{})
	f := newMITMH2Fixture(t, &MITMRoute{H2: true}, true, true, func(w http.ResponseWriter, r *http.Request) {
		grpcTestTrailers(w)
		// HTTP/2 can stream and send trailers with a known body length.
		w.Header().Set("Content-Length", strconv.Itoa(len(grpcTestFrame("first"))+len(grpcTestFrame("second"))))
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-sendFirst:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write(grpcTestFrame("first"))
		w.(http.Flusher).Flush()
		select {
		case <-sendSecond:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write(grpcTestFrame("second"))
		grpcTestComplete(w, "0", "stream complete")
	})
	res, err := f.client.RoundTrip(newGRPCTestRequest(t, f, "/stream", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.ProtoMajor != 2 {
		t.Fatalf("stream status = %d, protocol = %s", res.StatusCode, res.Proto)
	}
	close(sendFirst)
	readGRPCTestFrame(t, res.Body, "first")
	close(sendSecond)
	readGRPCTestFrame(t, res.Body, "second")
	if data, err := io.ReadAll(res.Body); err != nil || len(data) != 0 {
		t.Fatalf("stream remainder = %q, error %v", data, err)
	}
	assertGRPCTestTrailers(t, res, "0", "stream complete")
}

func TestMITMHTTP2GRPCDuplex(t *testing.T) {
	f := newMITMH2Fixture(t, &MITMRoute{H2: true}, true, true, func(w http.ResponseWriter, r *http.Request) {
		grpcTestTrailers(w)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		frame := make([]byte, len(grpcTestFrame("ping")))
		for _, message := range []string{"ping", "pong"} {
			if _, err := io.ReadFull(r.Body, frame); err != nil || !bytes.Equal(frame, grpcTestFrame(message)) {
				t.Errorf("origin read duplex frame %q, want %q, error %v", frame, message, err)
				return
			}
			_, _ = w.Write(frame)
			w.(http.Flusher).Flush()
		}
		if data, err := io.ReadAll(r.Body); err != nil || len(data) != 0 || r.Trailer.Get("X-Client-Trailer") != "complete" {
			t.Errorf("origin upload remainder = %q, trailers = %v, error %v", data, r.Trailer, err)
		}
		grpcTestComplete(w, "0", "duplex complete")
	})
	pr, pw := io.Pipe()
	defer pw.Close()
	req := newGRPCTestRequest(t, f, "/duplex", pr)
	req.Trailer = http.Header{"X-Client-Trailer": {"complete"}}
	res, err := f.client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.ProtoMajor != 2 {
		t.Fatalf("duplex status = %d, protocol = %s", res.StatusCode, res.Proto)
	}
	for _, message := range []string{"ping", "pong"} {
		if _, err := pw.Write(grpcTestFrame(message)); err != nil {
			t.Fatal(err)
		}
		readGRPCTestFrame(t, res.Body, message)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := io.ReadAll(res.Body); err != nil || len(data) != 0 {
		t.Fatalf("duplex remainder = %q, error %v", data, err)
	}
	assertGRPCTestTrailers(t, res, "0", "duplex complete")
}

func TestMITMHTTP2GRPCTrailersOnly(t *testing.T) {
	f := newMITMH2Fixture(t, &MITMRoute{
		H2: true, MatchScript: func(kind script.Kind, _ string) *MITMScript {
			if kind != script.KindHTTPResponse {
				return nil
			}
			return &MITMScript{ID: "response-headers", Run: func(context.Context, *script.Input) (script.Result, error) {
				return script.Result{Action: script.ActionModify, HeadersSet: true, Headers: []script.HeaderField{
					{Name: "Content-Type", Value: grpcTestContentType},
					{Name: "X-Edited", Value: "true"},
					{Name: "X-Error-Detail", Value: "replacement"},
				}}, nil
			}}
		},
	}, true, true, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", grpcTestContentType)
		// A trailers-only gRPC response sends these fields in the only
		// HEADERS frame, with END_STREAM and no separate trailers.
		grpcTestComplete(w, "7", "permission denied")
		w.Header().Set("X-Error-Detail", "origin")
		w.WriteHeader(http.StatusOK)
	})
	res, body := f.response(t, newGRPCTestRequest(t, f, "/trailers-only", nil))
	if res.StatusCode != http.StatusOK || res.Header.Get("Grpc-Status") != "7" ||
		res.Header.Get("Grpc-Message") != "permission denied" || res.Header.Get("X-Edited") != "true" ||
		res.Header.Get("X-Error-Detail") != "origin" ||
		len(res.Trailer) != 0 || body != "" {
		t.Fatalf("trailers-only status = %d, headers = %v, trailers = %v, body = %q", res.StatusCode, res.Header, res.Trailer, body)
	}
}

func TestMITMHTTP2GRPCCancellation(t *testing.T) {
	canceled := make(chan error, 1)
	f := newMITMH2Fixture(t, &MITMRoute{H2: true}, true, true, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_, _ = io.WriteString(w, "healthy")
			return
		}
		grpcTestTrailers(w)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		canceled <- r.Context().Err()
	})
	req := newGRPCTestRequest(t, f, "/cancel", nil)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	res, err := f.client.RoundTrip(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	cancel()
	if _, err := io.ReadAll(res.Body); err == nil {
		t.Errorf("canceled client stream finished without an error")
	}
	select {
	case err := <-canceled:
		if err != context.Canceled {
			t.Fatalf("upstream context error = %v", err)
		}
	case <-req.Context().Done():
		t.Fatal("upstream request was not canceled")
	}
	res, body := f.response(t, f.request(t, http.MethodGet, "/health", nil))
	if res.StatusCode != http.StatusOK || body != "healthy" || f.dials.Load() != 1 {
		t.Fatalf("status after cancel = %d, body = %q, origin dials = %d", res.StatusCode, body, f.dials.Load())
	}
}

func TestMITMHTTP2OversizeResponseStreams(t *testing.T) {
	const limit = 32
	first, second := grpcTestFrame(strings.Repeat("a", limit*2)), grpcTestFrame("rest")
	release := make(chan struct{})
	runs := make(chan api.MITMScriptRun, 1)
	f := newMITMH2Fixture(t, &MITMRoute{
		H2: true,
		MatchScript: func(kind script.Kind, _ string) *MITMScript {
			if kind != script.KindHTTPResponse {
				return nil
			}
			return &MITMScript{
				ID: "limited-script", RequiresBody: true, MaxSize: limit,
				Run: func(context.Context, *script.Input) (script.Result, error) {
					t.Error("oversized response ran its script")
					return script.Result{}, nil
				},
			}
		},
		OnScript: func(run api.MITMScriptRun, executed bool) {
			if executed {
				t.Error("oversized response was marked executed")
			}
			runs <- run
		},
	}, true, true, func(w http.ResponseWriter, r *http.Request) {
		grpcTestTrailers(w)
		_, _ = w.Write(first)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write(second)
		grpcTestComplete(w, "0", "complete")
	})
	res, err := f.client.RoundTrip(newGRPCTestRequest(t, f, "/oversize", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.ProtoMajor != 2 {
		t.Fatalf("oversized response status = %d, protocol = %s", res.StatusCode, res.Proto)
	}
	gotFirst := make([]byte, len(first))
	if _, err := io.ReadFull(res.Body, gotFirst); err != nil || !bytes.Equal(gotFirst, first) {
		t.Fatalf("first oversized chunk = %q, error %v", gotFirst, err)
	}
	close(release)
	if gotSecond, err := io.ReadAll(res.Body); err != nil || !bytes.Equal(gotSecond, second) {
		t.Fatalf("oversized response remainder = %q, error %v", gotSecond, err)
	}
	assertGRPCTestTrailers(t, res, "0", "complete")
	record := f.requestHistory(t, 1)[0]
	live := f.live(t)
	if record.BodyPassthroughs != 1 || live.MITMBodyPassthroughs != 1 ||
		len(record.Scripts) != 1 || record.Scripts[0].Result != "oversize" {
		t.Fatalf("oversized request diagnostics = %+v, connection diagnostics = %+v", record, live.MITMConnectionInfo)
	}
	select {
	case run := <-runs:
		if run.ID != "limited-script" || run.Result != "oversize" {
			t.Fatalf("oversized script run = %+v", run)
		}
	default:
		t.Fatal("oversized script run was not recorded")
	}
}
