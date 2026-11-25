package sagernet

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/script"
)

func TestMITMRequestScriptResult(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "https://origin.test/old", strings.NewReader("original"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Encoding", "gzip")
	request.Header.Set("X-Original", "old")
	target := "https://origin.test:8443/new"
	result := script.Result{
		URL: &target, HeadersSet: true, BodySet: true, Body: []byte("replaced"),
		Headers: []script.HeaderField{
			{Name: "Host", Value: "origin.test"},
			{Name: "X-Added", Value: "one"},
			{Name: "X-Added", Value: "two"},
			{Name: "Connection", Value: "X-Hop, Content-Length"},
			{Name: "X-Hop", Value: "hop"},
			{Name: "Content-Encoding", Value: "gzip"},
			{Name: "Content-Length", Value: "1"},
			{Name: "Transfer-Encoding", Value: "chunked"},
		},
	}
	destination, reroute, err := applyMITMRequestScript(request, result)
	if err != nil || !reroute || destination.String() != "origin.test:8443" {
		t.Fatalf("destination %v, reroute %v, error %v", destination, reroute, err)
	}
	if request.URL.String() != target || request.Host != "origin.test:8443" || request.ContentLength != int64(len(result.Body)) {
		t.Fatalf("URL %s, host %s, content length %d", request.URL, request.Host, request.ContentLength)
	}
	if !slices.Equal(request.Header.Values("X-Added"), []string{"one", "two"}) || request.Header.Get("Content-Length") != "8" ||
		request.Header.Get("Content-Encoding") != "" || request.Header.Get("Transfer-Encoding") != "" ||
		request.Header.Get("X-Hop") != "" || request.Header.Get("X-Original") != "" || request.Header.Get("Host") != "" {
		t.Fatalf("replacement headers = %v", request.Header)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != "replaced" {
		t.Fatalf("replacement body = %q, error %v", body, err)
	}

	invalid := "http://origin.test/invalid"
	result.URL = &invalid
	if _, _, err := applyMITMRequestScript(request, result); err == nil || request.URL.String() != target {
		t.Fatalf("invalid result changed URL to %v, error %v", request.URL, err)
	}
}

func TestMITMResponseScriptResult(t *testing.T) {
	// A header-only response script cannot change the framing or encoding
	// of the original stream.
	header := http.Header{"Content-Encoding": {"gzip"}, "X-Old": {"old"}}
	response := httprewrite.Response{StatusCode: http.StatusOK, Header: header}
	result := script.Result{
		Status: http.StatusAccepted, HeadersSet: true,
		Headers: []script.HeaderField{
			{Name: "Content-Length", Value: "2"},
			{Name: "Content-Encoding", Value: "deflate"},
			{Name: "Transfer-Encoding", Value: "chunked"},
			{Name: "X-Response", Value: "edited"},
		},
	}
	modified, err := applyMITMResponseScript(response, -1, result)
	if err != nil {
		t.Fatal(err)
	}
	if modified.StatusCode != http.StatusAccepted || modified.Body != nil || modified.Header.Get("X-Response") != "edited" ||
		modified.Header.Get("Content-Length") != "" || modified.Header.Get("Content-Encoding") != "gzip" ||
		modified.Header.Get("Transfer-Encoding") != "" || modified.Header.Get("X-Old") != "" {
		t.Fatalf("streaming response = %+v", modified)
	}
	result.BodySet = true
	modified, err = applyMITMResponseScript(response, -1, result)
	if err != nil || modified.Body == nil || len(modified.Body) != 0 ||
		modified.Header.Get("Content-Length") != "0" || modified.Header.Get("Content-Encoding") != "" {
		t.Fatalf("empty replacement response = %+v, error %v", modified, err)
	}
	result.Status = http.StatusSwitchingProtocols
	modified, err = applyMITMResponseScript(response, -1, result)
	if err == nil || modified.StatusCode != response.StatusCode || modified.Header.Get("X-Old") != "old" {
		t.Fatalf("invalid status result = %+v, error %v", modified, err)
	}
}

func TestMITMScriptBodyBuffer(t *testing.T) {
	handler := mitmHTTPHandler{route: &MITMRoute{MaxBodySize: 128}}
	source := strings.Repeat("a", 256)
	match := &MITMScript{RequiresBody: true, MaxSize: 64, Run: func(context.Context, *script.Input) (script.Result, error) {
		t.Fatal("unexpected script execution")
		return script.Result{}, nil
	}}
	stream := io.NopCloser(strings.NewReader(source))
	buffer, err := handler.bufferBody(stream, -1, true, match)
	if err != nil || !buffer.exceeds(handler.route.MaxBodySize) || buffer.data != nil {
		t.Fatalf("oversize buffer = %+v, error %v", buffer, err)
	}
	forwarded, err := io.ReadAll(buffer.reader)
	if err != nil || string(forwarded) != source {
		t.Fatalf("oversize replay returned %d bytes, error %v", len(forwarded), err)
	}

	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	if _, err := io.WriteString(zip, source); err != nil {
		t.Fatal(err)
	}
	if err := zip.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := compressed.Bytes()
	request, err := http.NewRequest(http.MethodPost, "https://origin.test/path", bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Encoding", "gzip")
	buffer, err = handler.bufferBody(request.Body, request.ContentLength, false, match)
	if err != nil || buffer.exceeds(match.MaxSize) {
		t.Fatalf("compressed buffer = %+v, error %v", buffer, err)
	}
	input := mitmScriptInput{id: 12, request: request}
	var stats mitmRequestStats
	if !handler.runScript(t.Context(), match, input, buffer, &stats, nil) || len(stats.scripts) != 1 || stats.scripts[0].Result != "oversize" ||
		!bytes.Equal(buffer.data, encoded) {
		t.Fatalf("decoded overflow = %+v, encoded buffer = %d bytes", stats.scripts, len(buffer.data))
	}
	match.RequiresBody = false
	job, err := input.scriptInput(match, buffer)
	if err != nil || job.Request.Body != nil || job.Request.ID != "12" {
		t.Fatalf("bodyless script input = %+v, error %v", job, err)
	}
}

func TestMITMScriptResponseUsesSuppliedEncoding(t *testing.T) {
	response, err := mitmScriptResponse(&script.Response{
		Status: http.StatusOK, Body: []byte("encoded"),
		Headers: []script.HeaderField{
			{Name: "Content-Encoding", Value: "gzip"},
			{Name: "Content-Length", Value: "1"},
			{Name: "Transfer-Encoding", Value: "chunked"},
		},
	})
	if err != nil || response.Header.Get("Content-Encoding") != "gzip" ||
		response.Header.Get("Content-Length") != "7" || response.Header.Get("Transfer-Encoding") != "" {
		t.Fatalf("local response = %+v, error %v", response, err)
	}
}

func TestMITMScriptUnsupportedDoesNotReadBody(t *testing.T) {
	match := &MITMScript{ID: "disabled", RequiresBody: true, MaxSize: 64}
	handler := mitmHTTPHandler{route: &MITMRoute{
		OnScript: func(run api.MITMScriptRun, executed bool) {
			if executed || run.Result != "unsupported" {
				t.Errorf("script outcome %+v, executed %v", run, executed)
			}
		},
	}}
	body := io.NopCloser(strings.NewReader("upload"))
	buffer, err := handler.bufferBody(body, -1, false, match)
	if err != nil || buffer.reader != body || buffer.data != nil {
		t.Fatalf("unsupported script buffered the body: %+v, error %v", buffer, err)
	}
	var stats mitmRequestStats
	handler.runScript(t.Context(), match, mitmScriptInput{}, buffer, &stats, nil)
	if len(stats.scripts) != 1 || stats.scripts[0].Result != "unsupported" {
		t.Fatalf("unsupported script diagnostics = %+v", stats.scripts)
	}
	data, err := io.ReadAll(body)
	if err != nil || string(data) != "upload" {
		t.Fatalf("forwarded body = %q, error %v", data, err)
	}
}

func TestMITMScriptRecordsMemoryOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		duration time.Duration
		executed bool
	}{
		{"skipped", script.ErrLowMemory, time.Millisecond, false},
		{"discarded", script.ErrMemoryExceeded, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "https://origin.test/", nil)
			if err != nil {
				t.Fatal(err)
			}
			match := &MITMScript{ID: "memory", Run: func(context.Context, *script.Input) (script.Result, error) {
				return script.Result{Duration: tc.duration}, fmt.Errorf("host: %w", tc.err)
			}}
			var got api.MITMScriptRun
			var executed bool
			handler := mitmHTTPHandler{route: &MITMRoute{
				OnScript: func(run api.MITMScriptRun, ran bool) {
					got, executed = run, ran
				},
			}}
			var stats mitmRequestStats
			oversize := handler.runScript(t.Context(), match, mitmScriptInput{request: request}, mitmBufferedBody{}, &stats, nil)
			if got.ID != match.ID || got.Result != "low-memory" || executed != tc.executed || oversize {
				t.Fatalf("run = %+v, executed = %v, oversize = %v", got, executed, oversize)
			}
		})
	}
}

func TestMITMScriptConnectionStats(t *testing.T) {
	var runs []api.MITMScriptRun
	for i := range maxConnectionEvents + 1 {
		runs = append(runs, api.MITMScriptRun{ID: fmt.Sprintf("script-%d", i), Result: "passed"})
	}
	runs = append(runs, api.MITMScriptRun{ID: runs[0].ID, Result: "modified"})
	stats := appendMITMScriptStats(nil, runs)
	if len(stats) != maxConnectionEvents || stats[0].Count != 2 || stats[0].LastResult != "modified" ||
		stats[len(stats)-1].ID != runs[maxConnectionEvents-1].ID {
		t.Fatalf("connection script stats = %+v", stats)
	}
}

func TestMITMScriptLocalHeadResponse(t *testing.T) {
	const host = "local-script.test"
	issuer, roots := mitmRelayTestIssuer(t, "Local script test CA")
	runs := make(chan api.MITMScriptRun, 1)
	wire := mitmLocalTestConnection(t, &MITMRoute{
		Host: host, Issuer: issuer,
		MatchScript: func(kind script.Kind, rawURL string) *MITMScript {
			if kind != script.KindHTTPRequest || rawURL != "https://"+host+"/head" {
				t.Errorf("unexpected script match for %s %s", kind, rawURL)
				return nil
			}
			return &MITMScript{ID: "local", Run: func(_ context.Context, input *script.Input) (script.Result, error) {
				if input.Request.ID == "" || input.Request.Method != http.MethodHead || input.Request.Body != nil {
					t.Errorf("local HEAD script input = %+v", input.Request)
				}
				return script.Result{Action: script.ActionRespond, Duration: time.Millisecond, Response: &script.Response{
					Status: http.StatusAccepted, Body: []byte("hidden"),
				}}, nil
			}}
		},
		OnScript: func(run api.MITMScriptRun, executed bool) {
			if !executed {
				t.Error("local script did not execute")
			}
			runs <- run
		},
	}, 0)
	client := tls.Client(wire, &tls.Config{ServerName: host, RootCAs: roots})
	if _, err := io.WriteString(client, "HEAD /head HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodHead})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted || response.ContentLength != 6 {
		t.Fatalf("HEAD response status = %d, length = %d", response.StatusCode, response.ContentLength)
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("HEAD response sent body bytes")
	}
	if run := <-runs; run.ID != "local" || run.Phase != "request" || run.Result != "responded" {
		t.Fatalf("local script outcome = %+v", run)
	}
}
