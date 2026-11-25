package generation

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/script"
)

func TestMITMScriptTableOrder(t *testing.T) {
	const request, response = string(script.KindHTTPRequest), string(script.KindHTTPResponse)
	var logs bytes.Buffer
	table := newMITMScriptTable([]compile.Script{
		{ID: "unsupported", Type: request, Pattern: ".*"},
		{ID: "non-http", Supported: true, Type: "event", Pattern: ".*"},
		{ID: "bad-pattern", Supported: true, Type: request, Pattern: "("},
		{ID: "response", Supported: true, Type: response, Pattern: "example[.]test"},
		{ID: "first", Supported: true, Type: request, Pattern: "/path$", Argument: "sample", Name: "First",
			Path: "https://scripts.test/sample.js", Hash: "hash", Format: "loon", RequiresBody: true,
			BinaryBodyMode: true, Timeout: 4, MaxSize: 128},
		{ID: "fallback", Supported: true, Type: request, Pattern: "example[.]test"},
	}, slog.New(slog.NewTextHandler(&logs, nil)))
	if table.count() != 3 || !strings.Contains(logs.String(), "bad-pattern") {
		t.Fatalf("entries = %d, diagnostics = %s", table.count(), &logs)
	}
	const url = "https://example.test/path"
	first := table.match(script.KindHTTPRequest, url)
	if first == nil || first.id != "first" || !first.requiresBody {
		t.Fatalf("first request match = %+v", first)
	}
	s := first.spec
	if s.Name != "First" || s.Key != "hash" || s.Path != "https://scripts.test/sample.js" ||
		s.Source != "" || s.Dialect != script.DialectLoon || !s.BinaryBody ||
		s.Argument == nil || *s.Argument != "sample" || s.Timeout != 4*time.Second || s.MaxSize != 128 {
		t.Fatalf("script = %+v", s)
	}
	if got := table.match(script.KindHTTPRequest, "https://example.test/other"); got == nil ||
		got.id != "fallback" || got.spec.Name != "fallback" || got.spec.Path != "fallback" || got.spec.Argument != nil {
		t.Fatalf("fallback request match = %+v", got)
	}
	if got := table.match(script.KindHTTPResponse, url); got == nil || got.id != "response" {
		t.Fatalf("response match = %+v", got)
	}
	if got := table.match(script.KindHTTPRequest, "https://other.test/other"); got != nil {
		t.Fatalf("unexpected script = %+v", got)
	}
}
