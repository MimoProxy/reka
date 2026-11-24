package httprewrite

import (
	"bytes"
	"errors"
	"image/gif"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func ref[T any](value T) *T { return &value }

func newTestSet(t *testing.T, spec Spec, opts Options) *Set {
	t.Helper()
	s, err := New(spec, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRejectResponses(t *testing.T) {
	tests := []struct {
		name        string
		response    *string
		status      int
		contentType string
		body        string
		action      ConnectionAction
	}{
		{name: "default", status: 404},
		{name: "error", response: ref("error"), status: 404},
		{name: "ok", response: ref("200"), status: 200},
		{name: "gif", response: ref("gif"), status: 200, contentType: "image/gif", body: tinyGIF},
		{name: "dict", response: ref("dict"), status: 200, contentType: "application/json", body: "{}"},
		{name: "array", response: ref("array"), status: 200, contentType: "application/json", body: "[]"},
		{name: "close", response: ref("close"), action: Close},
		{name: "drop", response: ref("drop"), action: Drop},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSet(t, Spec{HTTPRewrites: []HTTPRewrite{
				{ID: "reject", Match: "^https://a[.]example/", Action: "reject", Response: tt.response},
				{ID: "later", Match: ".*", Action: "reject", Response: ref("drop")},
			}}, Options{})
			got := s.Request(Request{URL: "https://a.example/x"})
			if got.Connection != tt.action || !slices.Equal(got.MatchedIDs, []string{"reject"}) {
				t.Fatalf("result = %+v", got)
			}
			if tt.status == 0 {
				if got.Local != nil {
					t.Fatalf("connection action returned HTTP response %+v", got.Local)
				}
				return
			}
			requireLocal(t, got.Local, tt.status, tt.contentType, tt.body)
		})
	}
}

func TestURLRewrites(t *testing.T) {
	tests := []struct {
		name        string
		match       string
		target      string
		want        string
		hostChanged bool
	}{
		{name: "captures", match: "(ab)", target: "$0/$1x/$$", want: "https://a.example/ab/abx/$/ab"},
		{name: "literal dollar", match: "(ab)", target: "$name/$", want: "https://a.example/$name/$/ab"},
		{name: "new host", match: "^https://a[.]example/", target: "https://other.example/", want: "https://other.example/ab/ab", hostChanged: true},
		{name: "host case", match: "^https://a[.]example/", target: "https://A.example/", want: "https://A.example/ab/ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, action := range []string{"302", "307", "header"} {
				t.Run(action, func(t *testing.T) {
					s := newTestSet(t, Spec{HTTPRewrites: []HTTPRewrite{
						{ID: "first", Match: tt.match, Action: action, Target: ref(tt.target)},
						{ID: "later", Match: ".*", Action: "reject"},
					}}, Options{})
					input := "https://a.example/ab/ab"
					got := s.Request(Request{URL: input})
					if !slices.Equal(got.MatchedIDs, []string{"first"}) {
						t.Fatalf("matched = %v", got.MatchedIDs)
					}
					if action == "header" {
						if got.URL != tt.want || got.HostChanged != tt.hostChanged || got.Local != nil {
							t.Fatalf("result = %+v", got)
						}
						return
					}
					status, err := strconv.Atoi(action)
					if err != nil {
						t.Fatal(err)
					}
					requireLocal(t, got.Local, status, "", "")
					if got.URL != input || got.Local.Header.Get("Location") != tt.want {
						t.Fatalf("URL = %q, Location = %q", got.URL, got.Local.Header.Get("Location"))
					}
				})
			}
		})
	}
}

func TestRequestRewriteOrder(t *testing.T) {
	const oldURL = "https://old.example/service"
	const newURL = "https://new.example/service"
	spec := Spec{
		HTTPRewrites: []HTTPRewrite{
			{ID: "url", Action: "header", Match: "^https://old[.]example/", Target: ref("https://new.example/")},
		},
		HeaderRewrites: []HeaderRewrite{
			{ID: "request-header", Match: "^https://new[.]example/", Op: "add", Name: "X-Request", Value: ref("updated")},
			{ID: "response-header", Phase: ref("response"), Match: ".*", Op: "add", Name: "X-Response", Value: ref("updated")},
		},
		BodyRewrites: []BodyRewrite{
			{ID: "request-body", Phase: "request", Match: "^https://new[.]example/", Replace: []Replacement{
				{Pattern: ref("input"), Value: ref("upstream")},
			}},
			{ID: "response-body", Phase: "response", Match: "^https://new[.]example/", Replace: []Replacement{
				{Pattern: ref("local"), Value: ref("upstream")},
			}},
		},
	}
	s := newTestSet(t, spec, Options{})
	if !s.NeedsRequestBody(oldURL) || s.NeedsResponseBody(oldURL) || !s.NeedsResponseBody(newURL) {
		t.Fatal("body detection did not respect the URL rewrite and direction")
	}
	req := Request{URL: oldURL, Body: []byte("input")}
	result := s.Request(req)
	if result.URL != newURL || !result.HostChanged || result.Header.Get("X-Request") != "updated" || string(result.Body) != "upstream" ||
		!slices.Equal(result.MatchedIDs, []string{"url", "request-header", "request-body"}) {
		t.Fatalf("request = %+v", result)
	}

	spec.MapLocal = []MapLocal{
		{ID: "new-map", Match: "^https://new[.]example/", DataType: ref("text"), Data: ref("local")},
		{ID: "later-map", Match: ".*", DataType: ref("text"), Data: ref("wrong")},
	}
	s = newTestSet(t, spec, Options{})
	if s.NeedsRequestBody(oldURL) {
		t.Fatal("map-local request should not need a body")
	}
	result = s.Request(req)
	requireLocal(t, result.Local, 200, "text/plain", "local")
	if result.URL != newURL || result.Header.Get("X-Request") != "updated" || string(result.Body) != "input" ||
		result.Local.Header.Get("X-Response") != "" || !slices.Equal(result.MatchedIDs, []string{"url", "request-header", "new-map"}) {
		t.Fatalf("request = %+v", result)
	}
}

func TestHeaderRewrites(t *testing.T) {
	const rawURL = "https://a.example/route"
	tests := []struct {
		name  string
		rules []HeaderRewrite
		input http.Header
		want  http.Header
	}{
		{
			name:  "add appends and expands",
			rules: []HeaderRewrite{{Op: "add", Name: "x-test", Match: "(route)", Value: ref("$1x $$")}},
			input: http.Header{"x-test": {"original"}},
			want:  http.Header{"X-Test": {"original", "routex $"}},
		},
		{
			name:  "add to nil header",
			rules: []HeaderRewrite{{Op: "add", Name: "X-Test", Value: ref("")}},
			want:  http.Header{"X-Test": {""}},
		},
		{
			name:  "delete all spellings",
			rules: []HeaderRewrite{{Op: "del", Name: "X-Test"}},
			input: http.Header{"X-Test": {"one", "two"}, "x-TEST": {"three"}, "X-Other": {"four"}},
			want:  http.Header{"X-Other": {"four"}},
		},
		{
			name:  "delete absent",
			rules: []HeaderRewrite{{Op: "del", Name: "X-Test"}},
		},
		{
			name:  "replace all values",
			rules: []HeaderRewrite{{Op: "replace", Name: "x-tEsT", Value: ref("one")}},
			input: http.Header{"X-TEST": {"two", "three"}},
			want:  http.Header{"X-Test": {"one"}},
		},
		{
			name:  "replace absent",
			rules: []HeaderRewrite{{Op: "replace", Name: "X-Test", Value: ref("one")}},
		},
		{
			name:  "replace all regex matches in each value",
			rules: []HeaderRewrite{{Op: "replace-regex", Name: "X-Test", Pattern: ref("(old)"), Value: ref("$1x $$ $0")}},
			input: http.Header{"X-Test": {"old; old", "unchanged"}, "x-test": {"old"}},
			want:  http.Header{"X-Test": {"oldx $ old; oldx $ old", "unchanged", "oldx $ old"}},
		},
		{
			name:  "replace regex absent",
			rules: []HeaderRewrite{{Op: "replace-regex", Name: "X-Test", Pattern: ref("old"), Value: ref("new")}},
		},
		{
			name:  "invalid result skips the operation",
			rules: []HeaderRewrite{{Op: "replace-regex", Name: "X-Test", Pattern: ref("(old)"), Value: ref("new")}},
			input: http.Header{"X-Test": {"old", "old\n"}},
			want:  http.Header{"X-Test": {"old", "old\n"}},
		},
		{
			name:  "connection nominated header",
			rules: []HeaderRewrite{{Op: "replace", Name: "x-test", Value: ref("changed")}},
			input: http.Header{"connection": {" X-Other, X-Test "}, "X-Test": {"original"}},
			want:  http.Header{"connection": {" X-Other, X-Test "}, "X-Test": {"original"}},
		},
		{
			name: "ordered response operations",
			rules: []HeaderRewrite{
				{Phase: ref("response"), Op: "add", Name: "X-Test", Value: ref("one")},
				{Phase: ref("response"), Op: "replace", Name: "X-Test", Value: ref("two")},
				{Phase: ref("response"), Op: "add", Name: "X-Test", Value: ref("three")},
			},
			want: http.Header{"X-Test": {"two", "three"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.rules {
				if tt.rules[i].Match == "" {
					tt.rules[i].Match = ".*"
				}
			}
			s := newTestSet(t, Spec{HeaderRewrites: tt.rules}, Options{})
			original := tt.input.Clone()
			got := s.Request(Request{URL: rawURL, Header: tt.input}).Header
			if tt.rules[0].Phase != nil && *tt.rules[0].Phase == "response" {
				if !reflect.DeepEqual(got, tt.input) {
					t.Fatalf("request headers = %v", got)
				}
				got = s.Response(rawURL, Response{Header: tt.input}).Header
			}
			if !reflect.DeepEqual(got, tt.want) || !reflect.DeepEqual(tt.input, original) {
				t.Fatalf("result = %v, input = %v, want result %v, input %v", got, tt.input, tt.want, original)
			}
		})
	}
}

func TestMapLocalTypes(t *testing.T) {
	tests := []struct {
		name        string
		rule        MapLocal
		status      int
		contentType string
		body        string
		read        bool
	}{
		{name: "text", rule: MapLocal{DataType: ref("text"), Data: ref("hello")}, status: 200, contentType: "text/plain", body: "hello"},
		{name: "text empty", rule: MapLocal{DataType: ref("text"), Data: ref("")}, status: 200, contentType: "text/plain"},
		{name: "json", rule: MapLocal{DataType: ref("json"), Data: ref("{}")}, status: 200, contentType: "application/json", body: "{}"},
		{name: "gif", rule: MapLocal{DataType: ref("tiny-gif")}, status: 200, contentType: "image/gif", body: tinyGIF},
		{name: "base64", rule: MapLocal{DataType: ref("base64"), Data: ref("AAEC")}, status: 200, contentType: "application/octet-stream", body: "\x00\x01\x02"},
		{name: "file default", rule: MapLocal{Hash: ref("hash")}, status: 200, contentType: "application/octet-stream", body: "file", read: true},
		{name: "file type", rule: MapLocal{DataType: ref("file"), Hash: ref("hash"), DownloadURL: ref("https://a.example/a.JSON?name=a.js")}, status: 200, contentType: "application/json", body: "file", read: true},
		{
			name: "override status and content type",
			rule: MapLocal{DataType: ref("text"), Data: ref("hello"), StatusCode: ref(418), Headers: []Header{
				{Name: "content-type", Value: ref("application/custom")},
				{Name: "X-Custom", Value: ref("one")},
				{Name: "x-custom", Value: ref("two")},
			}},
			status: 418, contentType: "application/custom", body: "hello",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.rule.Match = "^https://a[.]example/"
			var calls int
			s := newTestSet(t, Spec{MapLocal: []MapLocal{tt.rule}}, Options{ReadResource: func(hash string) ([]byte, error) {
				calls++
				if hash != "hash" {
					t.Fatalf("resource hash = %s", hash)
				}
				return []byte("file"), nil
			}})
			if outside := s.Request(Request{URL: "https://b.example/"}); outside.Local != nil || calls != 0 {
				t.Fatalf("miss = %+v, reads = %d", outside, calls)
			}
			got := s.Request(Request{URL: "https://a.example/"})
			requireLocal(t, got.Local, tt.status, tt.contentType, tt.body)
			if got.ResourceError != nil || tt.read && calls != 1 || !tt.read && calls != 0 {
				t.Fatalf("reads = %d, err = %v", calls, got.ResourceError)
			}
			if tt.status == 418 && !slices.Equal(got.Local.Header.Values("X-Custom"), []string{"one", "two"}) {
				t.Fatalf("headers = %v", got.Local.Header)
			}
			if tt.body == tinyGIF {
				image, err := gif.Decode(bytes.NewReader(got.Local.Body))
				if err != nil {
					t.Fatal(err)
				}
				if _, _, _, a := image.At(0, 0).RGBA(); a != 0 || image.Bounds().Dx() != 1 || image.Bounds().Dy() != 1 {
					t.Fatalf("GIF bounds = %v, alpha = %d", image.Bounds(), a)
				}
			}
			if len(got.Local.Body) > 0 {
				got.Local.Body[0] = '-'
			}
			got.Local.Header.Set("Content-Type", "changed")
			requireLocal(t, s.Request(Request{URL: "https://a.example/"}).Local, tt.status, tt.contentType, tt.body)
		})
	}
}

func TestMapLocalReadFailure(t *testing.T) {
	errMissing := errors.New("missing")
	s := newTestSet(t, Spec{MapLocal: []MapLocal{{ID: "file", Match: ".*", Hash: ref("hash")}}}, Options{
		ReadResource: func(string) ([]byte, error) { return nil, errMissing },
	})
	got := s.Request(Request{})
	requireLocal(t, got.Local, 404, "", "")
	if !errors.Is(got.ResourceError, errMissing) || !slices.Equal(got.MatchedIDs, []string{"file"}) {
		t.Fatalf("result = %+v", got)
	}
}

func TestValidationDiagnostics(t *testing.T) {
	spec := Spec{
		HTTPRewrites: []HTTPRewrite{
			{Match: "(?=x)", Action: "302", Target: ref("http://example.org/"), Response: ref("drop")},
			{Match: ".*", Action: "reject", Target: ref("x"), Response: ref("unknown")},
			{Match: ".*", Action: "header"},
			{Match: ".*", Action: "unsupported"},
		},
		HeaderRewrites: []HeaderRewrite{
			{Match: ".*", Op: "del", Name: "transfer-encoding", Pattern: ref("x"), Value: ref("x")},
			{Match: ".*", Op: "add", Name: "X-Test", Phase: ref("")},
			{Match: ".*", Op: "replace-regex", Name: ":method", Pattern: ref("(?=x)"), Value: ref("\n")},
		},
		BodyRewrites: []BodyRewrite{
			{Match: ".*", JQ: ref("input")},
			{Match: ".*", Phase: "request", Replace: []Replacement{}},
			{Match: ".*", Phase: "response", Replace: []Replacement{{Pattern: ref("(?=x)")}}},
		},
		MapLocal: []MapLocal{
			{Match: ".*", StatusCode: ref(99), Headers: []Header{{Name: "TE", Value: ref("\n")}}},
			{Match: ".*", DataType: ref("json"), Data: ref("{")},
			{Match: ".*", DataType: ref("base64"), Data: ref("-")},
			{Match: ".*", DataType: ref("tiny-gif"), Data: ref("x"), Hash: ref("a"), DownloadURL: ref("https://a.example/")},
			{Match: ".*", DataType: ref("json"), Data: ref("\"\xff\"")},
		},
	}
	s, err := New(spec, Options{})
	var errs ValidationErrors
	if s != nil || !errors.As(err, &errs) {
		t.Fatalf("New = %v, %v", s, err)
	}
	var got []string
	for _, e := range errs {
		got = append(got, e.Kind+"/"+strconv.Itoa(e.Index)+"/"+e.Field)
	}
	want := strings.Fields(`
		http-rewrites/0/match http-rewrites/0/response http-rewrites/1/target http-rewrites/1/response http-rewrites/2/target http-rewrites/3/action
		header-rewrites/0/name header-rewrites/0/pattern header-rewrites/0/value header-rewrites/1/phase header-rewrites/1/value
		header-rewrites/2/name header-rewrites/2/pattern header-rewrites/2/value
		body-rewrites/0/phase body-rewrites/0/jq body-rewrites/1/replace body-rewrites/2/replace/#0/pattern body-rewrites/2/replace/#0/value
		map-local/0/status-code map-local/0/headers/#0/name map-local/0/headers/#0/value map-local/0/hash
		map-local/1/data map-local/2/data map-local/3/hash map-local/3/download map-local/3/data map-local/4/data
	`)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("diagnostic paths:\n%v\nwant:\n%v", got, want)
	}
}

func TestCaptureWarnings(t *testing.T) {
	s := newTestSet(t, Spec{
		HTTPRewrites:   []HTTPRewrite{{Match: "(a)", Action: "header", Target: ref("$1x $0 $$1 $2 $2 $99")}},
		HeaderRewrites: []HeaderRewrite{{Match: "(a)(b)", Op: "replace-regex", Name: "X-Test", Pattern: ref("(x)"), Value: ref("$2")}},
		BodyRewrites:   []BodyRewrite{{Match: "(a)", Phase: "request", Replace: []Replacement{{Pattern: ref("x"), Value: ref("$1")}}}},
	}, Options{})
	warnings := s.Warnings()
	paths := make([]string, len(warnings))
	for i, warning := range warnings {
		paths[i] = warning.Kind + "/" + warning.Field
	}
	want := []string{"http-rewrites/target", "http-rewrites/target", "header-rewrites/value", "body-rewrites/replace/#0/value"}
	if !slices.Equal(paths, want) {
		t.Fatalf("warnings = %v", warnings)
	}
}

func TestEmptyInputs(t *testing.T) {
	s := newTestSet(t, Spec{}, Options{})
	if s != nil || s.Request(Request{}).Local != nil || s.Response("", Response{}).Body != nil ||
		s.NeedsRequestBody("") || s.NeedsResponseBody("") {
		t.Fatal("empty set changed empty input")
	}
	s = newTestSet(t, Spec{HTTPRewrites: []HTTPRewrite{{Match: "^https://a[.]example/", Action: "reject"}}}, Options{})
	for _, rawURL := range []string{"", "not a URL", "https://invalid%host/"} {
		if got := s.Request(Request{URL: rawURL}); got.URL != rawURL || got.Local != nil || len(got.MatchedIDs) != 0 {
			t.Fatalf("Request(%q) = %+v", rawURL, got)
		}
	}
}

func requireLocal(t *testing.T, got *Response, status int, contentType, body string) {
	t.Helper()
	if got == nil || got.StatusCode != status || got.Header.Get("Content-Type") != contentType ||
		got.Header.Get("Content-Length") != strconv.Itoa(len(body)) || string(got.Body) != body {
		t.Fatalf("local response = %+v, want status %d, type %q, body %q", got, status, contentType, body)
	}
}
