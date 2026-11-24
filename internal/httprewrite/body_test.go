package httprewrite

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"hash/adler32"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestBodyReplacements(t *testing.T) {
	s := newTestSet(t, Spec{
		HeaderRewrites: []HeaderRewrite{
			{ID: "header", Phase: ref("response"), Match: ".*", Op: "add", Name: "X-Test", Value: ref("yes")},
		},
		BodyRewrites: []BodyRewrite{
			{ID: "first", Phase: "response", Match: ".*", Replace: []Replacement{
				{Pattern: ref("(old)"), Value: ref("$1x")},
				{Pattern: ref("oldx"), Value: ref("new")},
			}},
			{ID: "second", Phase: "response", Match: "^https://a[.]example/", Replace: []Replacement{
				{Pattern: ref("new"), Value: ref("done $$ $0")},
			}},
		},
	}, Options{})
	body := []byte("old,old")
	header := http.Header{"content-length": {"999"}, "transfer-encoding": {"chunked"}, "X-Original": {"keep"}}
	original := header.Clone()
	got := s.Response("https://a.example/", Response{StatusCode: 201, Header: header, Body: body})
	if got.StatusCode != 201 || string(got.Body) != "done $ new,done $ new" || got.Header.Get("Content-Length") != strconv.Itoa(len(got.Body)) ||
		got.Header.Get("X-Test") != "yes" || got.Header.Get("X-Original") != "keep" || !slices.Equal(got.MatchedIDs, []string{"header", "first", "second"}) {
		t.Fatalf("response = %+v", got)
	}
	if _, present := headerValues(got.Header, "Transfer-Encoding"); present {
		t.Fatalf("transfer encoding retained in %v", got.Header)
	}
	if !reflect.DeepEqual(header, original) || string(body) != "old,old" {
		t.Fatalf("mutated input: header = %v, body = %q", header, body)
	}
}

func TestBodyLimitsAndEncodings(t *testing.T) {
	tooLarge := strings.Repeat("old", 100)
	tests := []struct {
		name     string
		encoding string
		input    []byte
		want     string
		max      int64
		pattern  string
		value    string
		changed  bool
	}{
		{name: "unbuffered", pattern: ".*", value: "new"},
		{name: "empty buffered", input: []byte{}, pattern: "^$", value: "new", want: "new", changed: true},
		{name: "empty replacement", input: []byte("old"), pattern: "^old$", changed: true},
		{name: "UTF-8 invalid", input: []byte("old\xff"), pattern: "old", value: "new"},
		{name: "input too large", input: []byte("oldold"), max: 3, pattern: "old", value: "new"},
		{name: "output too large", input: []byte("oldold"), max: 10, pattern: "(old)", value: "$0$1$1"},
		{name: "literal output too large", input: []byte("oldold"), max: 10, pattern: "o*", value: strings.Repeat("x", 12)},
		{name: "literal escape fits cap", input: []byte("oldold"), max: 6, pattern: "old", value: "$$$$", want: "$$$$", changed: true},
		{name: "capture output fits cap", input: []byte("old"), max: 4, pattern: "(o)ld", value: "$1$1$1x", want: "ooox", changed: true},
		{name: "decoded too large", encoding: "gzip", input: compressed(t, "gzip", tooLarge), max: 64, pattern: "old", value: "new"},
		{name: "gzip", encoding: "gzip", input: compressed(t, "gzip", "old"), want: "new", pattern: "old", value: "new", changed: true},
		{name: "gzip unchanged", encoding: "gzip", input: compressed(t, "gzip", "old"), pattern: "old", value: "old"},
		{name: "gzip invalid", encoding: "gzip", input: []byte("broken"), pattern: ".*", value: "new"},
		{name: "deflate", encoding: "deflate", input: compressed(t, "deflate", "old"), want: "new", pattern: "old", value: "new", changed: true},
		{name: "deflate with zlib wrapper", encoding: "deflate", input: compressed(t, "zlib", "old"), want: "new", pattern: "old", value: "new", changed: true},
		{name: "deflate invalid", encoding: "deflate", input: []byte("broken"), pattern: ".*", value: "new"},
		{name: "identity", encoding: "identity", input: []byte("old"), want: "new", pattern: "old", value: "new", changed: true},
		{name: "br passes through", encoding: "br", input: []byte("old"), pattern: "old", value: "new"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSet(t, Spec{BodyRewrites: []BodyRewrite{
				{ID: "body", Phase: "request", Match: ".*", Replace: []Replacement{{Pattern: ref(tt.pattern), Value: ref(tt.value)}}},
			}}, Options{MaxBodySize: tt.max})
			header := http.Header{"Content-Length": {strconv.Itoa(len(tt.input))}, "Transfer-Encoding": {"chunked"}}
			if tt.encoding != "" {
				header.Set("Content-Encoding", tt.encoding)
			}
			body := slices.Clone(tt.input)
			original := header.Clone()
			got := s.Request(Request{URL: "https://a.example/", Header: header, Body: body})
			if tt.changed {
				if string(got.Body) != tt.want || got.Header.Get("Content-Length") != strconv.Itoa(len(tt.want)) ||
					got.Header.Get("Content-Encoding") != "" || got.Header.Get("Transfer-Encoding") != "" {
					t.Fatalf("result = %+v, want body %q and updated framing", got, tt.want)
				}
			} else if !reflect.DeepEqual(got.Body, body) || !reflect.DeepEqual(got.Header, original) {
				t.Fatalf("result = %+v, want unchanged body %q and headers %v", got, body, original)
			}
			if !reflect.DeepEqual(body, tt.input) || !reflect.DeepEqual(header, original) {
				t.Fatalf("mutated input: header = %v, body = %q", header, body)
			}
		})
	}
}

func TestJQRewrites(t *testing.T) {
	tests := []struct {
		name  string
		query string
		body  string
		want  string
	}{
		{name: "deletion", query: `delpaths([["data","banner"]])`, body: `{"data":{"banner":1,"keep":2}}`, want: `{"data":{"keep":2}}`},
		{name: "invalid JSON", query: "1", body: `{`, want: `{`},
		{name: "trailing document", query: "1", body: `{} {}`, want: `{} {}`},
		{name: "execution error", query: `error("failed")`, body: `{"keep":true}`, want: `{"keep":true}`},
		{name: "no results", query: "empty", body: `{"keep":true}`, want: `{"keep":true}`},
		{name: "first result", query: "1, 2", body: "0", want: "1"},
		{name: "big integer", query: ".id += 1", body: `{"id":9223372036854775808123}`, want: `{"id":9223372036854775808124}`},
		{name: "HTML characters", query: `"</>"`, body: "null", want: `"</>"`},
		{name: "environment empty", query: `[env, $ENV]`, body: "null", want: "[{},{}]"},
		{name: "timeout", query: "until(false; .)", body: "0", want: "0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSet(t, Spec{BodyRewrites: []BodyRewrite{
				{ID: "jq", Phase: "response", Match: ".*", JQ: ref(tt.query)},
			}}, Options{})
			got := s.Response("https://a.example/", Response{Body: []byte(tt.body)})
			if string(got.Body) != tt.want {
				t.Fatalf("body = %q, want %q", got.Body, tt.want)
			}
		})
	}
}

func TestReplacementBoundMatchesActualExpansion(t *testing.T) {
	for _, pattern := range []string{"(a)", "(a)?", "(a|bc)", "(?m)^(.)", "(a*)", "((a)|b)", "(?P<a>a)(b?)"} {
		re := regexp.MustCompile(pattern)
		for _, raw := range []string{"", "abaca\nbabb", "ωa\nab🍂c", "aaaa"} {
			body := []byte(raw)
			for _, value := range []string{"", "$0", "$0$0$1x", "$2$1$$", "$$ $1 $99 $", "abc"} {
				template := normalizeTemplate(value, func(int) {})
				size := len(re.ReplaceAll(body, []byte(template)))
				for limit := len(body); limit <= max(len(body), size)+1; limit++ {
					if got := replacementFits(re, body, template, int64(limit)); got != (size <= limit) {
						t.Fatalf("pattern %q, body %q, template %q, limit %d: fit = %t, actual size %d", pattern, raw, value, limit, got, size)
					}
				}
			}
		}
	}
}

func compressed(t *testing.T, encoding, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	var writer io.WriteCloser
	if encoding == "gzip" {
		writer = gzip.NewWriter(&buf)
	} else {
		if encoding == "zlib" {
			buf.Write([]byte{0x78, 0x01})
		}
		var err error
		writer, err = flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := io.WriteString(writer, body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if encoding == "zlib" {
		buf.Write(binary.BigEndian.AppendUint32(nil, adler32.Checksum([]byte(body))))
	}
	return buf.Bytes()
}
